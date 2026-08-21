#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>

// custom headers
#include "platform.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "load_balancer.h"
#include "xxhash_functor.h"
#include "connection_tracker.h"
#include "dpi_engine.h"
#include "fast_path.h"
#include "memory_pool.h"
#include "logger.h"
#include <spdlog/spdlog.h> // Async logging!

using namespace NetHex;

// Global atomic flag for clean shutdown via CTRL+C
std::atomic<bool> keep_running{true};

void signal_handler(int) {
    keep_running = false;
}

// ------------------------------------------------------------------------
// THE WORKER THREAD (CONSUMER)
// ------------------------------------------------------------------------
void worker_node(int core_id, LoadBalancer* lb, PacketMemoryPool* mem_pool) {
    // 1. Cross-Platform CPU Pinning
    NetHex::pin_thread_to_core(core_id);
    spdlog::info("[Worker {}] Online and pinned to CPU Core {}", core_id, core_id);

    // 2. Private State! (No Mutexes Needed)
    // Every worker has its own dedicated memory for tracking flows and patterns.
    ConnectionTracker tracker;
    DpiEngine dpi_engine;
    
    // Grab the specific lock-free queue for this worker
    auto* my_queue = lb->get_queue(core_id);
    ParsedPacket packet;

    // Add a loop counter for the GC
    uint32_t loop_counter = 0;

    // 3. The High-Speed Polling Loop
    while (keep_running || !my_queue->empty()) {
        if (my_queue->pop(packet)) {

            // Reconstruct the bi-direction 5-tuple for the tracker
            FiveTuple tuple = create_bidirectional_tuple(packet.src_ip, packet.dest_ip, packet.src_port, packet.dest_port, packet.protocol);

            Connection* conn = nullptr;
            if (packet.protocol == 6) { // TCP
                conn = tracker.process_tcp_packet(tuple, packet.tcp_flags, packet.payload_length);
            } else if (packet.protocol == 17) { // UDP
                // Optionally implement tracker.process_udp_packet() in the future.
                // For now, we skip UDP connection tracking.
            }

            // FAST-PATH WITH MEMORY SAFETY
            if (conn != nullptr && FastPath::should_bypass(*conn)) {
                // We are bypassing! Release zero-copy memory immediately before we jump.
                if (packet.pool_slot_id != ParsedPacket::NO_PAYLOAD) {
                    mem_pool->release_slot(packet.pool_slot_id);
                }
                continue; // Instantly skip the rest of the loop! Maximum CPU cycles saved.
            };

            // Only run heavy inspection if it hasn't been bypassed
            if (packet.payload_length > 0 && packet.payload_ptr != nullptr) {
                
                int dummy_state = 0;
                uint8_t dummy_l7 = 0;
                
                // Extract Aho-Corasick state IF connection is tracked, otherwise use dummies for stateless UDP
                int& ac_state = (conn != nullptr) ? conn->ac_state : dummy_state;
                uint8_t& l7_proto = (conn != nullptr) ? conn->l7_protocol : dummy_l7;

                if (dpi_engine.inspect_payload(packet.payload_ptr, packet.payload_length, tuple, ac_state, l7_proto)) {
                    if (conn != nullptr) {
                        conn->is_malicious = true; // Mark as bad! Fast-Path will now block this forever.
                    }
                }
            }

            // NORMAL ZERO-COPY RELEASE (For packets that actually went through DPI)
            if (packet.pool_slot_id != ParsedPacket::NO_PAYLOAD) {
                mem_pool->release_slot(packet.pool_slot_id);
            }
        } else if (!keep_running){
            break; // Queue is empty AND main thread said stop. Safe to exit.
        } else {
            // If the queue is empty, yield the CPU slightly so we don't burn 
            // 100% of the core doing a busy-wait loop.
            std::this_thread::yield(); 
        }

        // --- BACKGROUND GARBAGE COLLECTION ---
        // This increments whether we processed a packet OR yielded. 
        // It guarantees cleanup even during complete network silence!
        loop_counter++;
        if (loop_counter >= 100000) {
            tracker.evict_stale_sessions();
            loop_counter = 0;
        }
    }
    
    spdlog::info("[Worker {}] Shutting down.", core_id);
}

// ------------------------------------------------------------------------
// THE MAIN THREAD (PRODUCER / INGESTION)
// ------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // Initialize Logger
    NetHex::Logger::init();
    spdlog::info("Starting NetHex DPI Engine...");

    if (argc < 2) {
        spdlog::error("Usage: {} <pcap_file>", argv[0]);
        return 1;
    }

    std::signal(SIGINT, signal_handler);

    // Determine hardware concurrency (how many cores the system actually has)
    // We leave 1 core dedicated to this Main Ingestion Thread.
    unsigned int num_cores = std::thread::hardware_concurrency();
    size_t num_workers = (num_cores > 1) ? num_cores - 1 : 1;
    
    spdlog::info("Started with {} Worker Threads.", num_workers);

    // Wrap initialization and execution in a try-catch block for absolute safety
    try {
        // Pin the Main Ingestion Thread to the last available core to prevent preemption of worker threads
        NetHex::pin_thread_to_core(num_cores - 1);
        spdlog::info("[Main] Ingestion Thread pinned to CPU Core {}", num_cores - 1);

        // Initialize the Load Balancer with 8192 capacity per queue
        LoadBalancer load_balancer(num_workers, 8192);

        // INSTANTIATE THE MEMORY POOL
        // 65,536 slots is standard, capable of holding heavy bursts of traffic
        PacketMemoryPool mem_pool(65536, 2048);

        // Spin up the worker threads
        std::vector<std::thread> workers;
        for (size_t i = 0; i < num_workers; ++i) {
            workers.emplace_back(worker_node, i, &load_balancer, &mem_pool);
        }

        // Open the target PCAP File
        PcapFileReader reader(argv[1]);
        if (!reader.open()) {
            spdlog::error("[Error] Failed to open PCAP file.");
            keep_running = false;
        } else {
            // The Ingestion Loop Variables
            const uint8_t* raw_packet = nullptr;
            uint32_t packet_len = 0;
            XxHashFunctor hash_fn;

            spdlog::info("[Ingestion] Reading packets and distributing to workers...");

            // The loop just asks for the next packet.
            while (keep_running && reader.read_next_packet(raw_packet, packet_len)) {
                uint32_t offset = 0;
                uint16_t next_proto_l2;
                uint8_t next_proto_l3, tcp_flags;
                uint32_t src_ip, dest_ip;

                // Parse Layer 2 (Ethernet): adv 'offset' by 14 && EtherType 0x0800 means IPv4
                if (PacketParser::parse_ethernet(raw_packet, packet_len, offset, next_proto_l2) && next_proto_l2 == 0x0800) {
                    
                    // Parse Layer 3 (IPv4)
                    if (PacketParser::parse_ipv4(raw_packet, packet_len, offset, src_ip, dest_ip, next_proto_l3)) {
                        
                        // Create our safe envelope (Zero-initialized by default)
                        ParsedPacket parsed(src_ip, dest_ip, 0, 0, next_proto_l3);

                        // Parse Layer 4 (TCP / UDP)
                        if (next_proto_l3 == 6) { 
                            if(!PacketParser::parse_tcp(raw_packet, packet_len, offset, parsed.src_port, parsed.dest_port, tcp_flags)) continue;
                            parsed.tcp_flags = tcp_flags;
                        } else if (next_proto_l3 == 17) { 
                            if(!PacketParser::parse_udp(raw_packet, packet_len, offset, parsed.src_port, parsed.dest_port)) continue;
                        } else {
                            continue; // Drop ICMP or other unsupported L4 protocols to save memory pool slots
                        }

                        // Copy the Layer 7 Payload safely into the envelope for cross-thread transit
                        if (packet_len > offset) {
                            uint32_t p_len = packet_len - offset;
                            uint32_t slot_id;
                            uint8_t* buffer_ptr;
                            
                            // Borrow a slot from the pool. Spin-wait if exhausted.
                            while (!mem_pool.acquire_slot(slot_id, buffer_ptr) && keep_running) {
                                std::this_thread::yield();
                            }

                            // Only proceed if we actually acquired a slot (i.e., we aren't shutting down)
                            if (keep_running) {
                                // Copy payload exactly ONCE into the pre-allocated pool buffer
                                uint32_t copy_size = (p_len > 2048) ? 2048 : p_len; 
                                std::memcpy(buffer_ptr, raw_packet + offset, copy_size);

                                // Point the lock-free envelope to the pool
                                parsed.pool_slot_id = slot_id;
                                parsed.payload_ptr = buffer_ptr;
                                parsed.payload_length = copy_size;
                            }
                        }

                        // Hash the 5-Tuple to guarantee Flow-Aware Routing (bi-directional)
                        FiveTuple tuple = create_bidirectional_tuple(parsed.src_ip, parsed.dest_ip, parsed.src_port, parsed.dest_port, parsed.protocol);
                        uint64_t flow_hash = hash_fn(tuple);

                        // Dispatch to the Lock-Free Queue!
                        // If the queue is full (returns false), we yield and retry until space opens up.
                        while (!load_balancer.dispatch(parsed, flow_hash) && keep_running) {
                            std::this_thread::yield(); 
                        }
                    }
                }
            }
            spdlog::info("[Ingestion] Finished reading PCAP. Waiting for workers to drain queues...");
        }

        // Give workers 1 second to empty their queues before sending the kill signal
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Stop the worker while-loops
        keep_running = false; 

        // Safely join all threads before exiting
        for (auto& t : workers) {
            if (t.joinable()) {
                t.join();
            }
        }

    } catch (const std::invalid_argument& e) {
        spdlog::critical("Failed to initialize load balancer: {}", e.what());
        return 1;
    } catch (const std::exception& e) {
        spdlog::critical("An unexpected fatal error occurred: {}", e.what());
        return 1;
    }

    spdlog::info("[System] Engine shutdown complete.");
    return 0;
}