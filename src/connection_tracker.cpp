#include "connection_tracker.h"
#include <spdlog/spdlog.h>

namespace NetHex {

    Connection* ConnectionTracker::process_tcp_packet(const FiveTuple& tuple, uint8_t tcp_flags, uint32_t payload_size) {
        
        // 1. Bitwise Extraction of TCP Flags
        // The flags arrive as a single byte.
        bool is_syn = (tcp_flags & 0x02) != 0;
        bool is_ack = (tcp_flags & 0x10) != 0;
        bool is_fin = (tcp_flags & 0x01) != 0;
        bool is_rst = (tcp_flags & 0x04) != 0;

        // 2. Lookup the connection in our Flow Table (O(1) time complexity)
        auto it = flow_table.find(tuple);

        if (it == flow_table.end()) {
            // FLOW DOES NOT EXIST. Is this the start of a new connection?
            
            if (is_syn && !is_ack) {
                // Legitimate start of a TCP connection (First step of the Handshake)
                Connection new_conn;
                new_conn.state = TcpState::SYN_SENT;
                new_conn.total_bytes = payload_size;
                new_conn.total_packets = 1;
                
                // Insert it into our Hash Map
                flow_table[tuple] = new_conn;

                spdlog::debug("[Tracker] [+] New Flow Created (SYN). Active Flows: {}", flow_table.size())
            } else {
                // SECURITY FEATURE: We saw a packet for a flow that doesn't exist, and it's NOT a SYN.
                // This could be a late packet from a closed connection, or a hacker sending spoofed traffic!
                // We drop/ignore it to protect our engine's memory.
                return nullptr;
            }
        } else {
            // FLOW EXISTS! We pull out the existing state.
            Connection& conn = it->second;
            
            // Update traffic stats and timestamps
            conn.total_bytes += payload_size;
            conn.total_packets += 1;
            conn.last_seen = std::chrono::steady_clock::now();

            // 3. The TCP State Machine Logic
            if (conn.state == TcpState::SYN_SENT && is_syn && is_ack) {
                // Server replied with SYN-ACK!
                conn.state = TcpState::SYN_RCVD;
            } 
            else if (conn.state == TcpState::SYN_RCVD && is_ack) {
                // Client replied with final ACK! Handshake is complete.
                conn.state = TcpState::ESTABLISHED;
                spdlog::debug("[Tracker] [==>] Flow ESTABLISHED!");
            }
            else if (is_fin || is_rst) {
                // The connection is being torn down.
                conn.state = TcpState::CLOSED;
                spdlog::debug("[Tracker] [-] Flow CLOSED.");
                
                // Note: We don't delete it from the map immediately. 
                // We leave it here so our future LRU Cache/Timeout system can clean it up efficiently.
            }
        }

        // Return a pointer to the flow so main.cpp can use it for Fast-Path!
        return &flow_table[tuple];
    }

    void ConnectionTracker::evict_stale_sessions() {
        auto now = std::chrono::steady_clock::now();
        size_t evicted_count = 0;

        // Notice we do NOT have a ++it in the loop definition. 
        // We control the iterator manually to prevent Segmentation Faults!
        for (auto it = flow_table.begin(); it != flow_table.end(); ) {
            const Connection& conn = it->second;
            
            // Calculate how many seconds have passed since we last saw a packet for this flow
            auto duration_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - conn.last_seen).count();

            bool should_evict = false;

            // --- THE EVICTION RULES ---
            if (conn.state == TcpState::CLOSED) {
                should_evict = true; // 1. It closed properly. Drop it instantly.
            } 
            else if (conn.state == TcpState::SYN_SENT && duration_seconds > 10) {
                should_evict = true; // 2. SYN Flood Protection! No reply after 10 seconds? Kill it.
            } 
            else if (conn.state == TcpState::ESTABLISHED && duration_seconds > 300) {
                should_evict = true; // 3. Idle Timeout. No data for 5 minutes? Kill it.
            }

            // THE SAFE DELETION
            if (should_evict) {
                // .erase() safely deletes the flow and returns a valid iterator to the next one
                it = flow_table.erase(it); 
                evicted_count++;
            } else {
                // If we didn't delete it, we manually move to the next flow
                ++it; 
            }
        }

        if (evicted_count > 0) {
            spdlog::info("[Garbage Collector] Evicted {} stale flows. Active memory: {} flows.", evicted_count, flow_table.size());
        }
    }

    size_t ConnectionTracker::get_active_flow_count() const {
        return flow_table.size();
    }
}