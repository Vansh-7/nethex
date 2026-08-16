#include "platform.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "connection_tracker.h"
#include "five_tuple.h"
#include <iostream>

int main() {
    std::cout << "[NetHex] Engine initializing Phase 2 (Stateful DPI)..." << std::endl;
    
    // Instantiate our reader
    std::unique_ptr<NetHex::IPacketReader> reader = std::make_unique<NetHex::PcapFileReader>("sample.pcap");
    
    // Instantiate our new Phase 2 Brain!
    NetHex::ConnectionTracker tracker; 

    if (reader->open()) {
        const uint8_t* packet_data = nullptr;
        uint32_t packet_length = 0;
        uint32_t packet_count = 0;

        // THE CORE INGESTION LOOP
        // The loop just asks for the next packet.
        while (reader->read_next_packet(packet_data, packet_length)) {
            packet_count++;
            
            // Initialize the offset for this specific packet
            uint32_t offset = 0;
            uint16_t next_protocol = 0;
            
            // 1. Parse Layer 2 (Ethernet). This will automatically advance the 'offset' by 14
            if (NetHex::PacketParser::parse_ethernet(packet_data, packet_length, offset, next_protocol)) {
                
                // EtherType 0x0800 means IPv4
                if (next_protocol == 0x0800) {
                    
                    uint32_t src_ip = 0, dest_ip = 0;
                    uint8_t l4_protocol = 0;
                    
                    // 2. Parse Layer 3 (IPv4)
                    if (NetHex::PacketParser::parse_ipv4(packet_data, packet_length, offset, src_ip, dest_ip, l4_protocol)) {
                        
                        // IANA Protocol Number 6 exactly means TCP
                        if (l4_protocol == 6) {
                            uint16_t src_port = 0, dest_port = 0;
                            uint8_t tcp_flags = 0;
                            
                            // 3. Parse Layer 4 (TCP)
                            if (NetHex::PacketParser::parse_tcp(packet_data, packet_length, offset, src_port, dest_port, tcp_flags)) {
                                
                                // --- THE PHASE 2 MAGIC HAPPENS HERE ---
                                
                                // A. Create our Bidirectional Fingerprint
                                NetHex::FiveTuple tuple = NetHex::create_bidirectional_tuple(
                                    src_ip, dest_ip, src_port, dest_port, l4_protocol
                                );
                                
                                // B. Calculate actual L7 payload size (e.g. HTTP/TLS data)
                                // We just subtract the current offset (L2+L3+L4 headers) from total length!
                                uint32_t payload_size = 0;
                                if (packet_length > offset) {
                                    payload_size = packet_length - offset;
                                }

                                // C. Feed the Brain!
                                tracker.process_tcp_packet(tuple, tcp_flags, payload_size);
                            }
                        }
                    }
                }
            }
        }

        std::cout << "\n[NetHex] Successfully ingested " << packet_count << " packets." << std::endl;
        std::cout << "[NetHex] Total Active Flows Tracked: " << tracker.get_active_flow_count() << std::endl;
        reader->close();
    } else {
        std::cout << "[NetHex] Note: Please drop a 'sample.pcap' file into your working directory to test ingestion." << std::endl;
    }
    
    return 0;
}