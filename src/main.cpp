#include "platform.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include <iostream>

int main() {
    std::cout << "[NetHex] Engine initializing..." << std::endl;
    
    // Instantiate our reader using standard polymorphic design
    std::unique_ptr<NetHex::IPacketReader> reader = std::make_unique<NetHex::PcapFileReader>("sample.pcap");

    if (reader->open()) {
        const uint8_t* packet_data = nullptr;
        uint32_t packet_length = 0;
        uint32_t packet_count = 0;

        // THE CORE INGESTION LOOP
        // The loop just asks for the next packet.
        while (reader->read_next_packet(packet_data, packet_length)) {
            packet_count++;
            
            // let's print first 3 packets
            if (packet_count <= 3) {
                std::cout << "\n[+] Packet #" << packet_count << " (Size: " << packet_length << " bytes)" << std::endl;
                
                // 1. Initialize the offset for this specific packet
                uint32_t offset = 0;
                uint16_t next_protocol = 0;
                
                // 2. Parse Layer 2 (Ethernet). This will automatically advance the 'offset' by 14
                if (NetHex::PacketParser::parse_ethernet(packet_data, packet_length, offset, next_protocol)) {
                    
                    // EtherType 0x0800 means the encapsulated data is IPv4
                    if (next_protocol == 0x0800) {
                        
                        uint32_t src_ip = 0, dest_ip = 0;
                        uint8_t l4_protocol = 0;
                        
                        // 3. Parse Layer 3 (IPv4). Notice we just pass the 'offset' directly!
                        if (NetHex::PacketParser::parse_ipv4(packet_data, packet_length, offset, src_ip, dest_ip, l4_protocol)) {
                            std::cout << "    [L3] IPv4 Parsed Successfully. Next Protocol: " << (int)l4_protocol << std::endl;
                            // The offset is now perfectly positioned for Layer 4 (TCP/UDP)
                        }
                    }
                }
            }
        }

        std::cout << "[NetHex] Successfully ingested " << packet_count << " packets." << std::endl;
        reader->close();
    } else {
        std::cout << "[NetHex] Note: Please drop a 'sample.pcap' file into your working directory to test ingestion." << std::endl;
    }
    
    return 0;
}