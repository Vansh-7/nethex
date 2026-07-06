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
                
                uint16_t next_protocol = 0;
                if (NetHex::PacketParser::parse_ethernet(packet_data, packet_length, next_protocol)) {
                    // EtherType 0x0800 means the encapsulated data is IPv4
                    if (next_protocol == 0x0800) {
                        // Offset the pointer by the size of the Ethernet header to get to the IP header
                        NetHex::PacketParser::parse_ipv4(packet_data, packet_length, sizeof(NetHex::EthernetHeader));
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