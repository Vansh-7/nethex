#include "packet_parser.h"
#include "platform.h"
#include <iomanip>

namespace NetHex {

    bool PacketParser::parse_ethernet(const uint8_t* packet_data, uint32_t packet_length, uint16_t& next_protocol) {
        // Safety check: Is the packet even large enough to have an Ethernet header?
        if (packet_length < sizeof(EthernetHeader)) {
            return false;
        }

        // Cast the raw bytes into our packed struct
        const EthernetHeader* eth_header = reinterpret_cast<const EthernetHeader*>(packet_data);

        // Network traffic is Big-Endian. We must convert the EtherType to our Host's Endianness.
        next_protocol = ntoh16(eth_header->ethertype);

        // Print MAC Addresses for debugging
        std::cout << "   [L2] Src MAC: ";
        for(int i=0; i<6; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->src_mac[i] << (i < 5 ? ":" : "");
        
        std::cout << " -> Dest MAC: ";
        for(int i=0; i<6; i++) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->dest_mac[i] << (i < 5 ? ":" : "");
        std::cout << std::dec << std::endl; // Reset to decimal

        return true;
    }

    bool PacketParser::parse_ipv4(const uint8_t* packet_data, uint32_t packet_length, uint32_t offset) {
        if (packet_length < offset + sizeof(IPv4Header)) {
            return false;
        }

        const IPv4Header* ip_header = reinterpret_cast<const IPv4Header*>(packet_data + offset);

        // Convert the IPs from Network Endian to Host Endian for reading
        uint32_t src_ip = ntoh32(ip_header->src_ip);
        uint32_t dest_ip = ntoh32(ip_header->dest_ip);

        // Extracting standard IP format (A.B.C.D) using bitwise shifts
        std::cout << "   [L3] IPv4: " 
                  << ((src_ip >> 24) & 0xFF) << "." << ((src_ip >> 16) & 0xFF) << "." << ((src_ip >> 8) & 0xFF) << "." << (src_ip & 0xFF)
                  << " -> "
                  << ((dest_ip >> 24) & 0xFF) << "." << ((dest_ip >> 16) & 0xFF) << "." << ((dest_ip >> 8) & 0xFF) << "." << (dest_ip & 0xFF)
                  << std::endl;

        return true;
    }
}