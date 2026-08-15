#include "packet_parser.h"
#include "platform.h"

namespace NetHex {

    bool PacketParser::parse_ethernet(const uint8_t* packet_data, 
                                      uint32_t packet_length, 
                                      uint32_t& offset, 
                                      uint16_t& next_protocol) {
        // Safety check: Is the packet even large enough to have an Ethernet header?
        if (packet_length < offset + sizeof(EthernetHeader)) {
            return false;
        }

        // Cast the raw bytes into our packed struct
        const EthernetHeader* eth_header = reinterpret_cast<const EthernetHeader*>(packet_data + offset);

        // Convert the EtherType to our Host's Endianness
        next_protocol = ntoh16(eth_header->ethertype);

        // Advance the offset by exactly the size of the Ethernet II header (14 bytes)
        offset += sizeof(EthernetHeader);

        return true;
    }

    bool PacketParser::parse_ipv4(const uint8_t* packet_data, 
                                  uint32_t packet_length, 
                                  uint32_t& offset,
                                  uint32_t& src_ip,
                                  uint32_t& dest_ip,
                                  uint8_t& next_protocol) {
        // Base safety check for the minimum IPv4 header size
        if (packet_length < offset + sizeof(IPv4Header)) {
            return false;
        }

        const IPv4Header* ip_header = reinterpret_cast<const IPv4Header*>(packet_data + offset);

        // Extract IPs in Host Endian format
        src_ip = ntoh32(ip_header->src_ip);
        dest_ip = ntoh32(ip_header->dest_ip);
        next_protocol = ip_header->protocol;

        // Calculate the actual header length using the IHL (Internet Header Length) field.
        // IHL is the lower 4 bits of the version_ihl byte. It represents the length in 32-bit words.
        uint8_t ihl = ip_header->version_ihl & 0x0F;
        uint32_t actual_header_bytes = ihl * 4;

        // Secondary safety check in case of malformed network packets advertising a fake IHL
        if (packet_length < offset + actual_header_bytes) {
            return false;
        }

        // Advance the offset dynamically so Layer 4 (TCP/UDP) knows exactly where to start
        offset += actual_header_bytes;

        return true;
    }

    bool PacketParser::parse_tcp(const uint8_t* packet_data, 
                                 uint32_t packet_length, 
                                 uint32_t& offset,
                                 uint16_t& src_port,
                                 uint16_t& dest_port,
                                 uint8_t& tcp_flags) {

        // Base safety check for the minimum TCP header size (20 bytes)
        if (packet_length < offset + sizeof(TCPHeader)) {
            return false;
        }

        const TCPHeader* tcp_header = reinterpret_cast<const TCPHeader*>(packet_data + offset);

        // Convert Ports from Network Endian to Host Endian
        src_port = ntoh16(tcp_header->src_port);
        dest_port = ntoh16(tcp_header->dest_port);

        // The "offset_reserved_flags" is a 16-bit chunk. We MUST convert its endianness 
        // before we try to extract individual bits using bitwise operations!
        uint16_t off_res_flags = ntoh16(tcp_header->offset_reserved_flags);

        // 1. Extract the TCP Flags (The lowest 8 bits of the 16-bit chunk)
        // Mask: 0x00FF (0000 0000 1111 1111 in binary)
        tcp_flags = off_res_flags & 0x00FF;

        // 2. Extract the Data Offset (The highest 4 bits of the 16-bit chunk)
        // We shift the bits right by 12 spaces to push the 4 bits to the bottom, then mask.
        uint8_t data_offset = (off_res_flags >> 12) & 0x0F;
        
        // The Data Offset tells us the header length in 32-bit words (just like IPv4 IHL)
        uint32_t actual_header_bytes = data_offset * 4;

        // Secondary safety check in case of malformed packets advertising a fake offset
        if (packet_length < offset + actual_header_bytes) {
            return false;
        }

        // Advance the offset dynamically. 
        // The offset now points EXACTLY to the start of the Application Payload (e.g., HTTP data)!
        offset += actual_header_bytes;

        return true;
    }

    bool PacketParser::parse_udp(const uint8_t* packet_data, 
                                 uint32_t packet_length, 
                                 uint32_t& offset,
                                 uint16_t& src_port,
                                 uint16_t& dest_port) {
        
        // Safety check for the exact UDP header size (8 bytes)
        if (packet_length < offset + sizeof(UDPHeader)) {
            return false;
        }

        const UDPHeader* udp_header = reinterpret_cast<const UDPHeader*>(packet_data + offset);

        // Convert Ports from Network Endian to Host Endian
        src_port = ntoh16(udp_header->src_port);
        dest_port = ntoh16(udp_header->dest_port);

        // Advance the offset dynamically. 
        // UDP headers are strictly 8 bytes, so we just add the struct size!
        // The offset now points EXACTLY to the start of the Application Payload (e.g., DNS data).
        offset += sizeof(UDPHeader);

        return true;
    }
}