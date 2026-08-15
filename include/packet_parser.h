#pragma once

#include "types.h"
#include <cstdint>

namespace NetHex {
    class PacketParser {
    public:
        // Parse Layer 2: Returns true if the next layer is IPv4
        static bool parse_ethernet(const uint8_t* packet_data, 
                                   uint32_t packet_length, 
                                   uint32_t& offset,
                                   uint16_t& next_protocol);
        
        // Parse Layer 3: Extracts IPs and returns the next protocol (TCP/UDP)
        static bool parse_ipv4(const uint8_t* packet_data, 
                               uint32_t packet_length, 
                               uint32_t& offset,
                               uint32_t& src_ip,
                               uint32_t& dest_ip,
                               uint8_t& next_protocol);

        // Parse Layer 4 (TCP):
        // Extracts ports and flags, and advances the offset to the actual payload (L7 data).
        static bool parse_tcp(const uint8_t* packet_data, 
                              uint32_t packet_length, 
                              uint32_t& offset,
                              uint16_t& src_port,
                              uint16_t& dest_port,
                              uint8_t& tcp_flags);

        // Parse Layer 4 (UDP):
        // Extracts ports and advances the offset to the actual payload (L7 data).
        static bool parse_udp(const uint8_t* packet_data, 
                              uint32_t packet_length, 
                              uint32_t& offset,
                              uint16_t& src_port,
                              uint16_t& dest_port);
    };
}