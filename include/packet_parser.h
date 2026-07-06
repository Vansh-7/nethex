#pragma once

#include "types.h"
#include <iostream>

namespace NetHex {
    class PacketParser {
    public:
        // Parse Layer 2: Returns true if the next layer is IPv4
        static bool parse_ethernet(const uint8_t* packet_data, uint32_t packet_length, uint16_t& next_protocol);
        
        // Parse Layer 3: Extracts IPs and returns the next protocol (TCP/UDP)
        static bool parse_ipv4(const uint8_t* packet_data, uint32_t packet_length, uint32_t offset);
    };
}