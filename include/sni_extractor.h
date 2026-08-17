#pragma once

#include <cstdint>
#include <string>

namespace NetHex {

    class SniExtractor {
    public:
        // Parses a raw TLS payload and returns the SNI domain if found.
        // Returns an empty string if no SNI is found or the packet is malformed.
        static std::string extract_sni(const uint8_t* payload, uint32_t payload_length);
    };

}