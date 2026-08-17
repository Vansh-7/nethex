#include "sni_extractor.h"

namespace NetHex {

    std::string SniExtractor::extract_sni(const uint8_t* payload, uint32_t payload_length) {
        // 1. Check TLS Record Header (5 bytes)
        // Byte [0] MUST be 0x16 (Handshake Protocol)
        if (payload_length < 5 || payload[0] != 0x16) return "";

        // 2. Check Handshake Header
        // Byte [5] MUST be 0x01 (Client Hello)
        if (payload_length < 9 || payload[5] != 0x01) return "";

        // The Client Hello header + Client Version (2) + Random (32) = 38 bytes
        // We start our pointer jump 43 bytes in (5 byte Record Header + 38 bytes)
        uint32_t offset = 43; 

        // 3. Jump over Session ID (Dynamic Length)
        if (offset >= payload_length) return "";
        uint8_t session_id_len = payload[offset];
        offset += 1 + session_id_len;

        // 4. Jump over Cipher Suites (Dynamic Length - 16 bit integer)
        if (offset + 2 > payload_length) return "";
        // Bitwise trick to read 2 bytes into a 16-bit integer (Network Byte Order / Big Endian)
        uint16_t cipher_suites_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2 + cipher_suites_len;

        // 5. Jump over Compression Methods (Dynamic Length)
        if (offset >= payload_length) return "";
        uint8_t comp_methods_len = payload[offset];
        offset += 1 + comp_methods_len;

        // 6. Enter the Extensions Block
        if (offset + 2 > payload_length) return "";
        uint16_t ext_total_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;

        uint32_t ext_end = offset + ext_total_len;
        if (ext_end > payload_length) ext_end = payload_length; // Safety bounds check

        // 7. Iterate through Extensions to find SNI (Type 0x0000)
        while (offset + 4 <= ext_end) {
            uint16_t ext_type = (payload[offset] << 8) | payload[offset + 1];
            uint16_t ext_len = (payload[offset + 2] << 8) | payload[offset + 3];
            offset += 4;

            if (ext_type == 0x0000) { // SNI FOUND!
                if (offset + 5 > ext_end) return "";
                
                // Read the actual string length
                uint16_t sni_len = (payload[offset + 3] << 8) | payload[offset + 4];
                offset += 5;
                
                // Return the extracted domain!
                if (offset + sni_len <= ext_end) {
                    return std::string(reinterpret_cast<const char*>(payload + offset), sni_len);
                }
            }
            // Jump to the next extension if this wasn't SNI
            offset += ext_len; 
        }

        return ""; // No SNI found
    }

}