#include "dns_parser.h"
#include "types.h"
#include "platform.h"

namespace NetHex {

    namespace {
        constexpr int MAX_COMPRESSION_JUMPS = 16; // Loop protection for hostile pointer chains
        constexpr uint16_t MAX_QUESTIONS = 64;    // Sanity cap - real queries have 1, rarely more
    }

    bool DnsParser::decode_name(const uint8_t* payload, uint32_t payload_length,
                                 uint32_t& offset, std::string& out_name) {
        out_name.clear();
        uint32_t cursor = offset;      // tracks where u reading rn
        bool jumped = false;           // taken compression ptr?
        uint32_t post_name_offset = 0; // remember where to return after following ptr
        int jumps = 0;

        while (true) {
            if (cursor >= payload_length) return false;

            // dns => www.google.com => [3]www[6]google[3]com[0]
            // [x]; here x = label_len
            uint8_t label_len = payload[cursor]; 

            // Compression pointer: top two bits are 11 (0xC0)
            if ((label_len & 0xC0) == 0xC0) {
                if (cursor + 1 >= payload_length) return false;
                if (++jumps > MAX_COMPRESSION_JUMPS) return false; // Refuse pointer infinite loops
                
                // combine remaining 6 bits of 1st byte with 2nd byte to
                // find target offset location
                uint16_t pointer = static_cast<uint16_t>((label_len & 0x3F) << 8) | payload[cursor + 1];

                if (!jumped) {
                    post_name_offset = cursor + 2; // Caller resumes right after the pointer
                    jumped = true;
                }

                if (pointer >= payload_length) return false;
                cursor = pointer; // jump to this location & restart loop
                continue;
            }

            // Null terminator: end of domain name
            if (label_len == 0) {
                cursor += 1;
                if (!jumped) post_name_offset = cursor;
                break;
            }

            // Regular label (RFC 1035: max 63 bytes)
            if (label_len > 63) return false;
            uint32_t label_start = cursor + 1;
            if (label_start + label_len > payload_length) return false;
            
            // append a dot if it's not the first word
            if (!out_name.empty()) out_name += '.';
            
            // append the characters to the string
            out_name.append(reinterpret_cast<const char*>(payload + label_start), label_len);

            cursor = label_start + label_len; // push the cursor forward
        }

        // update the main "offset" reference to post_name_offset so the main
        // extract_queries loop knows exactly where the Question block ended!
        offset = post_name_offset;
        return true;
    }

    std::vector<DnsQuery> DnsParser::extract_queries(const uint8_t* payload, uint32_t payload_length) {
        std::vector<DnsQuery> results;

        if (payload == nullptr || payload_length < sizeof(DnsHeader)) return results;

        // map struct over raw bytes to extract DNS header (12 bytes)
        const DnsHeader* header = reinterpret_cast<const DnsHeader*>(payload);
        uint16_t qd_count = ntoh16(header->qd_count);

        // sanity check: If someone asks 500 questions in one packet, it's a DoS attack
        // capped at 64 above!
        if (qd_count == 0 || qd_count > MAX_QUESTIONS) return results;

        uint32_t offset = sizeof(DnsHeader); // 12 bytes (since after header questions begin)

        // loop through every question
        for (uint16_t i = 0; i < qd_count; ++i) {
            std::string domain;

            // here offset is passed by ref, so as decode_name reads bytes
            // it pushes offset forward
            if (!decode_name(payload, payload_length, offset, domain)) break;

            // QTYPE (2 bytes) + QCLASS (2 bytes) follow the domain name
            if (offset + 4 > payload_length) break;
            // Read the next 2 bytes, stitch them into a 16-bit integer (Network Byte Order to Host)
            uint16_t qtype = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1];
            // Skip over the QTYPE (2 bytes) and QCLASS (2 bytes)
            offset += 4;

            results.push_back({std::move(domain), qtype});
        }

        return results;
    }
}