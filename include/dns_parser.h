#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace NetHex {

    struct DnsQuery {
        std::string domain;
        uint16_t qtype;
    };

    class DnsParser {
    public:
        // Parses a raw DNS payload (UDP/TCP port 53) and returns every queried
        // domain in the Question section. Returns an empty vector if malformed
        // or not DNS. Safe against out-of-bounds reads and compression-pointer
        // loops on hostile input.
        static std::vector<DnsQuery> extract_queries(const uint8_t* payload, uint32_t payload_length);

    private:
        // Decodes a single (possibly compressed) DNS name starting at `offset`.
        // On success, advances `offset` to point just past the name AS ENCODED
        // IN THE MESSAGE (i.e. past the compression pointer if one was used,
        // NOT into the jumped-to location).
        static bool decode_name(const uint8_t* payload, uint32_t payload_length,
                                 uint32_t& offset, std::string& out_name);
    };
}