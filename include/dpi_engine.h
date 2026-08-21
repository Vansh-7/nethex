#pragma once

#include "five_tuple.h"
#include "pattern_matcher.h"
#include "dns_parser.h"

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <string_view> // for zero-copy text parsing

namespace NetHex {

    class DpiEngine {
        public:
            DpiEngine();
            ~DpiEngine() = default;

            // Core inspection entry point
            // takes the raw payload pointer, its length, and flow fingerprint
            bool inspect_payload(const uint8_t* payload, uint32_t payload_length, const FiveTuple& tuple, int& ac_state, uint8_t& l7_protocol);

        private:
            // helper to safely visualize raw bytes during development
            void print_hex_dump(const uint8_t* payload, uint32_t payload_length);

            // unencrypted HTTP Payload Extractor
            bool parse_http(const uint8_t* payload, uint32_t payload_length);

            // Our high-speed scanner
            PatternMatcher scanner;
    };
}