#pragma once

#include <iostream>
#include "connection.h"

namespace NetHex {

    class FastPath {
    private:
        // How many packets to inspect before trusting the flow
        static constexpr uint32_t BYPASS_THRESHOLD = 10;

    public:
        // Evaluates a connection and decides if we should skip DPI
        static inline bool should_bypass(Connection& conn) {
            // 1. If we already marked it as bypassed, immediately return true
            if (conn.is_bypassed) {
                return true;
            }

            // 2. If it was flagged as malware, NEVER bypass it (keep logging/dropping)
            if (conn.is_malicious) {
                return false;
            }

            // 3. Increment packet count. If it hits the threshold, flip the bypass flag!
            conn.packet_count++;
            if (conn.packet_count > BYPASS_THRESHOLD) {
                conn.is_bypassed = true;
                
                std::cout << "[Fast-Path] Threshold reached (10 packets). Flow offloaded to Fast-Path!\n";
                return true; 
            }

            // 4. Threshold not met yet, keep inspecting
            return false;
        }
    };

}