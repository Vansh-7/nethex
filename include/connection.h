#pragma once

#include <cstdint>
#include <chrono>

namespace NetHex {

    // 1. Define the strictly enforced TCP states
    enum class TcpState : uint8_t {
        UNKNOWN = 0,
        SYN_SENT,       // Saw the first SYN
        SYN_RCVD,       // Saw the SYN-ACK reply
        ESTABLISHED,    // Saw the final ACK (Handshake complete)
        FIN_WAIT,       // Someone requested to close the connection
        CLOSED          // Connection is fully terminated (RST or double FIN)
    };

    // 2. The Connection State Object
    struct Connection {
        TcpState state;
        
        // Traffic Counters (Crucial for detecting data exfiltration or DDoS)
        uint64_t total_bytes;
        uint64_t total_packets;

        // Timestamps (Crucial for Session Timeouts / LRU Cache)
        // We use standard chrono to track exactly when this flow was born,
        // and exactly when we saw the last packet.
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;

        // A quick helper to initialize a brand new connection safely
        Connection(): 
            state(TcpState::UNKNOWN), 
            total_bytes(0), 
            total_packets(0),
            first_seen(std::chrono::steady_clock::now()),
            last_seen(first_seen) {}
    };
}