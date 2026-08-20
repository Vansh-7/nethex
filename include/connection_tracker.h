#pragma once

#include "five_tuple.h"
#include "connection.h"
#include "xxhash_functor.h"
#include <unordered_map>

namespace NetHex {

    class ConnectionTracker {
    private:
        // THE FLOW TABLE! 
        // This is the most important data structure in the entire engine.
        // It maps a FiveTuple (Key) to a Connection State (Value) using our custom xxHash.
        std::unordered_map<FiveTuple, Connection, XxHashFunctor> flow_table;

    public:
        ConnectionTracker() = default;
        ~ConnectionTracker() = default;

        // Core ingestion function: Call this every time we parse a TCP packet
        Connection* process_tcp_packet(const FiveTuple& tuple, uint8_t tcp_flags, uint32_t payload_size);

        // Garbage Collector: Cleans up dead or timed-out connections
        void evict_stale_sessions();
        
        // Utility to check how many active flows we are tracking
        size_t get_active_flow_count() const;
    };

}