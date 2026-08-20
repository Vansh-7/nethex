#pragma once

#include <cstdint>
#include <functional> //for std::hash

namespace NetHex {

    // Force strict 1-byte alignment to save memory
    // since we will store MILLIONS of these in our flow table
    #pragma pack(push, 1)
    struct FiveTuple {
        uint32_t src_ip;
        uint32_t dest_ip;
        uint16_t src_port;
        uint16_t dest_port;
        uint8_t protocol;
        
        // In C++, if we want to use a struct as a Key in a Hash Map, 
        // we MUST define the equality operator (==) so the map knows 
        // how to check if two keys are identical (handling hash collisions).
        bool operator==(const FiveTuple& other) const {
            return src_ip == other.src_ip &&
                   dest_ip == other.dest_ip &&
                   src_port == other.src_port &&
                   dest_port == other.dest_port &&
                   protocol == other.protocol;
        }
    };
    #pragma pack(pop)

    // A helper function to create a mathematically sorted FiveTuple
    // This enforces Bidirectional Hashing
    inline FiveTuple create_bidirectional_tuple(uint32_t s_ip, uint32_t d_ip, 
                                                uint16_t s_port, uint16_t d_port,
                                                uint8_t proto) {
        // MUST zero-initialize {} so padding/unused bytes don't corrupt the xxHash!
        FiveTuple tuple{};
        tuple.protocol = proto;

        // Sort the IPs and Ports so the hash is identical for both directions of the flow
        if (s_ip < d_ip) {
            tuple.src_ip = s_ip;
            tuple.dest_ip = d_ip;
            tuple.src_port = s_port;
            tuple.dest_port = d_port;
        } else if (s_ip > d_ip) {
            tuple.src_ip = d_ip;
            tuple.dest_ip = s_ip;
            tuple.src_port = d_port;
            tuple.dest_port = s_port;
        } else {
            // If IPs are identical (e.g., localhost loopback), sort by port
            tuple.src_ip = s_ip;
            tuple.dest_ip = d_ip;
            if (s_port < d_port) {
                tuple.src_port = s_port;
                tuple.dest_port = d_port;
            } else {
                tuple.src_port = d_port;
                tuple.dest_port = s_port;
            }
        }
        
        return tuple;
    }
}