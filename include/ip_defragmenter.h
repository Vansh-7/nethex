#pragma once

#include <cstdint>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <xxhash.h>

namespace NetHex {

    // ------------------------------------------------------------------------
    // FRAGMENT IDENTIFICATION KEY
    // ------------------------------------------------------------------------
    // fragments of the same datagram share (Src IP, Dest IP, Protocol, Identification). 
    // Unlike FiveTuple this is intentionally NOT sorted/bidirectional
    // - a fragment set is a one-way IP-layer object with no L4 ports of its own yet
    // (those live inside fragment #0's payload, which we can't safely read until reassembly completes).
    #pragma pack(push, 1)
    struct FragmentKey {
        uint32_t src_ip;
        uint32_t dest_ip;
        uint16_t identification;
        uint8_t  protocol;

        bool operator==(const FragmentKey& other) const {
            return src_ip == other.src_ip &&
                   dest_ip == other.dest_ip &&
                   identification == other.identification &&
                   protocol == other.protocol;
        }
    };
    #pragma pack(pop)

    struct FragmentKeyHasher {
        std::size_t operator()(const FragmentKey& key) const {
            return XXH64(&key, sizeof(FragmentKey), 0);
        }
    };

    // ------------------------------------------------------------------------
    // IP DEFRAGMENTER
    // ------------------------------------------------------------------------
    // Single-threaded by design (ingestion thread only) - no mutex needed.
    class IpDefragmenter {
    public:
        static constexpr uint32_t MAX_DATAGRAM_SIZE = 65535;      // RFC 791 hard limit
        static constexpr uint32_t FRAGMENT_TIMEOUT_SECONDS = 30;  // Also our anti-exhaustion GC
        static constexpr size_t MAX_CONCURRENT_DATAGRAMS = 4096;  // Bounds worst-case memory

        // Feed one IPv4 fragment in.
        //
        // fragment_offset_units: the raw 13-bit Fragment Offset field (units of
        //                        8 bytes - do NOT pre-multiply before calling).
        // more_fragments:        the MF bit from the IP header.
        // frag_payload/len:      bytes AFTER the IP header for THIS physical
        //                        packet only.
        //
        // Returns true iff this fragment completed the datagram. On true,
        // out_payload/out_length point at the reassembled L4 payload - an
        // internal buffer valid until the next call, so the caller must finish
        // using it (e.g. copy into the memory pool) before calling again.
        bool process_fragment(uint32_t src_ip, uint32_t dest_ip, uint8_t protocol,
                               uint16_t identification, uint16_t fragment_offset_units,
                               bool more_fragments,
                               const uint8_t* frag_payload, uint32_t frag_payload_len,
                               const uint8_t*& out_payload, uint32_t& out_length);

        // Garbage-collect fragment sets that never completed (mirrors
        // ConnectionTracker::evict_stale_sessions). Call periodically.
        void evict_stale_fragments();

        size_t get_pending_datagram_count() const { return buffers_.size(); }

    private:
        struct FragmentBuffer {
            std::vector<uint8_t> data;
            std::vector<bool> received;   // Per-byte coverage bitmap
            uint32_t total_length{0};     // Known once the MF=0 fragment arrives
            bool got_last_fragment{false};
            std::chrono::steady_clock::time_point first_seen{std::chrono::steady_clock::now()};
        };

        static bool is_fully_covered(const std::vector<bool>& received, uint32_t length);

        std::unordered_map<FragmentKey, FragmentBuffer, FragmentKeyHasher> buffers_;
        std::vector<uint8_t> completed_datagram_; // Scratch space returned to caller on completion
    };
}