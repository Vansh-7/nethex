#include "ip_defragmenter.h"
#include <spdlog/spdlog.h>
#include <cstring>
#include <algorithm>

namespace NetHex {

    bool IpDefragmenter::is_fully_covered(const std::vector<bool>& received, uint32_t length) {
        if (received.size() < length) return false;
        for (uint32_t i = 0; i < length; ++i) {
            if (!received[i]) return false;
        }
        return true;
    }

    bool IpDefragmenter::process_fragment(uint32_t src_ip, uint32_t dest_ip, uint8_t protocol,
                                           uint16_t identification, uint16_t fragment_offset_units,
                                           bool more_fragments,
                                           const uint8_t* frag_payload, uint32_t frag_payload_len,
                                           const uint8_t*& out_payload, uint32_t& out_length) {
        out_payload = nullptr;
        out_length = 0;

        if (frag_payload == nullptr || frag_payload_len == 0) return false;
        
        // IP header saves space by measuring offsets in units of 8 bytes. 
        // So an offset of 5 means byte 40.
        const uint32_t byte_offset = static_cast<uint32_t>(fragment_offset_units) * 8;

        // Computed in 64 bits deliberately: o prevent an integer overflow attack, where an 
        // attacker intentionally sends a massive offset to reset the math to a small number.
        const uint64_t end_offset64 = static_cast<uint64_t>(byte_offset) + frag_payload_len;

        if (end_offset64 > MAX_DATAGRAM_SIZE) {
            spdlog::warn("[Defrag] Rejected fragment claiming datagram > 65535 bytes "
                         "(possible evasion attempt). id={}", identification);
            return false;
        }
        const uint32_t end_offset = static_cast<uint32_t>(end_offset64);

        FragmentKey key{src_ip, dest_ip, identification, protocol};

        auto it = buffers_.find(key);
        if (it == buffers_.end()) {
            // New Fragment, create new FragmentBuffer.
            // unless we have hit memory limit (4096)
            if (buffers_.size() >= MAX_CONCURRENT_DATAGRAMS) {
                spdlog::warn("[Defrag] Fragment table full ({} datagrams in flight). Dropping fragment.",
                             MAX_CONCURRENT_DATAGRAMS);
                return false;
            }
            auto [new_it, inserted] = buffers_.emplace(key, FragmentBuffer{});
            (void)inserted;
            it = new_it;
        }

        FragmentBuffer& buf = it->second;

        if (end_offset > buf.data.size()) {
            buf.data.resize(end_offset, 0);
            buf.received.resize(end_offset, false);
        }

        // copy the bytes into their exact correct position (byte_offset) => data 
        // and mark those specific bytes as true in bitmap => received
        std::memcpy(buf.data.data() + byte_offset, frag_payload, frag_payload_len);
        std::fill(buf.received.begin() + byte_offset, buf.received.begin() + end_offset, true);

        if (!more_fragments) { // no more fragments
            buf.got_last_fragment = true;
            buf.total_length = end_offset;
        }

        if (buf.got_last_fragment && is_fully_covered(buf.received, buf.total_length)) {
            // Return reassembled packet!
            completed_datagram_ = std::move(buf.data);
            completed_datagram_.resize(buf.total_length); // Trim any stale tail from an overlength earlier fragment
            buffers_.erase(it);

            out_payload = completed_datagram_.data();
            out_length = static_cast<uint32_t>(completed_datagram_.size());

            spdlog::debug("[Defrag] Datagram reassembled. id={} total_bytes={}", identification, out_length);
            return true;
        }

        return false;
    }

    void IpDefragmenter::evict_stale_fragments() {
        auto now = std::chrono::steady_clock::now();
        size_t evicted = 0;

        for (auto it = buffers_.begin(); it != buffers_.end(); ) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_seen).count();
            if (age > FRAGMENT_TIMEOUT_SECONDS) {
                it = buffers_.erase(it);
                ++evicted;
            } else {
                ++it;
            }
        }

        if (evicted > 0) {
            spdlog::info("[Defrag] Evicted {} incomplete/stale datagrams (fragment timeout).", evicted);
        }
    }
}