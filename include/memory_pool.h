#pragma once
#include <vector>
#include <cstdint>
#include <queue>
#include <mutex>
#include <spdlog/spdlog.h>

namespace NetHex {
    class PacketMemoryPool {
    private:
        // The massive pre-allocated 2D array of bytes
        std::vector<std::vector<uint8_t>> pool;
        
        // Use a standard std::queue and a mutex for Multi-Producer safety
        std::queue<uint32_t> free_slots;
        std::mutex pool_mutex;

        size_t max_payload_size;

    public:
        PacketMemoryPool(size_t capacity, size_t payload_size = 2048) 
            : pool(capacity, std::vector<uint8_t>(payload_size)), 
              max_payload_size(payload_size) {
            
            // At startup, every slot is free! Push all IDs into the queue.
            for (uint32_t i = 0; i < capacity; ++i) {
                free_slots.push(i);
            }
            spdlog::info("[MemoryPool] Pre-allocated {} packet slots ({} bytes each).", capacity, payload_size);
        }

        // Reader Thread calls this to borrow memory
        bool acquire_slot(uint32_t& out_slot_id, uint8_t*& out_buffer_ptr) {
            std::lock_guard<std::mutex> lock(pool_mutex);
            if (!free_slots.empty()) {
                out_slot_id = free_slots.front();
                free_slots.pop();
                out_buffer_ptr = pool[out_slot_id].data();
                return true;
            }
            return false; // Pool exhausted!
        }

        // Multiple Worker Threads call this to return memory concurrently
        void release_slot(uint32_t slot_id) {
            std::lock_guard<std::mutex> lock(pool_mutex);
            free_slots.push(slot_id);
        }
    };
}