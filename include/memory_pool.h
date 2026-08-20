#pragma once
#include <vector>
#include <cstdint>
#include "thread_safe_queue.h"
#include <spdlog/spdlog.h>

namespace NetHex {
    class PacketMemoryPool {
    private:
        // The massive pre-allocated 2D array of bytes
        std::vector<std::vector<uint8_t>> pool;
        
        // A lock-free queue that simply holds the indices (0, 1, 2...) of available slots
        ThreadSafeQueue<uint32_t> free_slots;
        size_t max_payload_size;

    public:
        PacketMemoryPool(size_t capacity, size_t payload_size = 2048) 
            : pool(capacity, std::vector<uint8_t>(payload_size)), 
              free_slots(capacity), 
              max_payload_size(payload_size) {
            
            // At startup, every slot is free! Push all IDs into the queue.
            for (uint32_t i = 0; i < capacity; ++i) {
                free_slots.push(i);
            }
            spdlog::info("[MemoryPool] Pre-allocated {} packet slots ({} bytes each).", capacity, payload_size);
        }

        // Reader Thread calls this to borrow memory
        bool acquire_slot(uint32_t& out_slot_id, uint8_t*& out_buffer_ptr) {
            if (free_slots.pop(out_slot_id)) {
                out_buffer_ptr = pool[out_slot_id].data();
                return true;
            }
            return false; // Pool exhausted! (Under heavy load)
        }

        // Worker Thread calls this to return memory after inspection
        void release_slot(uint32_t slot_id) {
            free_slots.push(slot_id);
        }
    };
}