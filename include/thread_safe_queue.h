#pragma once

#include <atomic>
#include <vector>
#include <cstddef>
#include <stdexcept>

// Standard CPU cache line size is 64 bytes for x86_64 and ARM64.
#define CACHE_LINE_SIZE 64

template <typename T>
class LockFreeQueue {
private:
    std::vector<T> buffer_;
    const size_t capacity_;
    const size_t mask_; // Used for lightning-fast modulo operations

    // alignas(64) prevents "False Sharing" between the Producer core and Consumer core.
    // Producer writes to head_.
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> head_{0}; 
    
    // Consumer writes to tail_.
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> tail_{0}; 

public:
    // Capacity MUST be a power of 2 for the bitwise AND (&) mask to work.
    // e.g., if capacity is 8192, mask is 8191 (binary: 0001 1111 1111 1111).
    explicit LockFreeQueue(size_t capacity) 
        : buffer_(capacity), capacity_(capacity), mask_(capacity - 1) {
        
        // Ensure capacity is a power of 2
        if (capacity < 2 || (capacity & (capacity - 1)) != 0) {
            throw std::invalid_argument("Queue capacity must be a power of 2");
        }
    }

    // Called ONLY by the Producer (Ingestion Thread)
    bool push(const T& item) {
        // memory_order_relaxed: We don't need synchronization to just read our own head.
        const size_t current_head = head_.load(std::memory_order_relaxed);
        
        // We read the tail. Acquire is not strictly needed here since we are just checking size, 
        // but it's safe. Relaxed is faster and standard for SPSC queues.
        const size_t current_tail = tail_.load(std::memory_order_acquire);
        
        // If the queue is full
        if (current_head - current_tail == capacity_) {
            return false; 
        }

        // Write the item to the buffer.
        // Bitwise AND (& mask_) is significantly faster than standard modulo (% capacity_)
        buffer_[current_head & mask_] = item;
        
        // memory_order_release: Ensure the item is completely written to memory 
        // BEFORE we increment the head index.
        head_.store(current_head + 1, std::memory_order_release);
        return true;
    }

    // Called ONLY by the Consumer (Worker Thread)
    bool pop(T& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        
        // memory_order_acquire: Ensure we actually see the memory writes 
        // done by the Producer before this head update.
        const size_t current_head = head_.load(std::memory_order_acquire);

        // If head equals tail, the queue is empty.
        if (current_head == current_tail) {
            return false;
        }

        // Read the item from the buffer
        item = buffer_[current_tail & mask_];
        
        // memory_order_release: Ensure we finish reading the item 
        // BEFORE we update the tail and tell the Producer the slot is free.
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }
};