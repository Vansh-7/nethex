#pragma once

#include <vector>
#include <memory>
#include <cstdint>
#include <stdexcept>
#include "thread_safe_queue.h"
#include "types.h"

class LoadBalancer {
private:
    size_t num_workers_;
    // A vector of unique pointers to our Lock-Free Queues.
    // One dedicated queue per worker thread.
    std::vector<std::unique_ptr<LockFreeQueue<ParsedPacket>>> worker_queues_;

public:
    // Initialize the balancer with the number of CPU cores we want to use
    explicit LoadBalancer(size_t num_workers, size_t queue_capacity = 8192) 
        : num_workers_(num_workers) {
        
        if (num_workers == 0) {
            throw std::invalid_argument("Must have at least 1 worker core.");
        }

        // Create a separate queue for each worker core
        for (size_t i = 0; i < num_workers; ++i) {
            worker_queues_.push_back(
                std::make_unique<LockFreeQueue<ParsedPacket>>(queue_capacity)
            );
        }
    }

    // Called ONLY by the single Ingestion Thread for EVERY packet
    bool dispatch(const ParsedPacket& packet, uint64_t flow_hash) {
        // THE MAGIC TRICK: Flow-Aware Routing
        // Modulo arithmetic ensures the same flow hash ALWAYS goes to the same worker ID.
        size_t worker_id = flow_hash % num_workers_;
        
        // Push the packet into that specific worker's wait-free queue
        return worker_queues_[worker_id]->push(packet);
    }
    
    // Called ONLY by the Worker Threads upon startup to grab a pointer to their specific queue
    LockFreeQueue<ParsedPacket>* get_queue(size_t worker_id) {
        if (worker_id >= num_workers_) {
            return nullptr; // Safety check
        }
        return worker_queues_[worker_id].get();
    }
};