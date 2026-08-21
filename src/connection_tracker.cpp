#include "connection_tracker.h"
#include <spdlog/spdlog.h>

namespace NetHex {

    Connection* ConnectionTracker::process_tcp_packet(const FiveTuple& tuple, uint8_t tcp_flags, uint32_t payload_size) {
        
        // 1. Bitwise Extraction of TCP Flags
        // The flags arrive as a single byte.
        bool is_syn = (tcp_flags & 0x02) != 0;
        bool is_ack = (tcp_flags & 0x10) != 0;
        bool is_fin = (tcp_flags & 0x01) != 0;
        bool is_rst = (tcp_flags & 0x04) != 0;

        // 2. Lookup the connection in our Flow Table (O(1) time complexity)
        auto it = flow_table.find(tuple);

        if (it == flow_table.end()) {
            // FLOW DOES NOT EXIST. Is this the start of a new connection?
            
            if (is_syn && !is_ack) {
                // Legitimate start of a TCP connection (First step of the Handshake)
                TrackedFlow new_flow;
                new_flow.conn.state = TcpState::SYN_SENT;
                new_flow.conn.total_bytes = payload_size;
                new_flow.conn.total_packets = 1;
                new_flow.conn.last_seen = std::chrono::steady_clock::now();
                
                // LRU LOGIC
                // Push the new tuple to the front of the list, and save that iterator in the map!
                lru_list.push_front(tuple);
                new_flow.lru_it = lru_list.begin();
                // Insert into map (This may cause a rehash!)
                flow_table[tuple] = new_flow;
                spdlog::debug("[Tracker] [+] New Flow Created (SYN). Active Flows: {}", flow_table.size());

                return &(flow_table[tuple].conn);
            } else {
                // SECURITY FEATURE: We saw a packet for a flow that doesn't exist, and it's NOT a SYN.
                // This could be a late packet from a closed connection, or a hacker sending spoofed traffic!
                // We drop/ignore it to protect our engine's memory.
                return nullptr;
            }
        } else {
            // FLOW EXISTS! We pull out the existing state.
            TrackedFlow& flow = it->second;
            Connection& conn = flow.conn;
            
            // Update traffic stats and timestamps
            conn.total_bytes += payload_size;
            conn.total_packets += 1;
            conn.last_seen = std::chrono::steady_clock::now();

            // --- ZERO ALLOCATION LRU UPDATE ---
            // Move this flow to the very front of the list (it is the most recently used!)
            // .splice() unlinks the node and relinks it at the head without allocating memory.
            if (flow.lru_it != lru_list.begin()) {
                lru_list.splice(lru_list.begin(), lru_list, flow.lru_it);
            }

            // 3. The TCP State Machine Logic
            if (conn.state == TcpState::SYN_SENT && is_syn && is_ack) {
                // Server replied with SYN-ACK!
                conn.state = TcpState::SYN_RCVD;
            } 
            else if (conn.state == TcpState::SYN_RCVD && is_ack) {
                // Client replied with final ACK! Handshake is complete.
                conn.state = TcpState::ESTABLISHED;
                spdlog::debug("[Tracker] [==>] Flow ESTABLISHED!");
            }
            else if (is_fin || is_rst) {
                // The connection is being torn down.
                conn.state = TcpState::CLOSED;
                spdlog::debug("[Tracker] [-] Flow CLOSED.");
                
                // Note: We don't delete it from the map immediately. 
                // We leave it here so our future LRU Cache/Timeout system can clean it up efficiently.
            }

            return &conn;
        }
    }

    void ConnectionTracker::evict_stale_sessions() {
        auto now = std::chrono::steady_clock::now();
        size_t evicted_count = 0;

        // --- O(1) GARBAGE COLLECTOR ---
        // Because the list is ordered by time, we ONLY check the very back of the list!
        while (!lru_list.empty()) {
            const FiveTuple& oldest_tuple = lru_list.back();
            auto map_it = flow_table.find(oldest_tuple);

            if (map_it == flow_table.end()) {
                lru_list.pop_back(); // Safety fallback
                continue;
            }
            
            const Connection& conn = map_it->second.conn;
            // Calculate how many seconds have passed since we last saw a packet for this flow
            auto duration_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - conn.last_seen).count();

            bool should_evict = false;

            // --- THE EVICTION RULES ---
            if (conn.state == TcpState::CLOSED && duration_seconds > 5) {
                should_evict = true; // 1. It closed properly. Give a 5-second grace period for the 4-way teardown.
            }
            else if (conn.state == TcpState::SYN_SENT && duration_seconds > 10) {
                should_evict = true; // 2. SYN Flood Protection! No reply after 10 seconds? Kill it.
            } 
            else if (conn.state == TcpState::SYN_RCVD && duration_seconds > 10) {
                should_evict = true; // 3. Half-Open Connection Timeout! Client vanished during handshake.
            }
            else if (conn.state == TcpState::ESTABLISHED && duration_seconds > 300) {
                should_evict = true; // 4. Idle Timeout. No data for 5 minutes? Kill it.
            }

            // Because the list is chronological, if the oldest flow hasn't timed out, NOTHING has.
            if (!should_evict) {
                break; 
            }

            // THE SAFE DELETION
            spdlog::debug("[Tracker] Evicting stale flow.");
            flow_table.erase(map_it);
            lru_list.pop_back(); 
            evicted_count++;
        }

        if (evicted_count > 0) {
            spdlog::info("[Garbage Collector] Evicted {} stale flows. Active memory: {} flows.", evicted_count, flow_table.size());
        }
    }

    size_t ConnectionTracker::get_active_flow_count() const {
        return flow_table.size();
    }
}