#include "pattern_matcher.h"

namespace NetHex {

    PatternMatcher::PatternMatcher() {
        // Initialize the root node (Index 0)
        trie.emplace_back(); 
    }

    void PatternMatcher::add_pattern(const std::string& pattern) {
        int current_node = 0; // Start at root
        
        for (char c : pattern) {
            uint8_t byte_val = static_cast<uint8_t>(c);
            
            // If the path doesn't exist, create a new node
            if (trie[current_node].children[byte_val] == -1) {
                trie[current_node].children[byte_val] = trie.size();
                trie.emplace_back();
            }
            // Move down the tree
            current_node = trie[current_node].children[byte_val];
        }
        
        // Mark the end of this path as a successful match for the signature
        trie[current_node].matched_patterns.push_back(pattern);
    }

    void PatternMatcher::build_machine() {
        std::queue<int> q;

        // 1. Set the fail links for all direct children of the root to point back to root
        for (int i = 0; i < 256; ++i) {
            if (trie[0].children[i] != -1) {
                trie[trie[0].children[i]].fail_link = 0;
                q.push(trie[0].children[i]);
            } else {
                // Optimization: Loop unexisting root transitions back to root
                trie[0].children[i] = 0; 
            }
        }

        // 2. BFS to set fail links for the rest of the tree
        while (!q.empty()) {
            int current = q.front();
            q.pop();

            for (int i = 0; i < 256; ++i) {
                int child = trie[current].children[i];
                if (child != -1) {
                    q.push(child);

                    // Find the fail link for the child
                    int fail_state = trie[current].fail_link;
                    while (trie[fail_state].children[i] == -1) {
                        fail_state = trie[fail_state].fail_link;
                    }
                    trie[child].fail_link = trie[fail_state].children[i];

                    // Merge matches from the fail link (e.g., matching "he" also matches "e")
                    for (const auto& match : trie[trie[child].fail_link].matched_patterns) {
                        trie[child].matched_patterns.push_back(match);
                    }
                }
            }
        }
    }

    std::vector<std::string> PatternMatcher::search(const uint8_t* payload, uint32_t payload_length) {
        std::vector<std::string> results;
        if (payload_length == 0 || payload == nullptr) return results;

        int current_state = 0;

        for (uint32_t i = 0; i < payload_length; ++i) {
            uint8_t byte_val = payload[i];

            // Follow fail links until we find a valid transition
            while (trie[current_state].children[byte_val] == -1) {
                current_state = trie[current_state].fail_link;
            }

            // Transition to the next state
            current_state = trie[current_state].children[byte_val];

            // If this state contains matched patterns, record them!
            if (!trie[current_state].matched_patterns.empty()) {
                for (const auto& match : trie[current_state].matched_patterns) {
                    results.push_back(match);
                }
            }
        }

        return results;
    }

}