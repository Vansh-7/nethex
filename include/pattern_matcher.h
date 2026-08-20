#pragma once

#include <string>
#include <vector>
#include <queue>
#include <cstdint>

namespace NetHex {

    // A node in our Aho-Corasick State Machine
    struct TrieNode {
        int children[256]; // Array holding indices to child nodes for every possible byte
        int fail_link;     // Where to jump if a match fails
        std::vector<std::string> matched_patterns; // Signatures that end at this node

        TrieNode() {
            // Initialize all children to -1 (meaning no path exists yet)
            for (int i = 0; i < 256; ++i) children[i] = -1;
            fail_link = 0; // Default fail link points back to the root (node 0)
        }
    };

    class PatternMatcher {
    public:
        PatternMatcher();
        ~PatternMatcher() = default;

        // 1. Add a malware signature to the state machine
        void add_pattern(const std::string& pattern);

        // 2. Compile the failure links (Must be called AFTER all patterns are added)
        void build_machine();

        // 3. Scan a raw payload for any of the loaded patterns in a single pass
        std::vector<std::string> search(const uint8_t* payload, uint32_t payload_length, int& current_state);

    private:
        // Memory-safe, contiguous array to hold our state machine
        std::vector<TrieNode> trie; 
    };

}