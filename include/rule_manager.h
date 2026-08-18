#pragma once

#include "pattern_matcher.h"
#include <string>

namespace NetHex {

    class RuleManager {
    public:
        // Reads a Suricata-style .rules file and loads the 'content' 
        // patterns directly into our Aho-Corasick scanner.
        static bool load_rules(const std::string& filepath, PatternMatcher& scanner);
    };
}