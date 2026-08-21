#include "rule_manager.h"
#include <spdlog/spdlog.h>
#include <fstream>
#include <vector>

namespace NetHex {
    
    bool RuleManager::load_rules(const std::string& filepath, PatternMatcher& scanner) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            spdlog::critical("[RuleManager] CRITICAL ERROR: Could not open rule file: {}", filepath);
            return false;
        }

        std::string line;
        int loaded_count = 0;

        while (std::getline(file, line)) {
            // 1. Skip empty lines and comments (lines starting with #)
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // 2. We are specifically looking for the content:"..." keyword
            std::string content_keyword = "content:\"";
            size_t start_pos = line.find(content_keyword);
            
            if (start_pos != std::string::npos) {
                // Shift pointer to the start of the actual string value
                start_pos += content_keyword.length();
                
                // Find the closing quote
                size_t end_pos = line.find("\"", start_pos);
                if (end_pos != std::string::npos) {
                    // Extract the signature!
                    std::string signature = line.substr(start_pos, end_pos - start_pos);
                    if (signature.empty()) {
                        spdlog::warn("[RuleManager] Skipping empty content signature on line: {}", line);
                        continue;
                    }
                    
                    // Add it to our Aho-Corasick Engine
                    scanner.add_pattern(signature);
                    loaded_count++;
                }
            }
        }

        file.close();
        spdlog::info("[RuleManager] Successfully loaded {} signatures from {}", loaded_count, filepath);
        return true;
    }

}