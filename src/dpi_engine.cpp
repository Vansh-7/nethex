#include "dpi_engine.h"
#include "sni_extractor.h"
#include "rule_manager.h"
#include <spdlog/spdlog.h>
#include <sstream>
#include <iomanip>

namespace NetHex {

    // Initialize the Engine and Load Signatures
    DpiEngine::DpiEngine() {
        spdlog::info("[DPI] Initializing Aho-Corasick Threat Scanner...");
        
        // Load signatures dynamically from the file!
        if (!RuleManager::load_rules("threats.rules", scanner)) {
            spdlog::warn("[DPI] WARNING: No external rules loaded. Engine is running blind!");
        }
        
        // Compile the Failure Links AFTER all rules are loaded
        scanner.build_machine();
        spdlog::info("[DPI] Threat Scanner Online. State machine compiled.");
    }

    bool DpiEngine::inspect_payload(const uint8_t* payload, uint32_t payload_length, const FiveTuple& tuple, int& ac_state, uint8_t& l7_proto) {
        (void)tuple;

        // Basic safety catch for absolutely empty payloads
        if (payload_length == 0 || payload == nullptr) return false;

        bool is_malicious = false;

        // ==========================================
        // 1. THE GLOBAL MALWARE SCANNER
        // ==========================================
        // By running this FIRST, we guarantee that fragmented malware (even 1-byte packets)
        // is caught by the state machine, regardless of what protocol it's using.
        std::vector<std::string> alerts = scanner.search(payload, payload_length, ac_state);
        if (!alerts.empty()) {
            spdlog::warn("[THREAT ALERT !!!] Signature Match Detected!");
            for (const auto& alert : alerts) {
                spdlog::warn("      -> {}", alert);
            }
            is_malicious = true;
        }

        // ==========================================
        // 2. PROTOCOL IDENTIFICATION (Safe Bounds Checking)
        // ==========================================
        // Zero-copy window into the payload for protocol identification
        std::string_view data(reinterpret_cast<const char*>(payload), payload_length);

        // Traffic Routing: Send payload to correct L7 Decoder
        // 1. Is this HTTP? (Starts with GET, POST, or HTTP)
        if (l7_proto == 1 || data.substr(0, 4) == "GET " || data.substr(0, 5) == "POST " || data.substr(0, 5) == "HTTP/") {
            l7_proto = 1; //storing it also
            parse_http(payload, payload_length, ac_state);
        } 
        // 2. Is this TLS? (Byte 0 is 0x16 for Handshake, Byte 5 is 0x01 for Client Hello)
        else if (payload_length >= 6 && payload[0] == 0x16 && payload[5] == 0x01) {
            std::string sni_domain = SniExtractor::extract_sni(payload, payload_length);
            if (!sni_domain.empty()) {
                spdlog::info("[DPI] --- TLS Connection Detected ---");
                spdlog::info("    [Extracted SNI] {}", sni_domain);
            }
        } 
        // 3. Unknown Protocol
        else {
            spdlog::debug("[DPI] Unknown L7 Protocol. Dumping raw bytes:");
            // print_hex_dump(payload, payload_length);
        }

        return is_malicious;
    }

    bool DpiEngine::parse_http(const uint8_t* payload, uint32_t payload_length) {
        // ZERO-COPY MAGIC: string_view
        // It provides string manipulation functions (like .find) without copying the data!
        std::string_view data(reinterpret_cast<const char*>(payload), payload_length);

        // Is this actually an HTTP GET or POST request?
        bool is_request = (data.substr(0, 4) == "GET " || data.substr(0, 5) == "POST ");
        bool is_response = (data.substr(0, 5) == "HTTP/");

        if (!is_request && !is_response) return false;

        if (is_request) {
            spdlog::info("[DPI] --- HTTP Request Detected ---");

            // Extract the Host (e.g., Host: www.example.com\r\n)
            size_t host_pos = data.find("Host: ");
            if (host_pos != std::string_view::npos) {
                size_t end_pos = data.find("\r\n", host_pos);
                if (end_pos != std::string_view::npos) {
                    // Shift pointer past "Host: " (6 characters) and calculate the length of the domain
                    std::string_view host = data.substr(host_pos + 6, end_pos - (host_pos + 6));
                    spdlog::info("    [Extracted Host] {}", host);
                }
            }

            // Extract the User-Agent (Browser & OS Fingerprint)
            size_t ua_pos = data.find("User-Agent: ");
            if (ua_pos != std::string_view::npos) {
                size_t end_pos = data.find("\r\n", ua_pos);
                if (end_pos != std::string_view::npos) {
                    std::string_view ua = data.substr(ua_pos + 12, end_pos - (ua_pos + 12));
                    spdlog::info("    [Extracted User-Agent] {}", ua);
                }
            }

            return true;
        }

        if (is_response) {
            spdlog::info("[DPI] --- HTTP Response Detected ---");
            return true; 
        }

        return false;
    }

    void DpiEngine::print_hex_dump(const uint8_t* payload, uint32_t payload_length) {
        // Limit the dump to the first 32 bytes to avoid flooding the terminal
        uint32_t print_len = (payload_length < 32) ? payload_length : 32;
        
        std::ostringstream oss;
        oss << "[Hex] ";
        for (uint32_t i = 0; i < print_len; ++i) {
           oss << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i] << " ";
        }
        
        oss << "  [ASCII] ";
        for (uint32_t i = 0; i < print_len; ++i) {
            char c = payload[i];
            // Only print printable ASCII characters; otherwise print a dot
            if (c >= 32 && c <= 126) {
                oss << c;
            } else {
                oss << '.';
            }
        }

        spdlog::debug(oss.str());
    }
}