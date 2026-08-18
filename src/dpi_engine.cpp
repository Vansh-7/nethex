#include "dpi_engine.h"
#include "sni_extractor.h"

namespace NetHex {

    // Initialize the Engine and Load Signatures
    DpiEngine::DpiEngine() {
        std::cout << "[DPI] Initializing Aho-Corasick Threat Scanner..." << std::endl;
        
        // Load some classic malicious signatures
        scanner.add_pattern("etc/passwd");     // Linux Directory Traversal
        scanner.add_pattern("cmd.exe");        // Windows Command Injection
        scanner.add_pattern("UNION SELECT");   // SQL Injection
        scanner.add_pattern("password=");      // Plaintext credential sniffing
        
        // Compile the Failure Links!
        scanner.build_machine();
        std::cout << "[DPI] Threat Scanner Online. Signatures loaded." << std::endl;
    }

    void DpiEngine::inspect_payload(const uint8_t* payload, uint32_t payload_length, const FiveTuple& tuple) {
        (void)tuple;
        // Safety Check: TCP packets often have 0 payload (e.g., pure ACK or SYN packets)
        if (payload_length < 5 || payload == nullptr) return;

        // Zero-copy window into the payload for protocol identification
        std::string_view data(reinterpret_cast<const char*>(payload), payload_length);

        // Traffic Routing: Send payload to correct L7 Decoder
        // 1. Is this HTTP? (Starts with GET, POST, or HTTP)
        if (data.substr(0, 4) == "GET " || data.substr(0, 5) == "POST " || data.substr(0, 5) == "HTTP/") {
            parse_http(payload, payload_length);
        } 
        // 2. Is this TLS? (Byte 0 is 0x16 for Handshake, Byte 5 is 0x01 for Client Hello)
        else if (payload[0] == 0x16 && payload[5] == 0x01) {
            std::string sni_domain = SniExtractor::extract_sni(payload, payload_length);
            if (!sni_domain.empty()) {
                std::cout << "\n[DPI] --- TLS Connection Detected ---" << std::endl;
                std::cout << "    [Extracted SNI] " << sni_domain << std::endl;
            }
        } 
        // 3. Unknown Protocol
        else {
            // std::cout << "\n[DPI] Unknown L7 Protocol. Dumping raw bytes:" << std::endl;
            // print_hex_dump(payload, payload_length);
        }
    }

    void DpiEngine::parse_http(const uint8_t* payload, uint32_t payload_length) {
        // ---- ADD THIS DEBUG BLOCK ----
        std::cout << "\n[DEBUG] Port 80 Payload Received. Size: " << payload_length << " bytes" << std::endl;
        print_hex_dump(payload, payload_length);
        // ------------------------------

        // ZERO-COPY MAGIC: string_view
        // It provides string manipulation functions (like .find) without copying the data!
        std::string_view data(reinterpret_cast<const char*>(payload), payload_length);

        // Is this actually an HTTP GET or POST request?
        if (data.substr(0, 4) != "GET " && data.substr(0, 5) != "POST ") {
            return; 
        }

        std::cout << "\n[DPI] --- HTTP Request Detected ---" << std::endl;

        // Extract the Host (e.g., Host: www.example.com\r\n)
        size_t host_pos = data.find("Host: ");
        if (host_pos != std::string_view::npos) {
            size_t end_pos = data.find("\r\n", host_pos);
            if (end_pos != std::string_view::npos) {
                // Shift pointer past "Host: " (6 characters) and calculate the length of the domain
                std::string_view host = data.substr(host_pos + 6, end_pos - (host_pos + 6));
                std::cout << "    [Extracted Host] " << host << std::endl;
            }
        }

        // Extract the User-Agent (Browser & OS Fingerprint)
        size_t ua_pos = data.find("User-Agent: ");
        if (ua_pos != std::string_view::npos) {
            size_t end_pos = data.find("\r\n", ua_pos);
            if (end_pos != std::string_view::npos) {
                std::string_view ua = data.substr(ua_pos + 12, end_pos - (ua_pos + 12));
                std::cout << "    [Extracted User-Agent] " << ua << std::endl;
            }
        }

        // TRIGGER THE MALWARE SCANNER!
        // We pass the raw payload pointer directly into our O(N) state machine
        std::vector<std::string> alerts = scanner.search(payload, payload_length);
        
        for (const auto& alert : alerts) {
            std::cout << "    [!!! THREAT ALERT !!!] Signature Match: " << alert << std::endl;
        }
    }

    void DpiEngine::print_hex_dump(const uint8_t* payload, uint32_t payload_length) {
        // Limit the dump to the first 32 bytes to avoid flooding the terminal
        uint32_t print_len = (payload_length < 32) ? payload_length : 32;
        
        std::cout << "    [Hex] ";
        for (uint32_t i = 0; i < print_len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i] << " ";
        }
        
        std::cout << "  [ASCII] ";
        for (uint32_t i = 0; i < print_len; ++i) {
            char c = payload[i];
            // Only print printable ASCII characters; otherwise print a dot
            if (c >= 32 && c <= 126) {
                std::cout << c;
            } else {
                std::cout << '.';
            }
        }
        std::cout << std::dec << std::endl; // Reset back to standard decimal printing
    }
}