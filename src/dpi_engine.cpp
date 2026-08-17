#include "dpi_engine.h"
#include "sni_extractor.h"

namespace NetHex {

    void DpiEngine::inspect_payload(const uint8_t* payload, uint32_t payload_length, const FiveTuple& tuple){
        // 1. Safety Check: TCP packets often have 0 payload (e.g., pure ACK or SYN packets)
        if (payload_length == 0 || payload == nullptr) return; 

        // Traffic Routing: Send payload to correct L7 Decoder
        if(tuple.dest_port == 80) {
            parse_http(payload, payload_length);
        } 
        else if (tuple.dest_port == 443 || tuple.src_port == 443) {
            // Check if traffic is heading TO or coming FROM a secure web server
            // Route HTTPS traffic through our SNI Extractor
            std::string sni_domain = SniExtractor::extract_sni(payload, payload_length);
            if (!sni_domain.empty()) {
                std::cout << "\n[DPI] --- TLS Connection Detected ---" << std::endl;
                std::cout << "    [Extracted SNI] " << sni_domain << std::endl;
            }
        } 
        else {
            // For unknown application traffic, safely dump the raw hex
            std::cout << "\n[DPI] Unknown L7 Protocol. Dumping raw bytes:" << std::endl;
            print_hex_dump(payload, payload_length);
        }
    }

    void DpiEngine::parse_http(const uint8_t* payload, uint32_t payload_length) {
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