#pragma once

#include <cstdint>
#include <vector>

namespace NetHex {

    // ------------------------------------------------------------------------
    // PACKING ENFORCEMENT
    // ------------------------------------------------------------------------
    // force the compiler to pack these structs exactly byte-for-byte (1-byte alignment)
    // prevents the compiler from adding invisible padding
    #pragma pack(push, 1)

    // ------------------------------------------------------------------------
    // LAYER 2: DATA LINK (Ethernet II)
    // ------------------------------------------------------------------------
    struct EthernetHeader {
        uint8_t  dest_mac[6];    // Destination MAC Address
        uint8_t  src_mac[6];     // Source MAC Address
        uint16_t ethertype;      // Protocol encapsulated in the payload (e.g., IPv4 = 0x0800)
    };

    // ------------------------------------------------------------------------
    // LAYER 3: NETWORK (IPv4)
    // ------------------------------------------------------------------------
    struct IPv4Header {
        // Note: Bitfields are used here because Version and IHL share a single byte.
        // The order depends on the endianness of the compiler, but standard network 
        // processing usually handles this via bitwise operations in production. 
        // We will define it as a single byte to avoid cross-platform bitfield layout issues.
        uint8_t  version_ihl;    // Version (4 bits) + Internet Header Length (4 bits)
        uint8_t  tos;            // Type of Service / Differentiated Services
        uint16_t total_length;   // Total length of the IP packet (header + payload)
        uint16_t identification; // Identification for fragmentation
        uint16_t flags_offset;   // Flags (3 bits) + Fragment Offset (13 bits)
        uint8_t  ttl;            // Time to Live
        uint8_t  protocol;       // Next level protocol (e.g., TCP = 6, UDP = 17)
        uint16_t checksum;       // Header Checksum
        uint32_t src_ip;         // Source IP Address
        uint32_t dest_ip;        // Destination IP Address
    };

    // ------------------------------------------------------------------------
    // LAYER 4: TRANSPORT (TCP)
    // ------------------------------------------------------------------------
    struct TCPHeader {
        uint16_t src_port;       // Source Port
        uint16_t dest_port;      // Destination Port
        uint32_t seq_num;        // Sequence Number
        uint32_t ack_num;        // Acknowledgment Number
        
        // Data offset (4 bits), Reserved (6 bits), Flags (6 bits)
        // Handled as a 16-bit integer to avoid bitfield layout issues.
        uint16_t offset_reserved_flags; 
        
        uint16_t window_size;    // Window Size for flow control
        uint16_t checksum;       // Checksum
        uint16_t urgent_ptr;     // Urgent Pointer
    };

    // ------------------------------------------------------------------------
    // LAYER 4: TRANSPORT (UDP)
    // ------------------------------------------------------------------------
    struct UDPHeader {
        uint16_t src_port;       // Source Port
        uint16_t dest_port;      // Destination Port
        uint16_t length;         // Length of UDP header and payload
        uint16_t checksum;       // Checksum
    };

    // Restore the default compiler packing behavior so we don't mess up 
    // the rest of our standard C++ code.
    #pragma pack(pop)

    // ------------------------------------------------------------------------
    // INTER-THREAD COMMUNICATION WRAPPERS
    // ------------------------------------------------------------------------
    // This is the "Envelope" passed across the Lock-Free Queue
    struct ParsedPacket {
        // The 5-Tuple (Crucial for routing and connection tracking)
        uint32_t src_ip{0};
        uint32_t dest_ip{0};
        uint16_t src_port{0};
        uint16_t dest_port{0};
        uint8_t  protocol{0}; // e.g., 6 for TCP, 17 for UDP
        uint8_t  tcp_flags{0};

        // The Application Layer (L7) Data
        // ZERO-COPY
        uint32_t pool_slot_id; 
        const uint8_t* payload_ptr;
        uint32_t payload_length;
        
        static constexpr uint32_t NO_PAYLOAD = 0xFFFFFFFF;

        // Constructors default the slot ID to 0xFFFFFFFF (meaning "No Payload")
        ParsedPacket() : src_ip(0), dest_ip(0), src_port(0), dest_port(0), 
                         protocol(0), tcp_flags(0), pool_slot_id(NO_PAYLOAD), 
                         payload_ptr(nullptr), payload_length(0) {}

        ParsedPacket(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t proto)
            : src_ip(sip), dest_ip(dip), src_port(sport), dest_port(dport), 
              protocol(proto), tcp_flags(0), pool_slot_id(NO_PAYLOAD), 
              payload_ptr(nullptr), payload_length(0) {}
    };
}