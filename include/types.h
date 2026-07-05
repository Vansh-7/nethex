#pragma once

#include <cstdint>

namespace NetHex {

    // ------------------------------------------------------------------------
    // PACKING ENFORCEMENT
    // ------------------------------------------------------------------------
    // Force the compiler to pack these structs exactly byte-for-byte (1-byte alignment).
    // This prevents the compiler from adding invisible padding, ensuring our 
    // structs perfectly match the raw bytes coming off the network wire.
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
        
        // Data offset (4 bits), Reserved (3 bits), Flags (9 bits)
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
}