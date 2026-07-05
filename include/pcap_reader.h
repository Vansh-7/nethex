#pragma once

#include <string>
#include <fstream>
#include <vector>
#include <cstdint>
#include <memory>

namespace NetHex {

    // ------------------------------------------------------------------------
    // PCAP FILE FORMAT STRUCTURES
    // ------------------------------------------------------------------------
    // A PCAP file has a 24-byte global header at the start, followed by 
    // individual packets. Each packet has a 16-byte header, then the raw data.
    #pragma pack(push, 1)
    struct PcapGlobalHeader {
        uint32_t magic_number;  // Identifies the file as a PCAP
        uint16_t version_major; // Major Version
        uint16_t version_minor; // Minor Version
        int32_t  thiszone;      // GMT to local correction
        uint32_t sigfigs;       // Accuracy of timestamps
        uint32_t snaplen;       // Max length of captured packets
        uint32_t network;       // Data link type (e.g., 1 = Ethernet)
    };

    struct PcapPacketHeader {
        uint32_t ts_sec;        // Timestamp seconds
        uint32_t ts_usec;       // Timestamp microseconds
        uint32_t incl_len;      // Captured length of the packet
        uint32_t orig_len;      // Actual length of the packet on the wire
    };
    #pragma pack(pop)

    // ------------------------------------------------------------------------
    // THE ABSTRACTION INTERFACE
    // ------------------------------------------------------------------------
    class IPacketReader {
    public:
        virtual ~IPacketReader() = default;
        virtual bool open() = 0;
        virtual void close() = 0;
        
        // We pass references to a pointer to avoid copying memory! 
        // This is crucial for high performance.
        virtual bool read_next_packet(const uint8_t*& packet_data, uint32_t& packet_length) = 0;
    };

    // ------------------------------------------------------------------------
    // NATIVE OFFLINE PCAP READER
    // ------------------------------------------------------------------------
    class PcapFileReader : public IPacketReader {
    private:
        std::string file_path;
        std::ifstream file_stream;
        std::vector<uint8_t> packet_buffer; // Pre-allocated to prevent malloc overhead

    public:
        explicit PcapFileReader(const std::string& path);
        ~PcapFileReader() override;

        bool open() override;
        void close() override;
        bool read_next_packet(const uint8_t*& packet_data, uint32_t& packet_length) override;
    };

} 