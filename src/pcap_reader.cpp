#include "pcap_reader.h"
#include <spdlog/spdlog.h>

namespace NetHex {

    PcapFileReader::PcapFileReader(const std::string& path) 
        : file_path(path), packet_buffer(65535) { 
        // 65535 (64KB) is the standard maximum size of a network packet.
        // We pre-allocate this vector ONCE, saving massive CPU cycles later.
    }

    PcapFileReader::~PcapFileReader() {
        close();
    }

    bool PcapFileReader::open() {
        // We MUST open the file in binary mode to read raw packet bytes
        file_stream.open(file_path, std::ios::binary);
        if (!file_stream.is_open()) {
            spdlog::error("[NetHex] Error: Could not open PCAP file: {}", file_path);
            return false;
        }

        // 1. Read the Global PCAP Header directly into our struct
        PcapGlobalHeader global_header;
        file_stream.read(reinterpret_cast<char*>(&global_header), sizeof(PcapGlobalHeader));

        // 2. Check explicitly if the read operation failed
        if (file_stream.fail()) {
            spdlog::error("[NetHex] Error: Failed to read PCAP global header.");
            return false;
        }

        // 3. Validate the Magic Number (0xa1b2c3d4 is standard microsecond resolution)
        if (global_header.magic_number != 0xa1b2c3d4 && global_header.magic_number != 0xa1b23c4d) {
            spdlog::error("[NetHex] Error: Invalid PCAP magic number.");
            return false;
        }

        spdlog::info("[NetHex] PCAP file opened successfully. Ready to ingest.");
        return true;
    }

    void PcapFileReader::close() {
        if (file_stream.is_open()) {
            file_stream.close();
        }
    }

    bool PcapFileReader::read_next_packet(const uint8_t*& packet_data, uint32_t& packet_length) {
        if (!file_stream.is_open() || file_stream.eof()) {
            return false;
        }

        PcapPacketHeader packet_header;
        
        // 1. Read the 16-byte packet header
        file_stream.read(reinterpret_cast<char*>(&packet_header), sizeof(PcapPacketHeader));

        if (!file_stream || packet_header.incl_len == 0) {
            return false; // Reached end of file
        }

        // Security Check: Ensure malformed packets don't overflow our buffer
        if (packet_header.incl_len > packet_buffer.size()) {
            packet_header.incl_len = packet_buffer.size();
        }

        // 2. Read the actual raw packet data directly into our pre-allocated buffer
        file_stream.read(reinterpret_cast<char*>(packet_buffer.data()), packet_header.incl_len);

        if (!file_stream) {
            return false;
        }

        // 3. Point the output variables to our buffer
        packet_data = packet_buffer.data();
        packet_length = packet_header.incl_len;

        return true;
    }

}