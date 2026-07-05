#include "platform.h"
#include "pcap_reader.h"
#include <iostream>

int main() {
    std::cout << "[NetHex] Engine initializing..." << std::endl;
    
    // Instantiate our reader using standard polymorphic design
    std::unique_ptr<NetHex::IPacketReader> reader = std::make_unique<NetHex::PcapFileReader>("sample.pcap");

    if (reader->open()) {
        const uint8_t* packet_data = nullptr;
        uint32_t packet_length = 0;
        uint32_t packet_count = 0;

        // THE CORE INGESTION LOOP
        // The loop just asks for the next packet.
        while (reader->read_next_packet(packet_data, packet_length)) {
            packet_count++;
        }

        std::cout << "[NetHex] Successfully ingested " << packet_count << " packets." << std::endl;
        reader->close();
    } else {
        std::cout << "[NetHex] Note: Please drop a 'sample.pcap' file into your working directory to test ingestion." << std::endl;
    }
    
    return 0;
}