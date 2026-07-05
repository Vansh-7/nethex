#pragma once

#include <cstdint>

// OS-specific network includes
#if defined(_WIN32) || defined(_WIN64)
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else   
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

namespace NetHex {
    // Utility for Endian swapping (Network byte order to Host byte order)
    inline uint16_t ntoh16(uint16_t net_16) { return ntohs(net_16); }
    inline uint32_t ntoh32(uint32_t net_32) { return ntohl(net_32); }
    inline uint16_t hton16(uint16_t host_16) { return htons(host_16); }
    inline uint32_t hton32(uint32_t host_32) { return htonl(host_32); }
}