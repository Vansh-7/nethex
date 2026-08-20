#pragma once

#include <cstdint>
#include <spdlog/spdlog.h> // Async logging
#include <thread>   // Added for cross-platform thread identification

// OS-specific network includes
#if defined(_WIN32) || defined(_WIN64)
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h> // Added: Required for Windows Thread Affinity
#else   
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <pthread.h> // Added: Required for POSIX thread manipulation
    #ifdef __APPLE__
        #include <mach/mach.h>
        #include <mach/thread_policy.h> // Added: Required for macOS thread hints
    #endif
#endif

namespace NetHex {
    // Utility for Endian swapping (Network byte order to Host byte order)
    inline uint16_t ntoh16(uint16_t net_16) { return ntohs(net_16); }
    inline uint32_t ntoh32(uint32_t net_32) { return ntohl(net_32); }
    inline uint16_t hton16(uint16_t host_16) { return htons(host_16); }
    inline uint32_t hton32(uint32_t host_32) { return htonl(host_32); }

    // CPU Pinning
    inline void pin_thread_to_core(int core_id) {
#if defined(_WIN32) || defined(_WIN64)
        // Windows API for Thread Affinity
        DWORD_PTR mask = (DWORD_PTR)1 << core_id;
        if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) {
            spdlog::warn("Windows CPU pinning failed for core {}.", core_id);
        }
#elif defined(__linux__)
        // Linux POSIX API for Strict Thread Affinity
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
            spdlog::warn("Linux CPU pinning failed for core {}.", core_id);
        }
#elif defined(__APPLE__)
        // macOS does not allow strict hardware pinning. 
        // We use Mach thread policies to give the OS a "hint" to share L2 cache.
        thread_affinity_policy_data_t policy = { core_id };
        thread_port_t mach_thread = pthread_mach_thread_np(pthread_self());
        thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1);
#else
        spdlog::warn("CPU pinning not supported on this OS. Running unpinned.");
#endif
    }
}