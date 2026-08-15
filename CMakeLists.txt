cmake_minimum_required(VERSION 3.15)
project(NetHex VERSION 1.0.0 LANGUAGES CXX)

# enforce C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# find necessary dependencies (PCAP header and library)
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "PCAP library not found! Please install libpcap-dev.")
endif()

# static lib for core engine
add_library(nethex_core STATIC 
    src/pcap_reader.cpp
    src/packet_parser.cpp
) 

# Specify where the headers live
target_include_directories(nethex_core PUBLIC include)

# Compiler flags ONLY to core target
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nethex_core PRIVATE -Wall -Wextra -Werror -Wpedantic -O3)
elseif(MSVC)
    target_compile_options(nethex_core PRIVATE /W4 /WX /O2)
endif()

# Link libpcap to our core library
target_link_libraries(nethex_core PUBLIC ${PCAP_LIBRARY})
target_include_directories(nethex_core PUBLIC ${PCAP_INCLUDE_DIRS})

# Link the Windows Socket library if compiling on Windows
if(WIN32)
    target_link_libraries(nethex ws2_32)
endif()

# main executable and link the core library
add_executable(nethex src/main.cpp)
target_link_libraries(nethex PRIVATE nethex_core)