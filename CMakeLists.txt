cmake_minimum_required(VERSION 3.15)
project(NetHex VERSION 1.0.0 LANGUAGES CXX)

# Enforce C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags for production rigor
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wpedantic -O3") # Linux
elseif(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX /O2") # Windows
endif()

# Define the main executable
add_executable(nethex
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

# Specify where the headers live
target_include_directories(nethex PRIVATE include)

# Link the Windows Socket library if compiling on Windows
if(WIN32)
    target_link_libraries(nethex ws2_32)
endif()