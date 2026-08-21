cmake_minimum_required(VERSION 3.15)
project(NetHex VERSION 1.0.0 LANGUAGES CXX)

# enforce C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------

# find the xxHash header and library
find_path(XXHASH_INCLUDE_DIR xxhash.h)
find_library(XXHASH_LIBRARY xxhash)

if(NOT XXHASH_INCLUDE_DIR OR NOT XXHASH_LIBRARY)
    message(FATAL_ERROR "xxHash library not found! Please install libxxhash-dev.")
endif()

# Find native OS Threading Library
find_package(Threads REQUIRED)

# ------------------------------------------------------------------------
# CORE LIBRARY (nethex_core)
# ------------------------------------------------------------------------

include(FetchContent)
FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.12.0 # Or the latest stable version
)
FetchContent_MakeAvailable(spdlog)

# static lib for core engine
add_library(nethex_core STATIC 
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/connection_tracker.cpp
    src/dpi_engine.cpp
    src/sni_extractor.cpp
    src/pattern_matcher.cpp
    src/rule_manager.cpp
) 

# Specify where the headers live
target_include_directories(nethex_core PUBLIC include)

# Compiler flags ONLY to core target
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nethex_core PRIVATE -Wall -Wextra -Werror -Wpedantic -O3)
elseif(MSVC)
    target_compile_options(nethex_core PRIVATE /W4 /WX /O2)
endif()

# Link xxHash to our core library
target_link_libraries(nethex_core PUBLIC ${XXHASH_LIBRARY} spdlog::spdlog)

# ------------------------------------------------------------------------
# MAIN EXECUTABLE (nethex)
# ------------------------------------------------------------------------

# main executable
add_executable(nethex src/main.cpp)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nethex PRIVATE -Wall -Wextra -Werror -Wpedantic -O3)
elseif(MSVC)
    target_compile_options(nethex PRIVATE /W4 /WX /O2)
endif()

# Link the core library AND the newly found Threading library
target_link_libraries(nethex PRIVATE nethex_core Threads::Threads)

# Link the Windows Socket library if compiling on Windows
if(WIN32)
    target_link_libraries(nethex PRIVATE ws2_32)
endif()