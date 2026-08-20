#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace NetHex {

class Logger {
public:
    static void init() {
        // Create an async queue with 8192 slots
        spdlog::init_thread_pool(8192, 1);
        
        // Create a colorized console sink
        auto stdout_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        
        // Create the async logger
        auto logger = std::make_shared<spdlog::async_logger>(
            "NetHex", 
            stdout_sink, 
            spdlog::thread_pool(), 
            spdlog::async_overflow_policy::block
        );

        // Set a custom pattern: [Time] [ThreadID] [Level] Message
        logger->set_pattern("[%T.%e] [%t] [%^%l%$] %v");
        
        // Register it as the default global logger
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::info);
    }
};

}