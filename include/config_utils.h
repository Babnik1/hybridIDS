#pragma once

#include <string>
#include "logger.h"

struct Config {
    std::string interface;
    LogLevel logLevel = LogLevel::INFO;
};

bool loadConfig(const std::string& filename, Config& config);
