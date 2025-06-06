#pragma once

#include <string>
#include "logger.h"

struct Config {
    std::string interface;
    LogLevel logLevel = LogLevel::INFO;
    int alertCooldown = 5;
    int heuristicPacketThreshold = 100;
    int heuristicTimeWindowSeconds = 10;
};

bool loadConfig(const std::string& filename, Config& config);
