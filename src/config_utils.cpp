#include "config_utils.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <algorithm>

using json = nlohmann::json;

static LogLevel parseLogLevel(const std::string& levelStr)
{
    std::string lvl = levelStr;
    std::transform(lvl.begin(), lvl.end(), lvl.begin(), ::tolower);

    if (lvl == "debug") return LogLevel::DEBUG;
    if (lvl == "info") return LogLevel::INFO;
    if (lvl == "warn" || lvl == "warning") return LogLevel::WARNING;
    if (lvl == "error") return LogLevel::ERROR;

    return LogLevel::INFO; // default
}

bool loadConfig(const std::string& fileName, Config& config)
{
    std::ifstream file(fileName);
    if (!file.is_open())
        return false;

    try
    {
        json j;
        file >> j;

        if (j.contains("interface") && j["interface"].is_string())
            config.interface = j["interface"].get<std::string>();
        else
            return false;

        if (j.contains("log_level") && j["log_level"].is_string())
            config.logLevel = parseLogLevel(j["log_level"].get<std::string>());
        else
            config.logLevel = LogLevel::INFO;

        if (j.contains("alert_cooldown") && j["alert_cooldown"].is_number_integer())
            config.alertCooldown = j["alert_cooldown"].get<int>();
        else
            config.alertCooldown = 10;
        if (j.contains("heuristicPacketThreshold") && j["heuristicPacketThreshold"].is_number_integer())
            config.heuristicPacketThreshold = j["heuristicPacketThreshold"].get<int>();
        else
            config.heuristicPacketThreshold = 100;
        if (j.contains("heuristicTimeWindowSeconds") && j["heuristicTimeWindowSeconds"].is_number_integer())
            config.heuristicTimeWindowSeconds = j["heuristicTimeWindowSeconds"].get<int>();
        else
            config.heuristicTimeWindowSeconds = 10;
        return true;
    }
    catch (...)
    {
        return false;
    }
}
