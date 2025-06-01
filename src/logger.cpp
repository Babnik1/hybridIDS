#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>

#include "logger.h"

using json = nlohmann::json;

Logger::Logger(const std::string& filename)
{
    logFile.open(filename, std::ios::app);
    if (!logFile)
    {
        std::cout << "Error opening log file: " << filename << std::endl;
    }
}

Logger::~Logger()
{
    if (logFile.is_open())
    {
        logFile.close();
    }
}

void Logger::setLogLevel(LogLevel level)
{
    currentLevel = level;
}

std::string Logger::levelToString(LogLevel level)
{
    switch (level)
    {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}


std::string Logger::getTimestamp() const
{
    auto now = std::chrono::system_clock::now();
    std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&nowTime, &tm);

    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

    return std::string(buffer);
}

void Logger::log(const std::string& message, const std::string& module, LogLevel level)
{
    if (level < currentLevel) return;

    std::lock_guard<std::mutex> lock(logMutex);
    std::string timestamp = getTimestamp();
    std::string fullMessage = "[" + timestamp + "][" + levelToString(level) + "][" + module + "] " + message;

    if (logFile.is_open())
    {
        logFile << fullMessage << std::endl;
    }

    std::cout << fullMessage << std::endl;
}
