#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <regex>

#include "logger.h"

std::string extractIP(const std::string& msg) {
    static std::regex ipRegex(R"((\d{1,3}\.){3}\d{1,3})");
    std::smatch match;
    if (std::regex_search(msg, match, ipRegex)) {
        return match.str(0);
    }
    return "";
}


Logger::Logger(std::chrono::seconds floodInterval, const std::string& filename)
    : floodInterval(floodInterval)
{
    logFile.open(filename, std::ios::app);
    if (!logFile)
    {
        std::cout << "Error opening log file: " << filename << std::endl;
    }
    lastLogTime = std::chrono::steady_clock::now() - floodInterval - std::chrono::seconds(1); // чтобы первое сообщение точно прошло
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

    std::string ip = extractIP(message);
    std::string key = levelToString(level) + "|" + ip;
    auto now = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(logMutex);
        if (!ip.empty() && floodMap.count(key) && now - floodMap[key] < floodInterval)
        {
            return; // подавляем спам
        }
        floodMap[key] = now;
    }

    std::string fullMessage = "[" + getTimestamp() + "][" + levelToString(level) + "][" + module + "] " + message;

    std::lock_guard<std::mutex> lock(logMutex); // новый лок для вывода

    if (logFile.is_open())
    {
        logFile << fullMessage << std::endl;
    }

    std::cout << fullMessage << std::endl;
}

