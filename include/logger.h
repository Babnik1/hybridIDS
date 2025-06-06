#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include <chrono>
#include <unordered_map>

enum class LogLevel
{
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR
};

class Logger
{
public:
    Logger(std::chrono::seconds floodInterval = std::chrono::seconds(5), const std::string& filename = "logs/hybridIDS.log");
    ~Logger();

    virtual void log(const std::string& message, const std::string& module = "general", LogLevel level = LogLevel::INFO);
    void setLogLevel(LogLevel level);
    static std::string levelToString(LogLevel level);

private:
    std::ofstream logFile;
    std::mutex logMutex;
    LogLevel currentLevel = LogLevel::INFO;

    std::string lastMessage;
    std::chrono::steady_clock::time_point lastLogTime;
    std::chrono::seconds floodInterval;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> floodMap;

    std::string getTimestamp() const;
};
