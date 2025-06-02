#pragma once

#include <fstream>
#include <mutex>
#include <string>

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
    Logger(const std::string& filename = "logs/hybridIDS.log");
    ~Logger();

    virtual void log(const std::string& message, const std::string& module = "general", LogLevel level = LogLevel::INFO);
    void setLogLevel(LogLevel level);
    static std::string levelToString(LogLevel level);

private:
    std::ofstream logFile;
    std::mutex logMutex;
    LogLevel currentLevel = LogLevel::INFO;

    std::string getTimestamp() const;
};
