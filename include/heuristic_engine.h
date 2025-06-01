#pragma once

#include <string>
#include <unordered_map>
#include <chrono>

#include "packet.h"
#include "logger.h"

class HeuristicEngine
{
public:
    HeuristicEngine(Logger* logger = nullptr);

    // Возвращает true, если обнаружена подозрительная активность
    bool analyzePacket(const Packet& packet, const uint8_t* rawData, size_t dataLen);

private:
    Logger* logger;

    struct IpStats
    {
        int packetCount = 0;
        std::chrono::steady_clock::time_point firstPacketTime;
    };

    std::unordered_map<std::string, IpStats> ipStats;
    const int packetThreshold = 100;       // Порог пакетов
    const std::chrono::seconds timeWindow = std::chrono::seconds(10); // Временной интервал

    bool checkPacketRate(const Packet& packet);
    bool checkTcpFlags(const Packet& packet, const uint8_t* rawData, size_t dataLen);
    bool checkPortAnomalies(const Packet& packet);
    bool checkEmptyTcpPacket(const Packet& packet, const uint8_t* rawData, size_t dataLen);
    bool checkPacketSizeAnomaly(size_t dataLen);
};
