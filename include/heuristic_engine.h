#pragma once

#include <string>
#include <unordered_map>
#include <chrono>

#include "packet.h"
#include "logger.h"
#include "config_utils.h"

class HeuristicEngine
{
public:
    HeuristicEngine(Config& config, Logger* logger = nullptr);

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
    std::unordered_map<std::string, IpStats> ipStatsUDP;

    const int packetThreshold;       // Порог пакетов
    const std::chrono::seconds timeWindow; // Временной интервал

    bool checkPacketRateTCP(const Packet& packet);
    bool checkPacketRateUDP(const Packet& packet);

    bool checkTcpFlags(const Packet& packet, const uint8_t* rawData, size_t dataLen);
    bool checkPortAnomalies(const Packet& packet);
    bool checkEmptyTcpPacket(const Packet& packet, const uint8_t* rawData, size_t dataLen);
    bool checkPacketSizeAnomaly(size_t dataLen);

    bool checkEmptyUdpPacket(const Packet& packet, const uint8_t* rawData, size_t dataLen);
    bool checkUdpPacketSize(size_t dataLen);
    bool checkUdpPortAnomalies(const Packet& packet);

    bool checkPacketRateICMP(const Packet& packet);
    bool checkIcmpAnomalies(const Packet& packet, const uint8_t* rawData, size_t dataLen);

};
