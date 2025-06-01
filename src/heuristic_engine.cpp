#include <netinet/tcp.h>
#include <chrono>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip.h>

#include "heuristic_engine.h"

HeuristicEngine::HeuristicEngine(Config& config, Logger* logger)
    : logger(logger), packetThreshold(config.heuristicPacketThreshold), timeWindow(std::chrono::seconds(config.heuristicTimeWindowSeconds))
{}

bool HeuristicEngine::analyzePacket(const Packet& packet, const uint8_t* rawData, size_t dataLen)
{
    bool suspicious = false;

    if (checkPacketRate(packet)) suspicious = true;
    if (packet.protocol == "TCP")
    {
        if (checkTcpFlags(packet, rawData, dataLen)) suspicious = true;
        if (checkEmptyTcpPacket(packet, rawData, dataLen)) suspicious = true;
    }
    if (checkPortAnomalies(packet)) suspicious = true;
    if (checkPacketSizeAnomaly(dataLen)) suspicious = true;

    return suspicious;
}

bool HeuristicEngine::checkPacketRate(const Packet& packet)
{
    using clock = std::chrono::steady_clock;
    auto now = clock::now();

    auto& stats = ipStats[packet.srcIP];
    if (stats.packetCount == 0)
    {
        stats.firstPacketTime = now;
        stats.packetCount = 1;
        return false;
    }

    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - stats.firstPacketTime);
    if (duration > timeWindow)
    {
        stats.packetCount = 1;
        stats.firstPacketTime = now;
        return false;
    }
    else
    {
        stats.packetCount++;
        if (stats.packetCount > packetThreshold)
        {
            if (logger)
                logger->log("Heuristic alert: High packet rate from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
            stats.packetCount = 0;
            return true;
        }
    }
    return false;
}

bool HeuristicEngine::checkTcpFlags(const Packet& packet, const uint8_t* rawData, size_t dataLen)
{
    // Проверяем TCP флаги на аномалии
    // Данные rawData: ethernet + IP + TCP
    if (dataLen < sizeof(ether_header) + sizeof(ip) + sizeof(tcphdr))
        return false;

    const ip* iphdr = (const ip*)(rawData + sizeof(ether_header));
    size_t ipHeaderLen = iphdr->ip_hl * 4;

    if (dataLen < sizeof(ether_header) + ipHeaderLen + sizeof(tcphdr))
        return false;

    const tcphdr* tcph = (const tcphdr*)(rawData + sizeof(ether_header) + ipHeaderLen);

    uint8_t flags = ((uint8_t*)tcph)[13]; // th_flags — смещение 13 байт от начала tcphdr

    bool syn = flags & TH_SYN;
    bool fin = flags & TH_FIN;
    bool rst = flags & TH_RST;
    bool psh = flags & TH_PUSH;
    bool ack = flags & TH_ACK;
    bool urg = flags & TH_URG;

    // Несовместимые флаги: SYN+FIN, SYN+RST, FIN без ACK, URG без ACK и т.п.

    if ((syn && fin) || (syn && rst))
    {
        if (logger)
            logger->log("Heuristic alert: Suspicious TCP flags SYN+FIN or SYN+RST from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    if (fin && !ack)
    {
        if (logger)
            logger->log("Heuristic alert: FIN flag without ACK from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    if (urg && !ack)
    {
        if (logger)
            logger->log("Heuristic alert: URG flag without ACK from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }

    return false;
}

bool HeuristicEngine::checkPortAnomalies(const Packet& packet)
{
    // Порты вне диапазона 1-65535 или необычные порты (например, порты ниже 1024 при нестандартных протоколах)
    if (packet.srcPort < 0 || packet.srcPort > 65535)
    {
        if (logger)
            logger->log("Heuristic alert: Invalid source port " + std::to_string(packet.srcPort) + " from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    if (packet.dstPort < 0 || packet.dstPort > 65535)
    {
        if (logger)
            logger->log("Heuristic alert: Invalid destination port " + std::to_string(packet.dstPort) + " from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }

    // Например, подозрительно много трафика на очень высокие порты (49152-65535)
    if (packet.dstPort >= 49152 && packet.dstPort <= 65535)
    {
        if (logger)
            logger->log("Heuristic alert: Traffic to high port " + std::to_string(packet.dstPort) + " from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
    }

    return false;
}

bool HeuristicEngine::checkEmptyTcpPacket(const Packet& packet, const uint8_t* rawData, size_t dataLen)
{
    // Проверяем, что TCP пакет без полезных данных (например, длина TCP-сегмента == 0)
    if (packet.protocol != "TCP")
        return false;

    if (dataLen < sizeof(ether_header) + sizeof(ip))
        return false;

    const ip* iphdr = (const ip*)(rawData + sizeof(ether_header));
    size_t ipHeaderLen = iphdr->ip_hl * 4;
    if (dataLen < sizeof(ether_header) + ipHeaderLen + sizeof(tcphdr))
        return false;

    const tcphdr* tcph = (const tcphdr*)(rawData + sizeof(ether_header) + ipHeaderLen);
    size_t tcpHeaderLen = tcph->th_off * 4;

    size_t tcpPayloadLen = ntohs(iphdr->ip_len) - ipHeaderLen - tcpHeaderLen;
    if (tcpPayloadLen == 0)
    {
        if (logger)
            logger->log("Heuristic alert: Empty TCP packet from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    return false;
}

bool HeuristicEngine::checkPacketSizeAnomaly(size_t dataLen)
{
    // Маленькие (< 40 байт) или очень большие (>1500 байт) пакеты
    if (dataLen < 40)
    {
        if (logger)
            logger->log("Heuristic alert: Very small packet size: " + std::to_string(dataLen), "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    if (dataLen > 1500)
    {
        if (logger)
            logger->log("Heuristic alert: Very large packet size: " + std::to_string(dataLen), "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    return false;
}
