#include <netinet/tcp.h>
#include <chrono>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "heuristic_engine.h"

HeuristicEngine::HeuristicEngine(Config& config, Logger* logger)
    : logger(logger), packetThreshold(config.heuristicPacketThreshold), timeWindow(std::chrono::seconds(config.heuristicTimeWindowSeconds))
{}

bool HeuristicEngine::analyzePacket(const Packet& packet, const uint8_t* rawData, size_t dataLen)
{
    bool suspicious = false;

    if (packet.protocol == "TCP")
    {
        if (checkPacketRateTCP(packet)) suspicious = true;
        if (checkTcpFlags(packet, rawData, dataLen)) suspicious = true;
        if (checkEmptyTcpPacket(packet, rawData, dataLen)) suspicious = true;
    }
    else if (packet.protocol == "UDP")
    {
        if (checkPacketRateUDP(packet)) suspicious = true;
        if (checkEmptyUdpPacket(packet, rawData, dataLen)) suspicious = true;
        if (checkUdpPacketSize(dataLen)) suspicious = true;
    }
    if (packet.protocol == "ICMP") {
        if (checkPacketRateICMP(packet)) suspicious = true;
        if (checkIcmpAnomalies(packet, rawData, dataLen)) suspicious = true;
    }

    if (checkPortAnomalies(packet)) suspicious = true;

    if (checkPacketSizeAnomaly(dataLen)) suspicious = true;

    if (packet.protocol == "UDP")
    {
        if (checkUdpPortAnomalies(packet)) suspicious = true;
    }

    return suspicious;
}

bool HeuristicEngine::checkPacketRateTCP(const Packet& packet)
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

bool HeuristicEngine::checkPacketRateUDP(const Packet& packet)
{
    using clock = std::chrono::steady_clock;
    auto now = clock::now();

    auto& stats = ipStatsUDP[packet.srcIP];
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
                logger->log("Heuristic alert: High UDP packet rate from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
            stats.packetCount = 0;
            return true;
        }
    }
    return false;
}

bool HeuristicEngine::checkEmptyUdpPacket(const Packet& packet, const uint8_t* rawData, size_t dataLen)
{
    if (packet.protocol != "UDP")
        return false;

    if (dataLen < sizeof(ether_header) + sizeof(ip) + sizeof(udphdr))
        return false;

    const ip* iphdr = (const ip*)(rawData + sizeof(ether_header));
    size_t ipHeaderLen = iphdr->ip_hl * 4;

    if (dataLen < sizeof(ether_header) + ipHeaderLen + sizeof(udphdr))
        return false;

    const udphdr* udph = (const udphdr*)(rawData + sizeof(ether_header) + ipHeaderLen);

    size_t udpPayloadLen = ntohs(udph->len) - sizeof(udphdr);

    if (udpPayloadLen == 0)
    {
        if (logger)
            logger->log("Heuristic alert: Empty UDP packet from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    return false;
}

bool HeuristicEngine::checkUdpPacketSize(size_t dataLen)
{
    // UDP заголовок — 8 байт, минимальный IP заголовок 20 байт, Ethernet 14 байт
    // Обычно payload UDP > 8 байт, слишком маленькие и слишком большие — подозрительно
    const size_t minSize = sizeof(ether_header) + sizeof(ip) + sizeof(udphdr) + 8;  // 8 — минимальный полезный размер
    const size_t maxSize = 576; // Часто используют max UDP packet size ~576 байт (можно изменить)

    if (dataLen < minSize)
    {
        if (logger)
            logger->log("Heuristic alert: Very small UDP packet size: " + std::to_string(dataLen), "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    if (dataLen > maxSize)
    {
        if (logger)
            logger->log("Heuristic alert: Very large UDP packet size: " + std::to_string(dataLen), "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    return false;
}

bool HeuristicEngine::checkUdpPortAnomalies(const Packet& packet)
{
    // Порты вне диапазона 1-65535
    if (packet.srcPort < 0 || packet.srcPort > 65535)
    {
        if (logger)
            logger->log("Heuristic alert: Invalid UDP source port " + std::to_string(packet.srcPort) + " from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }
    if (packet.dstPort < 0 || packet.dstPort > 65535)
    {
        if (logger)
            logger->log("Heuristic alert: Invalid UDP destination port " + std::to_string(packet.dstPort) + " from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }

    // Много трафика на системные порты (например, 0-1023) без явной причины подозрительно
    if ((packet.srcPort > 0 && packet.srcPort < 1024) || (packet.dstPort > 0 && packet.dstPort < 1024))
    {
        if (logger)
            logger->log("Heuristic alert: UDP traffic on system port from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
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

bool HeuristicEngine::checkPacketRateICMP(const Packet& packet)
{
    using clock = std::chrono::steady_clock;
    auto now = clock::now();

    auto& stats = ipStats[packet.srcIP];  // Общая статистика (используем ту же map)
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
                logger->log("Heuristic alert: High ICMP packet rate from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
            stats.packetCount = 0;
            return true;
        }
    }
    return false;
}

bool HeuristicEngine::checkIcmpAnomalies(const Packet& packet, const uint8_t* rawData, size_t dataLen)
{
    if (packet.protocol != "ICMP")
        return false;

    if (dataLen < sizeof(ether_header) + sizeof(ip) + 4) // Минимум для ICMP-заголовка
        return false;

    const ip* iphdr = (const ip*)(rawData + sizeof(ether_header));
    size_t ipHeaderLen = iphdr->ip_hl * 4;

    const uint8_t* icmpData = rawData + sizeof(ether_header) + ipHeaderLen;
    uint8_t type = icmpData[0];
    uint8_t code = icmpData[1];

    // Пример аномалий:
    // - Частые эхо-запросы
    // - Неизвестные типы (>18 по IANA)
    if (type == 8) // Echo Request (ping)
    {
        if (logger)
            logger->log("Heuristic alert: ICMP Echo Request from IP " + packet.srcIP, "heuristic_engine", LogLevel::INFO);
    }
    else if (type > 18)
    {
        if (logger)
            logger->log("Heuristic alert: Unknown ICMP type " + std::to_string(type) + " from IP " + packet.srcIP, "heuristic_engine", LogLevel::WARNING);
        return true;
    }

    return false;
}
