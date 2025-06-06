#pragma once

#include <string>
#include <cstdint>


class Packet
{
    public:
    std::string srcIP;
    std::string dstIP;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    std::string protocol;

    uint8_t icmpType = 0;
    uint8_t icmpCode = 0;

    std::string summary() const;
};