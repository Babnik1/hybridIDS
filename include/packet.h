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

    std::string summary() const;

    //TODO: Валидацию, сеттеры и геттеры
};