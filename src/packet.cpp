#include "packet.h"

#include <sstream>

std::string Packet::summary() const
{
    std::ostringstream oss;
    oss << "Протокол: " << protocol
        << ", " << srcIP << ":" << srcPort
        << " → " << dstIP << ":" << dstPort;
    return oss.str();
}