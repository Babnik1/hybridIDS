#pragma once

#include <functional>
#include <string>
#include <thread>
#include <pcap.h>

#include "packet.h"
#include "logger.h"

class Sniffer
{
public:
    using PacketHandler = std::function<void(const Packet&)>;

    Sniffer(const std::string& interfaceName, Logger* logger = nullptr);
    ~Sniffer();

    void setPacketHandler(PacketHandler handler);

    void start();
    void stop();

private:
    std::string interface;
    pcap_t* handle = nullptr;
    bool running = false;
    PacketHandler packetHandler;
    std::thread captureThread;

    Logger* logger;

    void captureLoop();
};
