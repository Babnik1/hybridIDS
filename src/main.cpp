#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

#include "sniffer.h"
#include "rule_engine.h"
#include "nftables_control.h"
#include "logger.h"
#include "packet.h"
#include "config_utils.h"
#include "heuristic_engine.h"

std::string configPath = "config/config.json";

std::atomic<bool> running(true);
Logger* globalLogger = nullptr;

void signalHandler(int signum)
{
    if (globalLogger)
        globalLogger->log("Termination signal received (" + std::to_string(signum) + ")", "main", LogLevel::INFO);
    running = false;
}

int main()
{
    Config config;
    if (!loadConfig(configPath, config))
    {
        std::cerr << "Failed to load configuration from config.json\n";
        return 1;
    }
    Logger logger( std::chrono::seconds(config.alertCooldown) );
    logger.setLogLevel(config.logLevel);
    globalLogger = &logger;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    logger.log(std::string("Logging level: ") + Logger::levelToString(config.logLevel), "main", LogLevel::INFO);
    logger.log("Interface: " + config.interface, "main", LogLevel::INFO);
    logger.log("Starting hybridIDS", "main", LogLevel::INFO);

    RuleEngine ruleEngine(config, &logger);
    if (!ruleEngine.loadRules("config/rules.json"))
    {
        logger.log("Error loading rules", "rule_engine", LogLevel::ERROR);
        return 1;
    }

    if (!ruleEngine.loadWhitelist("config/whitelist.txt"))
    {
        logger.log("Error loading whitelist", "rule_engine", LogLevel::ERROR);
        return 1;
    }

    HeuristicEngine heuristicEngine(config, &logger);
    NftablesControl nftables(&logger);
    Sniffer sniffer(config.interface, &logger);

    sniffer.setPacketHandler([&](const Packet& pkt, const uint8_t* rawData, size_t dataLen)
    {
        bool sigDetect = ruleEngine.checkPacket(pkt);
        bool heurDetect = heuristicEngine.analyzePacket(pkt, rawData, dataLen);
        if (sigDetect || heurDetect)
        {
            logger.log("Threat detected from IP: " + pkt.srcIP, "main", LogLevel::WARNING);
            nftables.blockIP(pkt.srcIP);
        }
    });

    sniffer.start();

    while (running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    logger.log("Stop hybridIDS", "main", LogLevel::INFO);
    sniffer.stop();

    logger.log("hybridIDS completed", "main", LogLevel::INFO);
    return 0;
}