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

std::string configPath = "config/config.json";

std::atomic<bool> running(true);
Logger* globalLogger = nullptr;

void signalHandler(int signum)
{
    if (globalLogger)
        globalLogger->log("Получен сигнал завершения (" + std::to_string(signum) + ")", "main", LogLevel::INFO);
    running = false;
}

int main()
{
    Config config;
    if (!loadConfig(configPath, config))
    {
        std::cerr << "Не удалось загрузить конфигурацию из config.json\n";
        return 1;
    }
    Logger logger;
    logger.setLogLevel(config.logLevel);
    globalLogger = &logger;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    logger.log(std::string("Уровень логирования: ") + Logger::levelToString(config.logLevel), "main", LogLevel::INFO);
    logger.log("Интерфейс: " + config.interface, "main", LogLevel::INFO);
    logger.log("Запуск hybridIDS", "main", LogLevel::INFO);

    RuleEngine ruleEngine(&logger);
    if (!ruleEngine.loadRules("config/rules.json"))
    {
        logger.log("Ошибка загрузки правил", "rule_engine", LogLevel::ERROR);
        return 1;
    }

    if (!ruleEngine.loadWhitelist("config/whitelist.txt"))
    {
        logger.log("Ошибка загрузки белого списка", "rule_engine", LogLevel::ERROR);
        return 1;
    }

    NftablesControl nftables(&logger);
    Sniffer sniffer(config.interface, &logger);

    sniffer.setPacketHandler([&](const Packet& pkt) 
    {
        if (ruleEngine.checkPacket(pkt))
        {
            logger.log("Найдена угроза:" + pkt.summary(), "rule_engine", LogLevel::WARNING);
            nftables.blockIP(pkt.srcIP);
        }
    });

    std::thread snifferThread([&]()
    {
        sniffer.start();
    });

    while (running)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    logger.log("Остановка hybridIDS", "main", LogLevel::INFO);
    sniffer.stop();

    if (snifferThread.joinable())
        snifferThread.join();

    logger.log("hybridIDS завершен", "main", LogLevel::INFO);
    return 0;
}