#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp> 

#include "rule_engine.h"

using json = nlohmann::json;

RuleEngine::RuleEngine(Logger* logger) : logger(logger)
{
    if (!nft.init())
    {
        if(logger)
            logger->log("Error initializing NftablesControl", "rule_engine", LogLevel::ERROR);
    }
}

bool RuleEngine::loadRules(const std::string& fileName)
{
    std::ifstream file(fileName);
    if (!file.is_open())
    {
        if (logger)
            logger->log("Failed to open rules file: " + fileName, "rule_engine", LogLevel::ERROR);
        return false;
    }

    json j;
    try
    {
        file >> j;
    }
    catch (const json::parse_error& e)
    {
        if (logger)
            logger->log(std::string("Error parsing JSON rules: ") + e.what(), "rule_engine", LogLevel::ERROR);
        return false;
    }
    if (!j.is_array())
    {
        if(logger)
            logger->log("The format of the rules file must be a JSON array", "rule_engine", LogLevel::ERROR);
        return false;
    }
    rules.clear();

    for (const auto& item : j)
    {
        Rule rule;

        if(item.contains("src_ip"))
            rule.srcIP = item["src_ip"].get<std::string>();
        if(item.contains("dst_ip"))
            rule.dstIP = item["dst_ip"].get<std::string>();
        if(item.contains("src_port"))
            rule.srcPort = item["src_port"].get<int>();
        if(item.contains("dst_port"))
            rule.dstPort = item["dst_port"].get<int>();
        if(item.contains("protocol"))
            rule.protocol = item["protocol"].get<std::string>();
        
        if (rule.srcPort < -1 || rule.srcPort > 65535)
        {
            if (logger)
                logger->log("Incorrect srcPort in rule: " + std::to_string(rule.srcPort), "rule_engine", LogLevel::DEBUG);
            continue; 
        }
        if (rule.dstPort < -1 || rule.dstPort > 65535)
        {
            if(logger)
                logger->log("Incorrect dstPort in rule: " + std::to_string(rule.dstPort), "rule_engine", LogLevel::DEBUG);
            continue;
        }

        rules.push_back(rule);

    }
    if(logger)
        logger->log("Rules loaded successfully: " + std::to_string(rules.size()), "rule_engine", LogLevel::INFO);
    return true;
}

bool RuleEngine::checkPacket(const Packet& packet)
{
    if (whitelist.contains(packet.srcIP))
    {
        if(logger)
            logger->log("IP from the white list, skip: " + packet.srcIP, "rule_engine", LogLevel::INFO);
        return false;
    }

    for (const auto& rule : rules)
    {
        if (!rule.srcIP.empty() && rule.srcIP != packet.srcIP)
            continue;
        if (!rule.dstIP.empty() && rule.dstIP != packet.dstIP)
            continue;
        if (rule.srcPort != -1 && rule.srcPort != packet.srcPort)
            continue;
        if (rule.dstPort != -1 && rule.dstPort != packet.dstPort)
            continue;
        if (!rule.protocol.empty() && rule.protocol != packet.protocol)
            continue;
        if(logger)
            logger->log("Suspicious package detected: " + packet.summary(), "rule_engine", LogLevel::WARNING);

        // Блокируем IP
        if (!blockedIPs.contains(packet.srcIP))
        {
            if (nft.blockIP(packet.srcIP))
            {
                this->blockedIPs.insert(packet.srcIP);
                if(logger)
                    logger->log(std::string("IP blocked by rule: ") + packet.srcIP, "rule_engine", LogLevel::WARNING);
            }
            else
            {
                if(logger)
                    logger->log(std::string("IP blocking error: ") + packet.srcIP, "rule_engine", LogLevel::ERROR);
            }
        }
        else
        {
            if(logger)
               logger->log(std::string("IP already blocked: ") + packet.srcIP, "rule_engine", LogLevel::WARNING);
        }
        return true;
    }

    return false;
}

bool RuleEngine::loadWhitelist(const std::string& fileName)
{
    std::ifstream file(fileName);
    if (!file.is_open())
    {
        if(logger)
            logger->log(std::string("Failed to open file whitelist: ") + fileName, "rule_engine", LogLevel::ERROR);
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        if (!line.empty())
            this->whitelist.insert(line);
    }

    if(logger)
        logger->log(std::string("Loaded whitelist from file: ") + fileName, "rule_engine", LogLevel::INFO);
    return true;
}
