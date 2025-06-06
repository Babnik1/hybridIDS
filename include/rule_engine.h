#pragma once

#include <vector>
#include <string>
#include <unordered_set>

#include"logger.h"
#include "packet.h"
#include "nftables_control.h"
#include "config_utils.h"

struct Rule
{
    std::string srcIP;
    std::string dstIP;
    int srcPort = -1;
    int dstPort = -1;
    std::string protocol;

    int icmpType = -1;
    int icmpCode = -1;
};

class RuleEngine
{
public:
    RuleEngine(const Config& config, Logger* logger = nullptr);

    bool loadRules(const std::string& fileName);
    bool checkPacket(const Packet& packet);
    bool loadWhitelist(const std::string& fileName);

private:
    std::vector<Rule> rules;
    NftablesControl nft;
    std::unordered_set<std::string> blockedIPs;
    std::unordered_set<std::string> whitelist;
    Logger* logger;

    std::unordered_map<std::string, time_t> recentAlerts;
    int alertCooldownSeconds;
};