#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <thread>
#include <chrono>
#include <vector>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include "../include/config_utils.h"
#include "../include/heuristic_engine.h"
#include "../include/logger.h"
#include "../include/nftables_control.h"
#include "../include/rule_engine.h"
#include "../include/packet.h"
#include "../include/sniffer.h"

//
// ---------------- CONFIG_UTILS ----------------
//
class ConfigUtilsTest : public ::testing::Test {
protected:
    std::string validFile = "test_valid_config.json";
    std::string invalidFile = "test_invalid_config.json";

    void SetUp() override {
        std::ofstream ofs(validFile);
        ofs << R"({
            "interface": "eth0",
            "log_level": "debug",
            "alert_cooldown": 5,
            "heuristicPacketThreshold": 50,
            "heuristicTimeWindowSeconds": 5
        })";
        ofs.close();

        std::ofstream ofs2(invalidFile);
        ofs2 << R"({
            "interface": 123,
            "log_level": 42
        })";
        ofs2.close();
    }

    void TearDown() override {
        std::remove(validFile.c_str());
        std::remove(invalidFile.c_str());
    }
};

TEST_F(ConfigUtilsTest, LoadValidConfig) {
    Config config;
    ASSERT_TRUE(loadConfig(validFile, config));
    EXPECT_EQ(config.interface, "eth0");
    EXPECT_EQ(config.logLevel, LogLevel::DEBUG);
    EXPECT_EQ(config.alertCooldown, 5);
    EXPECT_EQ(config.heuristicPacketThreshold, 50);
    EXPECT_EQ(config.heuristicTimeWindowSeconds, 5);
}

TEST_F(ConfigUtilsTest, LoadInvalidConfig) {
    Config config;
    ASSERT_FALSE(loadConfig(invalidFile, config));
}

TEST_F(ConfigUtilsTest, LoadMissingFile) {
    Config config;
    ASSERT_FALSE(loadConfig("nonexistent.json", config));
}

//
// ---------------- HEURISTIC_ENGINE ----------------
//
class DummyLogger : public Logger {
public:
    DummyLogger() : Logger("/dev/null") {}
    std::vector<std::string> messages;
    void log(const std::string& msg, const std::string& src, LogLevel lvl) override {
        messages.push_back(msg);
    }
};

Packet makePacket(std::string proto, std::string ip = "192.168.1.1", int sport = 1234, int dport = 80) {
    Packet p;
    p.protocol = proto;
    p.srcIP = ip;
    p.dstIP = "10.0.0.1";
    p.srcPort = sport;
    p.dstPort = dport;
    return p;
}

TEST(HeuristicEngineTest, PacketRateThresholdTCP) {
    Config config;
    config.heuristicPacketThreshold = 3;
    config.heuristicTimeWindowSeconds = 10;

    DummyLogger logger;
    HeuristicEngine engine(config, &logger);

    std::array<uint8_t, 40> rawData = {
    // IP-заголовок (20 байт)
    0x45, 0x00, 0x00, 0x28,  // Версия+длина, DSCP, длина = 40
    0x00, 0x00, 0x40, 0x00,  // ID, флаги+фрагменты
    0x40, 0x06, 0x00, 0x00,  // TTL, протокол (6=TCP), чек-сумма
    0x7F, 0x00, 0x00, 0x01,  // Src IP: 127.0.0.1
    0x7F, 0x00, 0x00, 0x01,  // Dst IP: 127.0.0.1

    // TCP-заголовок (20 байт)
    0x1F, 0x90, 0x00, 0x50,  // Src port: 8080, Dst port: 80
    0x00, 0x00, 0x00, 0x00,  // Seq number
    0x00, 0x00, 0x00, 0x00,  // Ack number
    0x50, 0x02, 0x71, 0x10,  // Header len+flags (SYN), window
    0x00, 0x00, 0x00, 0x00   // Checksum, urgent pointer
};

    Packet pkt = makePacket("TCP");

    for (int i = 0; i < 4; ++i)
    {
        engine.analyzePacket(pkt, rawData.data(), 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    EXPECT_FALSE(logger.messages.empty());
}

TEST(HeuristicEngineTest, EmptyUdpPacketTriggersAlert) {
    Config config;
    DummyLogger logger;
    HeuristicEngine engine(config, &logger);

    uint8_t raw[64] = {};
    Packet p = makePacket("UDP");
    
    ip* iphdr = (ip*)(raw + sizeof(ether_header));
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(28);
    udphdr* udph = (udphdr*)(raw + sizeof(ether_header) + sizeof(ip));
    udph->len = htons(8);

    engine.analyzePacket(p, raw, sizeof(raw));
    ASSERT_FALSE(logger.messages.empty());
}

TEST(HeuristicEngineTest, SuspiciousTcpFlagsDetected) {
    Config config;
    DummyLogger logger;
    HeuristicEngine engine(config, &logger);

    uint8_t raw[64] = {};
    Packet p = makePacket("TCP");

    ip* iphdr = (ip*)(raw + sizeof(ether_header));
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(40);
    tcphdr* tcph = (tcphdr*)(raw + sizeof(ether_header) + sizeof(ip));
    tcph->th_off = 5;
    ((uint8_t*)tcph)[13] = TH_SYN | TH_FIN;

    engine.analyzePacket(p, raw, sizeof(raw));
    ASSERT_FALSE(logger.messages.empty());
}

TEST(HeuristicEngineTest, EmptyTcpPayloadDetected) {
    Config config;
    DummyLogger logger;
    HeuristicEngine engine(config, &logger);

    uint8_t raw[64] = {};
    Packet p = makePacket("TCP");

    ip* iphdr = (ip*)(raw + sizeof(ether_header));
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(40);
    tcphdr* tcph = (tcphdr*)(raw + sizeof(ether_header) + sizeof(ip));
    tcph->th_off = 5;

    engine.analyzePacket(p, raw, sizeof(raw));
    ASSERT_FALSE(logger.messages.empty());
}

//
// ---------------- LOGGER ----------------
//
class LoggerTest : public ::testing::Test {
protected:
    const std::string testLogFile = "test_logger_output.log";

    void TearDown() override {
        std::remove(testLogFile.c_str());
    }

    std::string readLogFile() {
        std::ifstream file(testLogFile);
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }
};

TEST_F(LoggerTest, LogWritesToFileAndConsole) {
    Logger logger(testLogFile);
    logger.setLogLevel(LogLevel::DEBUG);

    std::string message = "Test message";
    logger.log(message, "test_module", LogLevel::INFO);

    std::string content = readLogFile();
    EXPECT_NE(content.find("Test message"), std::string::npos);
    EXPECT_NE(content.find("test_module"), std::string::npos);
    EXPECT_NE(content.find("INFO"), std::string::npos);
}

TEST_F(LoggerTest, LogLevelFiltering) {
    Logger logger(testLogFile);
    logger.setLogLevel(LogLevel::WARNING);

    logger.log("This should not appear", "test", LogLevel::INFO);
    logger.log("This should appear", "test", LogLevel::ERROR);

    std::string content = readLogFile();
    EXPECT_EQ(content.find("This should not appear"), std::string::npos);
    EXPECT_NE(content.find("This should appear"), std::string::npos);
}

TEST_F(LoggerTest, TimestampFormat) {
    Logger logger(testLogFile);
    logger.setLogLevel(LogLevel::DEBUG);
    logger.log("Timestamp test", "time", LogLevel::INFO);

    std::string content = readLogFile();
    std::regex pattern(R"(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\[INFO\]\[time\] Timestamp test)");
    EXPECT_TRUE(std::regex_search(content, pattern));
}

TEST_F(LoggerTest, LevelToStringReturnsCorrectString) {
    EXPECT_EQ(Logger::levelToString(LogLevel::DEBUG), "DEBUG");
    EXPECT_EQ(Logger::levelToString(LogLevel::INFO), "INFO");
    EXPECT_EQ(Logger::levelToString(LogLevel::WARNING), "WARNING");
    EXPECT_EQ(Logger::levelToString(LogLevel::ERROR), "ERROR");
}

//
// ---------------- NFTABLES_CONTROL ----------------
//
class NftablesControlTest : public ::testing::Test {
protected:
    DummyLogger dummyLogger;
};

TEST_F(NftablesControlTest, Initialization) {
    NftablesControl nft(&dummyLogger);
    EXPECT_TRUE(nft.init());
}

TEST_F(NftablesControlTest, BlockValidIP) {
    NftablesControl nft(&dummyLogger);
    ASSERT_TRUE(nft.init());
    EXPECT_TRUE(nft.blockIP("192.168.1.1"));
}

TEST_F(NftablesControlTest, BlockInvalidIP) {
    NftablesControl nft(&dummyLogger);
    ASSERT_TRUE(nft.init());
    EXPECT_TRUE(nft.blockIP("256.256.256.256"));
}

//
// ---------------- RULE_ENGINE ----------------
//
class RuleEngineTest : public ::testing::Test {
protected:
    DummyLogger dummyLogger;
    Config config{.alertCooldown = 0};
    std::string rulesFile = "test_rules.json";
    std::string whitelistFile = "test_whitelist.txt";

    void SetUp() override {
        std::ofstream ofs(rulesFile);
        ofs << R"([
            {
                "src_ip": "1.2.3.4",
                "dst_port": 80,
                "protocol": "TCP"
            }
        ])";
        ofs.close();

        std::ofstream wl(whitelistFile);
        wl << "5.6.7.8\n";
        wl.close();
    }

    void TearDown() override {
        std::remove(rulesFile.c_str());
        std::remove(whitelistFile.c_str());
    }
};

TEST_F(RuleEngineTest, LoadValidRules) {
    RuleEngine engine(config, &dummyLogger);
    EXPECT_TRUE(engine.loadRules(rulesFile));
}

TEST_F(RuleEngineTest, LoadInvalidRulesFile) {
    RuleEngine engine(config, &dummyLogger);
    EXPECT_FALSE(engine.loadRules("nonexistent.json"));
}

TEST_F(RuleEngineTest, LoadWhitelist) {
    RuleEngine engine(config, &dummyLogger);
    EXPECT_TRUE(engine.loadWhitelist(whitelistFile));
}

TEST_F(RuleEngineTest, CheckPacketMatchesRule) {
    RuleEngine engine(config, &dummyLogger);
    engine.loadRules(rulesFile);

    Packet p = makePacket("TCP", "1.2.3.4", 12345, 80);
    EXPECT_TRUE(engine.checkPacket(p));
}

TEST_F(RuleEngineTest, CheckPacketDoesNotMatchRule) {
    RuleEngine engine(config, &dummyLogger);
    engine.loadRules(rulesFile);

    Packet p = makePacket("TCP", "9.9.9.9", 12345, 443);
    EXPECT_FALSE(engine.checkPacket(p));
}

TEST_F(RuleEngineTest, WhitelistSkipsDetection) {
    RuleEngine engine(config, &dummyLogger);
    engine.loadRules(rulesFile);
    engine.loadWhitelist(whitelistFile);

    Packet p = makePacket("TCP", "5.6.7.8", 12345, 80);
    EXPECT_FALSE(engine.checkPacket(p));
}

//
// ---------------- SNIFFER ----------------
//
class SnifferTest : public ::testing::Test {
protected:
    DummyLogger logger;
};

TEST_F(SnifferTest, ConstructAndSetHandler) {
    Sniffer sniffer("lo", &logger);
    bool called = false;
    sniffer.setPacketHandler([&](const Packet& p, const uint8_t*, size_t) {
        called = true;
    });
    EXPECT_FALSE(called);
}

TEST_F(SnifferTest, StartStopSnifferNoCrash) {
    Sniffer sniffer("lo", &logger);
    sniffer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    sniffer.stop();
    SUCCEED();
}

TEST_F(SnifferTest, InvalidInterfaceLogsError) {
    Sniffer sniffer("invalid0", &logger);
    sniffer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    sniffer.stop();

    bool errorLogged = false;
    for (const auto& line : logger.messages) {
        if (line.find("Error opening interface") != std::string::npos) {
            errorLogged = true;
            break;
        }
    }

    EXPECT_TRUE(errorLogged);
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
