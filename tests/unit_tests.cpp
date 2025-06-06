#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <netinet/ip_icmp.h>
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

std::chrono::seconds floodInterval{0};

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
    DummyLogger() : Logger(std::chrono::seconds(0), "/dev/null") {}
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
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
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

    std::this_thread::sleep_for(std::chrono::milliseconds(5500));
    engine.analyzePacket(p, raw, sizeof(raw));
    ASSERT_FALSE(logger.messages.empty());
}

TEST(HeuristicEngineTest, IcmpPacketTriggersAlertOnEmptyPayload) {
    Config config;
    DummyLogger logger;
    HeuristicEngine engine(config, &logger);

    uint8_t raw[64] = {};
    Packet p = makePacket("ICMP");

    // IP-заголовок
    ip* iphdr = (ip*)(raw + sizeof(ether_header));
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(28);
    iphdr->ip_p = IPPROTO_ICMP;

    // ICMP-заголовок
    icmphdr* icmph = (icmphdr*)(raw + sizeof(ether_header) + sizeof(ip));
    icmph->type = 8;  // Echo request
    icmph->code = 0;
    icmph->checksum = 0;  // Можно посчитать, но обычно для теста можно 0

    engine.analyzePacket(p, raw, 28);  // Передаем длину IP+ICMP без лишнего мусора

    ASSERT_FALSE(logger.messages.empty());
}


TEST(HeuristicEngineTest, IcmpPacketWithSuspiciousTypeTriggersAlert) {
    Config config;
    DummyLogger logger;
    HeuristicEngine engine(config, &logger);

    uint8_t raw[64] = {};
    Packet p = makePacket("ICMP");

    ip* iphdr = (ip*)(raw + sizeof(ether_header));
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(28);
    iphdr->ip_p = IPPROTO_ICMP;

    icmphdr* icmph = (icmphdr*)(raw + sizeof(ether_header) + sizeof(ip));
    icmph->type = 3;  // Destination unreachable
    icmph->code = 13; // Communication administratively prohibited
    icmph->checksum = 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(5500));
    engine.analyzePacket(p, raw, 28);

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
    Logger logger(floodInterval, testLogFile);
    logger.setLogLevel(LogLevel::DEBUG);

    std::string message = "Test message";
    logger.log(message, "test_module", LogLevel::INFO);

    std::string content = readLogFile();
    EXPECT_NE(content.find("Test message"), std::string::npos);
    EXPECT_NE(content.find("test_module"), std::string::npos);
    EXPECT_NE(content.find("INFO"), std::string::npos);
}

TEST_F(LoggerTest, LogLevelFiltering) {
    Logger logger(floodInterval, testLogFile);
    logger.setLogLevel(LogLevel::WARNING);

    logger.log("This should not appear", "test", LogLevel::INFO);
    logger.log("This should appear", "test", LogLevel::ERROR);

    std::string content = readLogFile();
    EXPECT_EQ(content.find("This should not appear"), std::string::npos);
    EXPECT_NE(content.find("This should appear"), std::string::npos);
}

TEST_F(LoggerTest, TimestampFormat) {
    Logger logger(floodInterval, testLogFile);
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

TEST_F(RuleEngineTest, CheckIcmpPacketMatchesRule) {
    // Добавим правило для ICMP
    std::ofstream ofs(rulesFile);
    ofs << R"([
        {
            "src_ip": "1.2.3.4",
            "protocol": "ICMP"
        }
    ])";
    ofs.close();

    RuleEngine engine(config, &dummyLogger);
    EXPECT_TRUE(engine.loadRules(rulesFile));

    Packet icmpPkt = makePacket("ICMP", "1.2.3.4");
    EXPECT_TRUE(engine.checkPacket(icmpPkt));
}

TEST_F(RuleEngineTest, CheckIcmpPacketDoesNotMatchRule) {
    std::ofstream ofs(rulesFile);
    ofs << R"([
        {
            "src_ip": "1.2.3.4",
            "protocol": "ICMP"
        }
    ])";
    ofs.close();

    RuleEngine engine(config, &dummyLogger);
    EXPECT_TRUE(engine.loadRules(rulesFile));

    Packet icmpPkt = makePacket("ICMP", "9.9.9.9");
    EXPECT_FALSE(engine.checkPacket(icmpPkt));
}

TEST_F(RuleEngineTest, IcmpPacketWhitelisted) {
    std::ofstream ofs(rulesFile);
    ofs << R"([
        {
            "src_ip": "5.6.7.8",
            "protocol": "ICMP"
        }
    ])";
    ofs.close();

    RuleEngine engine(config, &dummyLogger);
    EXPECT_TRUE(engine.loadRules(rulesFile));
    engine.loadWhitelist(whitelistFile); // whitelist содержит 5.6.7.8

    Packet icmpPkt = makePacket("ICMP", "5.6.7.8");
    EXPECT_FALSE(engine.checkPacket(icmpPkt));
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

TEST_F(SnifferTest, ParseIcmpPacket) {
    // Формируем минимальный Ethernet + IP + ICMP пакет (echo request)

    // Ethernet (14 байт)
    std::array<uint8_t, 14> eth = {
        0xff,0xff,0xff,0xff,0xff,0xff, // MAC dst (broadcast)
        0x00,0x0c,0x29,0xab,0xcd,0xef, // MAC src (пример)
        0x08, 0x00                     // Ethertype = IPv4 (0x0800)
    };

    // IP (20 байт)
    std::array<uint8_t, 20> ip = {
        0x45, 0x00, 0x00, 0x1c, // Версия+hlen=5(20байт), DSCP, длина=28 байт
        0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment offset
        64, IPPROTO_ICMP, 0x00, 0x00, // TTL=64, протокол=1(ICMP), контрольная сумма (0 для теста)
        127, 0, 0, 1,           // Src IP = 127.0.0.1
        127, 0, 0, 1            // Dst IP = 127.0.0.1
    };

    // ICMP (8 байт минимум, но нам хватит 2 для типа и кода)
    std::array<uint8_t, 8> icmp = {
        8, 0,       // Тип = 8 (echo request), Код = 0
        0x00, 0x00, // Чек-сумма (0 для теста)
        0x00, 0x01, 0x00, 0x01 // Остальные поля (идентификатор, seq)
    };

    // Собираем полный пакет
    std::vector<uint8_t> packet;
    packet.insert(packet.end(), eth.begin(), eth.end());
    packet.insert(packet.end(), ip.begin(), ip.end());
    packet.insert(packet.end(), icmp.begin(), icmp.end());

    // Создаём Sniffer с тестовым логгером
    DummyLogger logger;
    Sniffer sniffer("lo", &logger);

    Packet parsedPacket;
    bool handlerCalled = false;

    sniffer.setPacketHandler([&](const Packet& p, const uint8_t* data, size_t len) {
        parsedPacket = p;
        handlerCalled = true;
    });

    // Имитация вызова обработки пакета вручную (т.к. pcap не используется в тестах)

    // Разбор Ethernet
    if (packet.size() < sizeof(ether_header)) FAIL();
    const struct ether_header* ethh = (const struct ether_header*)packet.data();
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) FAIL();

    if (packet.size() < sizeof(ether_header) + sizeof(ip)) FAIL();
    const struct ip* iphdr = (const struct ip*)(packet.data() + sizeof(ether_header));
    Packet pkt;
    pkt.srcIP = inet_ntoa(iphdr->ip_src);
    pkt.dstIP = inet_ntoa(iphdr->ip_dst);

    const uint8_t* transportHeader = packet.data() + sizeof(ether_header) + iphdr->ip_hl * 4;

    switch (iphdr->ip_p)
    {
        case IPPROTO_ICMP:
            pkt.protocol = "ICMP";
            pkt.icmpType = transportHeader[0];
            pkt.icmpCode = transportHeader[1];
            break;
        default:
            FAIL(); 
    }

    parsedPacket = pkt;
    handlerCalled = true;

    ASSERT_TRUE(handlerCalled);
    EXPECT_EQ(parsedPacket.protocol, "ICMP");
    EXPECT_EQ(parsedPacket.icmpType, 8);
    EXPECT_EQ(parsedPacket.icmpCode, 0);
    EXPECT_EQ(parsedPacket.srcIP, "127.0.0.1");
    EXPECT_EQ(parsedPacket.dstIP, "127.0.0.1");
}

TEST_F(SnifferTest, ParseTcpPacket) {
    // Ethernet
    std::array<uint8_t, 14> eth = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x0c,0x29,0xab,0xcd,0xef,
        0x08, 0x00
    };
    // IP
    std::array<uint8_t, 20> ip = {
        0x45, 0x00, 0x00, 0x28,  // длина 40 байт (20 IP + 20 TCP)
        0x00, 0x00, 0x00, 0x00,
        64, IPPROTO_TCP, 0x00, 0x00,
        192, 168, 0, 1,
        192, 168, 0, 2
    };
    // TCP (20 байт)
    std::array<uint8_t, 20> tcp = {
        0x04, 0xd2, 0x00, 0x50, // src port = 1234, dst port = 80
        0x00,0x00,0x00,0x00,    // seq number
        0x00,0x00,0x00,0x00,    // ack number
        0x50, 0x02,             // data offset=5 (20 байт), flags SYN
        0x72, 0x10,             // window
        0x00, 0x00,             // checksum
        0x00, 0x00              // urgent pointer
    };
    std::vector<uint8_t> packet;
    packet.insert(packet.end(), eth.begin(), eth.end());
    packet.insert(packet.end(), ip.begin(), ip.end());
    packet.insert(packet.end(), tcp.begin(), tcp.end());

    DummyLogger logger;
    Sniffer sniffer("lo", &logger);

    Packet parsedPacket;
    bool handlerCalled = false;

    sniffer.setPacketHandler([&](const Packet& p, const uint8_t*, size_t) {
        parsedPacket = p;
        handlerCalled = true;
    });

    if (packet.size() < sizeof(ether_header)) FAIL();
    const struct ether_header* ethh = (const struct ether_header*)packet.data();
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) FAIL();
    if (packet.size() < sizeof(ether_header) + sizeof(ip)) FAIL();

    const struct ip* iphdr = (const struct ip*)(packet.data() + sizeof(ether_header));
    Packet pkt;
    pkt.srcIP = inet_ntoa(iphdr->ip_src);
    pkt.dstIP = inet_ntoa(iphdr->ip_dst);

    const uint8_t* transportHeader = packet.data() + sizeof(ether_header) + iphdr->ip_hl * 4;

    switch (iphdr->ip_p)
    {
        case IPPROTO_TCP:
        {
            pkt.protocol = "TCP";
            const struct tcphdr* tcph = (const struct tcphdr*)transportHeader;
            pkt.srcPort = ntohs(tcph->th_sport);
            pkt.dstPort = ntohs(tcph->th_dport);
            break;
        }
        default:
            FAIL();
    }
    parsedPacket = pkt;
    handlerCalled = true;

    ASSERT_TRUE(handlerCalled);
    EXPECT_EQ(parsedPacket.protocol, "TCP");
    EXPECT_EQ(parsedPacket.srcPort, 1234);
    EXPECT_EQ(parsedPacket.dstPort, 80);
    EXPECT_EQ(parsedPacket.srcIP, "192.168.0.1");
    EXPECT_EQ(parsedPacket.dstIP, "192.168.0.2");
}

TEST_F(SnifferTest, ParseUdpPacket) {
    // Ethernet
    std::array<uint8_t, 14> eth = {
        0xff,0xff,0xff,0xff,0xff,0xff,
        0x00,0x0c,0x29,0xab,0xcd,0xef,
        0x08, 0x00
    };
    // IP
    std::array<uint8_t, 20> ip = {
        0x45, 0x00, 0x00, 0x1c,  // длина 28 байт (20 IP + 8 UDP)
        0x00, 0x00, 0x00, 0x00,
        64, IPPROTO_UDP, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2
    };
    // UDP (8 байт)
    std::array<uint8_t, 8> udp = {
        0x1f, 0x90, 0x00, 0x35, // src port=8080, dst port=53
        0x00, 0x08, 0x00, 0x00  // length=8, checksum=0
    };

    std::vector<uint8_t> packet;
    packet.insert(packet.end(), eth.begin(), eth.end());
    packet.insert(packet.end(), ip.begin(), ip.end());
    packet.insert(packet.end(), udp.begin(), udp.end());

    DummyLogger logger;
    Sniffer sniffer("lo", &logger);

    Packet parsedPacket;
    bool handlerCalled = false;

    sniffer.setPacketHandler([&](const Packet& p, const uint8_t*, size_t) {
        parsedPacket = p;
        handlerCalled = true;
    });

    if (packet.size() < sizeof(ether_header)) FAIL();
    const struct ether_header* ethh = (const struct ether_header*)packet.data();
    if (ntohs(ethh->ether_type) != ETHERTYPE_IP) FAIL();
    if (packet.size() < sizeof(ether_header) + sizeof(ip)) FAIL();

    const struct ip* iphdr = (const struct ip*)(packet.data() + sizeof(ether_header));
    Packet pkt;
    pkt.srcIP = inet_ntoa(iphdr->ip_src);
    pkt.dstIP = inet_ntoa(iphdr->ip_dst);

    const uint8_t* transportHeader = packet.data() + sizeof(ether_header) + iphdr->ip_hl * 4;

    switch (iphdr->ip_p)
    {
        case IPPROTO_UDP:
        {
            pkt.protocol = "UDP";
            const struct udphdr* udph = (const struct udphdr*)transportHeader;
            pkt.srcPort = ntohs(udph->uh_sport);
            pkt.dstPort = ntohs(udph->uh_dport);
            break;
        }
        default:
            FAIL();
    }
    parsedPacket = pkt;
    handlerCalled = true;

    ASSERT_TRUE(handlerCalled);
    EXPECT_EQ(parsedPacket.protocol, "UDP");
    EXPECT_EQ(parsedPacket.srcPort, 8080);
    EXPECT_EQ(parsedPacket.dstPort, 53);
    EXPECT_EQ(parsedPacket.srcIP, "10.0.0.1");
    EXPECT_EQ(parsedPacket.dstIP, "10.0.0.2");
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
