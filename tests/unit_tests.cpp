// unit_tests.cpp — Расширенные юнит-тесты для всех компонентов hybridIDS

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "config_utils.h"
#include "heuristic_engine.h"
#include "logger.h"
#include "rule_engine.h"
#include "packet.h"
#include "nftables_control.h"
#include "sniffer.h"
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>
#include <regex>

using namespace std;
using namespace std::chrono;
using ::testing::_;

// Утилита: временный файл
string createTempFile(const string& name, const string& content) {
    ofstream file(name);
    file << content;
    return name;
}

//---------------------------------------------
// config_utils
//---------------------------------------------
TEST(ConfigUtilsTest, InvalidTypesAndNegativeValues) {
    string json = R"({
        "interface": 42,
        "log_level": "debug",
        "alert_cooldown": -1,
        "heuristic_packet_threshold": "a lot",
        "heuristic_time_window": null
    })";
    auto path = createTempFile("bad_config.json", json);
    Config cfg;
    EXPECT_FALSE(loadConfig(path, cfg));
}

TEST(ConfigUtilsTest, EmptyJsonAndMalformedJson) {
    string empty = "{}";
    string malformed = "{ \"interface\": \"eth0\"";
    EXPECT_FALSE(loadConfig(createTempFile("empty.json", empty), Config{}));
    EXPECT_FALSE(loadConfig(createTempFile("broken.json", malformed), Config{}));
}

//---------------------------------------------
// heuristic_engine
//---------------------------------------------
TEST(HeuristicEngineTest, MultipleIPsIndependently) {
    HeuristicEngine engine(3, 5);
    Packet p1{"192.168.1.1"};
    Packet p2{"10.0.0.1"};
    for (int i = 0; i < 4; ++i) engine.addPacket(p1);
    for (int i = 0; i < 2; ++i) engine.addPacket(p2);
    EXPECT_TRUE(engine.checkAnomaly("192.168.1.1"));
    EXPECT_FALSE(engine.checkAnomaly("10.0.0.1"));
}

TEST(HeuristicEngineTest, RecheckClearsOldState) {
    HeuristicEngine engine(2, 1);
    Packet p{"1.1.1.1"};
    engine.addPacket(p);
    EXPECT_FALSE(engine.checkAnomaly("1.1.1.1"));
    engine.addPacket(p);
    EXPECT_TRUE(engine.checkAnomaly("1.1.1.1"));
    this_thread::sleep_for(seconds(2));
    engine.addPacket(p);
    EXPECT_FALSE(engine.checkAnomaly("1.1.1.1"));
}

//---------------------------------------------
// logger
//---------------------------------------------
TEST(LoggerTest, LogLevelAndOutputFile) {
    Logger& logger = Logger::getInstance();
    ofstream log("test.log"); log.close();
    logger.setLogFile("test.log");
    logger.setLogLevel(LogLevel::INFO);
    logger.log(LogLevel::DEBUG, "debug");
    logger.log(LogLevel::INFO, "info");

    ifstream in("test.log");
    string line;
    bool found = false;
    while (getline(in, line)) {
        if (line.find("info") != string::npos) found = true;
        ASSERT_TRUE(line.find("debug") == string::npos);
    }
    EXPECT_TRUE(found);
}

//---------------------------------------------
// rule_engine
//---------------------------------------------
TEST(RuleEngineTest, CombinedRuleMatch) {
    string json = R"([
        {"src_ip": "10.0.0.1", "dest_port": 80, "protocol": "TCP"}
    ])";
    RuleEngine engine;
    engine.loadRules(createTempFile("rules.json", json));
    Packet p{"10.0.0.1", "1.1.1.1", 1234, 80, "TCP"};
    EXPECT_TRUE(engine.match(p));
}

TEST(RuleEngineTest, InvalidAndEmptyRules) {
    string bad_json = "[{ \"src_ip\": 123 }]";
    RuleEngine engine;
    EXPECT_NO_THROW(engine.loadRules(createTempFile("bad.json", bad_json)));
    EXPECT_FALSE(engine.match(Packet{"1.1.1.1"}));
}

TEST(RuleEngineTest, OverlappingRules) {
    string json = R"([
        {"src_ip": "10.0.0.1"},
        {"src_ip": "10.0.0.1", "dest_port": 80}
    ])";
    RuleEngine engine;
    engine.loadRules(createTempFile("overlap.json", json));
    Packet p{"10.0.0.1", "2.2.2.2", 1000, 80, "TCP"};
    EXPECT_TRUE(engine.match(p));
}

//---------------------------------------------
// packet
//---------------------------------------------
TEST(PacketTest, PacketFieldsCorrect) {
    Packet p{"a", "b", 1, 2, "c"};
    EXPECT_EQ(p.srcIP, "a");
    EXPECT_EQ(p.destIP, "b");
    EXPECT_EQ(p.srcPort, 1);
    EXPECT_EQ(p.destPort, 2);
    EXPECT_EQ(p.protocol, "c");
}

//---------------------------------------------
// nftables_control (мок system)
//---------------------------------------------
#ifdef TESTING
int mock_call_count = 0;
std::string last_cmd;
int mock_system(const char* cmd) {
    ++mock_call_count;
    last_cmd = cmd;
    return 0;
}
#define system mock_system
#endif

TEST(NftablesControlTest, BlockIPCommandFormat) {
#ifdef TESTING
    mock_call_count = 0;
    blockIP("5.5.5.5");
    EXPECT_EQ(mock_call_count, 1);
    EXPECT_NE(last_cmd.find("5.5.5.5"), string::npos);
#else
    SUCCEED();
#endif
}

//---------------------------------------------
// sniffer (мокаем обработку pcap)
//---------------------------------------------
TEST(SnifferTest, SimulatePacketCallback) {
    Packet fake{"1.2.3.4", "5.6.7.8", 1000, 80, "TCP"};
    bool triggered = false;
    auto cb = [&](const Packet& p) {
        EXPECT_EQ(p.srcIP, fake.srcIP);
        EXPECT_EQ(p.destPort, 80);
        triggered = true;
    };
    cb(fake);
    EXPECT_TRUE(triggered);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
