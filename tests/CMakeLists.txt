find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(LIBMNL REQUIRED libmnl)
pkg_check_modules(LIBNFTNL REQUIRED libnftnl)

add_executable(unit_tests
    ../src/logger.cpp
    ../src/sniffer.cpp
    ../src/nftables_control.cpp
    ../src/rule_engine.cpp
    ../src/heuristic_engine.cpp
    ../src/config_utils.cpp
    ../src/packet.cpp
    unit_tests.cpp
)

target_compile_definitions(unit_tests PRIVATE TESTING)

target_include_directories(unit_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
    ${LIBMNL_INCLUDE_DIRS}
    ${LIBNFTNL_INCLUDE_DIRS}
)

target_link_libraries(unit_tests
    GTest::gtest
    GTest::gtest_main
    nlohmann_json::nlohmann_json
    pthread

    ${PCAP_LIBRARIES}
    ${LIBMNL_LIBRARIES}
    ${LIBNFTNL_LIBRARIES}
)

add_test(NAME AllUnitTests COMMAND unit_tests --gtest_color=yes --gtest_print_time=1)
