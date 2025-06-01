cmake_minimum_required(VERSION 3.20)

project(hybridIDS VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Let CMake find Conan packages
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}")

# Binary directory
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(SOURCES
    src/main.cpp
    src/sniffer.cpp
    src/rule_engine.cpp
    src/nftables_control.cpp
    src/logger.cpp
    src/packet.cpp
    src/config_utils.cpp
)

add_executable(hybridIDS ${SOURCES})

set_target_properties(hybridIDS PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)

target_include_directories(hybridIDS PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Conan-provided package
find_package(nlohmann_json REQUIRED)
target_link_libraries(hybridIDS PRIVATE nlohmann_json::nlohmann_json)

# System libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

target_include_directories(hybridIDS PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(hybridIDS PRIVATE ${PCAP_LIBRARIES})
target_compile_options(hybridIDS PRIVATE ${PCAP_CFLAGS_OTHER})

pkg_check_modules(LIBMNL REQUIRED libmnl)
pkg_check_modules(LIBNFTNL REQUIRED libnftnl)

target_include_directories(hybridIDS PRIVATE ${LIBMNL_INCLUDE_DIRS} ${LIBNFTNL_INCLUDE_DIRS})
target_link_libraries(hybridIDS PRIVATE ${LIBMNL_LIBRARIES} ${LIBNFTNL_LIBRARIES})
target_compile_options(hybridIDS PRIVATE ${LIBMNL_CFLAGS_OTHER} ${LIBNFTNL_CFLAGS_OTHER})
