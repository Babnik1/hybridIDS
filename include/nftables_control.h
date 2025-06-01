#pragma once

#include <string>
#include <libmnl/libmnl.h>

#include "logger.h"

class NftablesControl
{
public:
    NftablesControl(Logger* logger = nullptr);
    ~NftablesControl();

    bool init();
    bool blockIP(const std::string& ip);

private:
    struct mnl_socket* nl = nullptr;
    Logger* logger;

    bool ensureTable();
    bool ensureChain();
    bool addRule(const std::string& ip);
};
