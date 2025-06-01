#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>

#include "nftables_control.h"

NftablesControl::NftablesControl(Logger* logger) : nl(nullptr), logger(logger)
{
    init();
}

NftablesControl::~NftablesControl()
{
    if (nl != nullptr)
    {
        mnl_socket_close(nl);
        nl = nullptr;
    }
}

bool NftablesControl::init()
{
    if (nl != nullptr)
    {
        // Уже инициализирован
        return true;
    }

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == nullptr)
    {
        if (logger)
            logger->log("Ошибка при открытии сокета Netlink.", "nftables", LogLevel::ERROR);
        return false;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        if (logger)
            logger->log("Ошибка при привязке сокета Netlink.", "nftables", LogLevel::ERROR);
        mnl_socket_close(nl);
        nl = nullptr;
        return false;
    }

    if (!ensureTable() || !ensureChain())
    {
        if (logger)
            logger->log("Ошибка при создании таблицы или цепочки nftables.", "nftables", LogLevel::ERROR);
        return false;
    }

    return true;
}

bool NftablesControl::ensureTable()
{
    struct nftnl_table* table = nftnl_table_alloc();
    if (!table) return false;

    nftnl_table_set_str(table, NFTNL_TABLE_NAME, "filter");
    nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_INET);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh = nftnl_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE,
        NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, 0);

    nftnl_table_nlmsg_build_payload(nlh, table);

    int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    nftnl_table_free(table);

    if (ret < 0) return false;

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    return (ret >= 0);
}

bool NftablesControl::ensureChain()
{
    struct nftnl_chain* chain = nftnl_chain_alloc();
    if (!chain) return false;

    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, "filter");
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, "input");
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, NFPROTO_INET);

    // Вот это — КОРРЕКТНОЕ задание hook'а
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN); // "input" по смыслу
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 0);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "filter");

    // Опционально: политика
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_POLICY, NF_ACCEPT);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN,
        NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, 0);

    nftnl_chain_nlmsg_build_payload(nlh, chain);
    int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    nftnl_chain_free(chain);

    if (ret < 0) return false;

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    return (ret >= 0);
}


bool NftablesControl::blockIP(const std::string& ip)
{
    if (logger)
        logger->log("Блокировка IP через nftables: " + ip, "nftables", LogLevel::INFO);

    struct nftnl_rule* rule = nftnl_rule_alloc();
    if (!rule) return false;

    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "filter");
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "input");
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_INET);

    struct nftnl_expr* expr = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, 12);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, 4);
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);

    uint32_t ip_bin = inet_addr(ip.c_str());
    nftnl_expr_set_data(expr, NFTNL_EXPR_CMP_DATA, &ip_bin, sizeof(ip_bin));
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("immediate");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, NF_DROP);
    nftnl_rule_add_expr(rule, expr);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE,
        NFPROTO_INET, NLM_F_CREATE | NLM_F_ACK, 0);

    nftnl_rule_nlmsg_build_payload(nlh, rule);

    int ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    nftnl_rule_free(rule);

    if (ret < 0) return false;

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    return (ret >= 0);
    //return true; // или false в случае ошибки
}
