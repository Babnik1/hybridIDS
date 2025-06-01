#include "sniffer.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h> // для ether_header
#include <arpa/inet.h>


Sniffer::Sniffer(const std::string& interfaceName, Logger* logger) : interface(interfaceName), logger(logger){}

Sniffer::~Sniffer()
{
    stop();
    if (handle)
    {
        pcap_close(handle);
        handle = nullptr;
    }
}

void Sniffer::setPacketHandler(PacketHandler handler)
{
    packetHandler = handler;
}

void Sniffer::start()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        if (logger)
            logger->log(std::string("Error opening interface ") + interface + ": " + errbuf, "sniffer", LogLevel::ERROR);
        return;
    }

    running = true;
    captureThread = std::thread([this]() { captureLoop(); });
}

void Sniffer::stop()
{
    running = false;
    if (handle)
    {
        pcap_breakloop(handle); 
    }
    if (captureThread.joinable())
        captureThread.join();
}

void Sniffer::captureLoop()
{
    while (running)
    {
        struct pcap_pkthdr* header;
        const u_char* data;
        int result = pcap_next_ex(handle, &header, &data);
        if (result == 1)
        {
            if (header->caplen < sizeof(ether_header))
                continue; // Мало данных

            Packet pkt;

            // Разбор Ethernet
            const struct ether_header* eth = (const struct ether_header*)data;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP)
                continue; // Только IPv4

            if (header->caplen < sizeof(ether_header) + sizeof(struct ip))
                continue; // Мало данных для IP

            // Разбор IP
            const struct ip* iphdr = (const struct ip*)(data + sizeof(struct ether_header));
            pkt.srcIP = inet_ntoa(iphdr->ip_src);
            pkt.dstIP = inet_ntoa(iphdr->ip_dst);

            // Протокол
            switch (iphdr->ip_p)
            {
                case IPPROTO_TCP:
                {
                    pkt.protocol = "TCP";

                    if (header->caplen < sizeof(ether_header) + iphdr->ip_hl * 4 + sizeof(tcphdr))
                        continue; // Мало данных для TCP

                    const struct tcphdr* tcph = (const struct tcphdr*)(data + sizeof(ether_header) + iphdr->ip_hl * 4);
                    pkt.srcPort = ntohs(tcph->th_sport);
                    pkt.dstPort = ntohs(tcph->th_dport);
                    break;
                }
                case IPPROTO_UDP:
                {
                    pkt.protocol = "UDP";

                    if (header->caplen < sizeof(ether_header) + iphdr->ip_hl * 4 + sizeof(udphdr))
                        continue; // Мало данных для UDP

                    const struct udphdr* udph = (const struct udphdr*)(data + sizeof(ether_header) + iphdr->ip_hl * 4);
                    pkt.srcPort = ntohs(udph->uh_sport);
                    pkt.dstPort = ntohs(udph->uh_dport);
                    break;
                }
                default:
                    pkt.protocol = "OTHER";
                    pkt.srcPort = 0;
                    pkt.dstPort = 0;
                    break;
            }

            if (packetHandler)
                packetHandler(pkt, data, header->caplen);
        }
        else if (result == -1)
        {
            if (logger)
                logger->log(std::string("pcap_next_ex error: ") + pcap_geterr(handle), "sniffer", LogLevel::DEBUG);
            break;
        }
    }
}
