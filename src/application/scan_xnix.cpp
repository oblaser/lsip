/*
author          Oliver Blaser
date            05.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>

#include "middleware/cli.h"
#include "project.h"

#include <omw/clock.h>
#include <omw/defs.h>
#include <omw/encoding.h>

#if (OMW_PLAT_UNIX || OMW_PLAT_LINUX || OMW_PLAT_APPLE) // *nix

#include <errno.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>


#define SWITCH_CASE_DEFINE_TO_STR(_define) \
    case _define:                          \
        str = #_define;                    \
        break



static std::string aftos(int af);
static std::string ethptos(uint32_t proto);
static std::string ipptos(uint32_t proto);
static std::string sockaddrtos(const struct sockaddr* sa);
static uint16_t inetChecksum(const uint8_t* data, size_t count);



/**
 * @param ipStr IPv4 address, format: `a.b.c.d`
 * @param macBuffer uint8_t[6] MAC address buffer
 * @return 0 on success, negative on error, positive on timeout
 */
int impl_scan_xnix(const char* ipStr, uint8_t* macBuffer)
{
#if PRJ_DEBUG && 1
    for (size_t i = 0; i < 6; ++i) { macBuffer[i] = 0xFF; }
    return 0;
#else // PRJ_DEBUG
#error "TODO implement"
#endif // PRJ_DEBUG
}



#if PRJ_DEBUG

#include <application/vendor-lookup.h>

static int printL2Packet(const uint8_t* sockData, size_t sockDataSize, const struct sockaddr* sockSrcAddr)
{
    const struct ethhdr* const ethHeader = (const struct ethhdr*)(sockData + 0);
    const mac::Addr srcMac(ethHeader->h_source);
    const mac::Addr dstMac(ethHeader->h_dest);
    const uint16_t ethProtocol = ntohs(ethHeader->h_proto);
    const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
    const uint8_t* const ethData = sockData + ethHeaderSize;
    const size_t ethDataSize = sockDataSize - ethHeaderSize - 4 /* CRC */;

    // filter
    if (((srcMac & mac::EUI48::oui28_mask) == mac::EUI48(0xB8D812600000)) || //
        (ethProtocol != ETH_P_ARP))                                          //
    {
        return 1;
    }

#if 0
    // looks like this is always the AF used when creating the socket
    printf("recvfrom() src addr %s: %s\n", aftos(sockSrcAddr->sa_family).c_str(), sockaddrtos(sockSrcAddr).c_str());
    cli::hexDump((uint8_t*)(sockSrcAddr->sa_data), sizeof(sockSrcAddr->sa_data));

    printf("\nrecvfrom() data [%zu]:\n", sockDataSize);
    cli::hexDump(sockData, sockDataSize);

    printf("\n");
#endif

    printf("Ethernet\n");
    printf("  src   %s %s\n", srcMac.toString().c_str(), app::lookupVendor(srcMac).name().c_str());
    printf("  dst   %s %s\n", dstMac.toString().c_str(), app::lookupVendor(dstMac).name().c_str());
    printf("  proto 0x%04x %s\n", (int)ethProtocol, ethptos(ethProtocol).c_str());
    printf("  hdr size  %zu\n", ethHeaderSize);
    printf("  data size %zu\n", ethDataSize);

    if (ethProtocol == ETH_P_IP)
    {
        const struct iphdr* const ipHeader = (const struct iphdr*)(ethData + 0);
        const uint8_t ipVersion = ipHeader->version;
        const uint8_t ipIhl = ipHeader->ihl;
        const size_t ipHeaderSize = ipIhl * 4u;
        const uint8_t ipTos = ipHeader->tos;
        const uint16_t ipTotalLen = ntohs(ipHeader->tot_len);
        const uint16_t ipId = ntohs(ipHeader->id);
        const uint8_t ipFlags = (uint8_t)(ntohs(ipHeader->frag_off) >> 13);
        const uint16_t ipFragOff = (ntohs(ipHeader->frag_off) & 0x1FFF);
        const uint8_t ipTtl = ipHeader->ttl;
        const uint8_t ipProtocol = ipHeader->protocol;
        const uint16_t ipCheck = ntohs(ipHeader->check);
        const uint16_t ipCheckCalc = inetChecksum(ethData + 0, ipHeaderSize);
        const uint32_t srcIp = ntohl(ipHeader->saddr);
        const uint32_t dstIp = ntohl(ipHeader->daddr);
        const uint8_t* const ipData = ethData + ipHeaderSize;
        const size_t ipDataSize = ethDataSize - ipHeaderSize;

        // filter
        // if (ipProtocol == IPPROTO_TCP) { return 1; }

        char ntopBuffer[32 + 15 + 1];

        printf("\nIPv4\n");
        printf("  version   %i\n", (int)ipVersion);
        printf("  IHL       %i\n", (int)ipIhl);
        printf("  ToS       0x%02x\n", (int)ipTos);
        printf("  total len %i\n", (int)ipTotalLen);
        printf("  ID        %i\n", (int)ipId);
        printf("  flags     0x%02x\n", (int)ipFlags);
        printf("  frag off  %i\n", (int)ipFragOff);
        printf("  TTL       %i\n", (int)ipTtl);
        printf("  protocol  %02x %s\n", ipProtocol, ipptos(ipProtocol).c_str());
        printf("  check     %s0x%04x\033[90m 0x%04x\033[39m\n", (ipCheckCalc == 0 ? "" : "\033[31m"), (int)ipCheck, (int)ipCheckCalc);
        printf("  src addr  %s\n", inet_ntop(AF_INET, &(ipHeader->saddr), ntopBuffer, sizeof(ntopBuffer)));
        printf("  dst addr  %s\n", inet_ntop(AF_INET, &(ipHeader->daddr), ntopBuffer, sizeof(ntopBuffer)));
        printf("  hdr size  %zu\n", ipHeaderSize);
        printf("  data size %zu\n", ipDataSize);

        if (ipProtocol == IPPROTO_TCP)
        {
            const struct tcphdr* const tcpHeader = (const struct tcphdr*)(ipData + 0);
            const uint16_t srcPort = ntohs(tcpHeader->th_sport);
            const uint16_t dstPort = ntohs(tcpHeader->th_dport);
            const uint32_t tcpSeq = ntohl(tcpHeader->th_seq);
            // ...
            const uint8_t tcpDataOff = tcpHeader->th_off;
            const size_t tcpHeaderSize = tcpDataOff * 4u;
            const uint8_t tcpFlags = tcpHeader->th_flags;
            // ...
            const uint8_t* const tcpData = ipData + tcpHeaderSize;
            const size_t tcpDataSize = ipDataSize - tcpHeaderSize;

            printf("\nTCP\n");
            printf("  src port  %i\n", (int)srcPort);
            printf("  dst port  %i\n", (int)dstPort);
            printf("  sequence  %u\n", tcpSeq);
            printf("  data off  %i\n", (int)tcpDataOff);
            printf("  flags     0x%02x\n", (int)tcpFlags);
            printf("  hdr size  %zu\n", tcpHeaderSize);
            printf("  data size %zu\n", tcpDataSize);

            if (tcpDataSize < ipDataSize) { cli::hexDump(tcpData, tcpDataSize); }
            else { cli::printWarning("TCP data size"); }
        }
        else if (ipProtocol == IPPROTO_UDP)
        {
            const struct udphdr* const udpHeader = (const struct udphdr*)(ipData + 0);
            const size_t udpHeaderSize = 8;
            const uint8_t* const udpData = ipData + udpHeaderSize;
            const size_t udpDataSize = ipDataSize - udpHeaderSize;
            const uint16_t srcPort = ntohs(udpHeader->uh_sport);
            const uint16_t dstPort = ntohs(udpHeader->uh_dport);
            const uint16_t udpLength = ntohs(udpHeader->uh_ulen);
            const uint16_t udpCheck = ntohs(udpHeader->uh_sum);
            const uint16_t udpCheckCalc = inetChecksum(ipData + 0, udpHeaderSize + udpDataSize);

            printf("\nUDP\n");
            printf("  src port  %i\n", (int)srcPort);
            printf("  dst port  %i\n", (int)dstPort);
            printf("  length    %i\n", (int)udpLength);
            printf("  check     %s0x%04x\033[90m 0x%04x\033[39m\n", (udpCheckCalc == 0 ? "" : "\033[31m"), (int)udpCheck, (int)udpCheckCalc);
            printf("  hdr size  %zu\n", udpHeaderSize);
            printf("  data size %zu\n", udpDataSize);

            cli::hexDump((const uint8_t*)udpHeader, udpHeaderSize);
            cli::hexDump(udpData, udpDataSize);
        }
        else if (ipProtocol == IPPROTO_ICMP)
        {
            const struct icmphdr* const icmpHeader = (const struct icmphdr*)(ipData + 0);
            const size_t icmpHeaderSize = 8;
            const uint8_t* const icmpData = ipData + icmpHeaderSize;
            const size_t icmpDataSize = ipDataSize - icmpHeaderSize;
            const uint8_t icmpType = icmpHeader->type;
            const uint8_t icmpCode = icmpHeader->code;
            const uint16_t icmpCheck = ntohs(icmpHeader->checksum);
            const uint16_t icmpCheckCalc = inetChecksum(ipData + 0, icmpHeaderSize + icmpDataSize);
            // ...

            printf("\nICMP\n");
            printf("  type      %i\n", (int)icmpType);
            printf("  code      %i\n", (int)icmpCode);
            printf("  check     %s0x%04x\033[90m 0x%04x\033[39m\n", (icmpCheckCalc == 0 ? "" : "\033[31m"), (int)icmpCheck, (int)icmpCheckCalc);
            printf("  hdr size  %zu\n", icmpHeaderSize);
            printf("  data size %zu\n", icmpDataSize);

            cli::hexDump((const uint8_t*)icmpHeader, icmpHeaderSize);
            cli::hexDump(icmpData, icmpDataSize);
        }
        else
        {
            printf("\nIP %s\n", ipptos(ipProtocol).c_str());
            cli::hexDump(ipData, ipDataSize);
        }
    }
    else if (ethProtocol == ETH_P_ARP)
    {
        const struct arphdr* const arpHeader = (const struct arphdr*)(ethData + 0);
        const size_t arpHeaderSize = 8;
        const uint16_t arpHwType = ntohs(arpHeader->ar_hrd);
        const uint16_t arpProtocol = ntohs(arpHeader->ar_pro);
        const uint8_t arpHwLength = arpHeader->ar_hln;
        const uint8_t arpProtoLen = arpHeader->ar_pln;
        const uint16_t arpOperation = ntohs(arpHeader->ar_op);
        const uint8_t* const arpData = ethData + arpHeaderSize;
        const size_t arpDataSize = ethDataSize - arpHeaderSize;

        printf("\nARP\n");
        printf("  hw type   %i\n", (int)arpHwType);
        printf("  proto     0x%04x %s\n", (int)arpProtocol, ethptos(arpProtocol).c_str());
        printf("  hw length %i\n", (int)arpHwLength);
        printf("  proto len %i\n", (int)arpProtoLen);
        printf("  operation %i\n", (int)arpOperation);
        printf("  hdr size  %zu\n", arpHeaderSize);
        printf("  data size %zu\n", arpDataSize);

        if ((arpHwLength == 6) && (arpProtoLen == 4))
        {
            struct arpdata
            {
                uint8_t s_mac[6]; // sender MAC address
                uint32_t s_ip;    // sender IP address
                uint8_t t_mac[6]; // target MAC address
                uint32_t t_ip;    // target IP address
            };

            const struct arpdata* const data = (const struct arpdata*)(arpData + 0);
            const mac::Addr sMac(data->s_mac);
            const mac::Addr dMac(data->t_mac);

            char ntopBuffer[32 + 15 + 1];

            printf("  src MAC   %s %s\n", sMac.toString().c_str(), app::lookupVendor(sMac).name().c_str());
            printf("  src addr  %s\n", inet_ntop(AF_INET, &(data->s_ip), ntopBuffer, sizeof(ntopBuffer)));

            printf("  dst MAC   %s %s\n", dMac.toString().c_str(), app::lookupVendor(dMac).name().c_str());
            printf("  dst addr  %s\n", inet_ntop(AF_INET, &(data->t_ip), ntopBuffer, sizeof(ntopBuffer)));
        }
        else
        {
            cli::hexDump((const uint8_t*)arpHeader, arpHeaderSize);
            cli::hexDump(arpData, arpDataSize);
        }
    }
    else if (ethProtocol == ETH_P_8021Q)
    {
        // extend the Ethernet header
        const uint16_t ethVlanTpid = ethProtocol;                                     // Tag Protocol Identifier
        const uint16_t ethVlanTci = omw::bigEndian::decode_ui16(sockData + ETH_HLEN); // Tag Control Information
        const int ethVlanPcp = ethVlanTci >> 13;                                      // Priority Code Point
        const int ethVlanDei = (ethVlanTci >> 12) & 0x01;                             // Drop Eligible Indicator
        const int ethVlanVid = ethVlanTci & 0x0FFF;                                   // VLAN-Identifier

        const uint16_t ethProtocolEff = omw::bigEndian::decode_ui16(sockData + ETH_HLEN) + 2; // effective protocol (EtherType)

        printf("  802.1Q VLAN Extended Header\n");
        printf("    PCP %i", ethVlanPcp);
        printf("    DEI %i", ethVlanDei);
        printf("    VID %i", ethVlanVid);

        if (ethProtocol != ethProtocolEff) { printf("  effective proto \033[31m0x%04x %s\033[39m\n", (int)ethProtocolEff, ethptos(ethProtocolEff).c_str()); }



        // interpret VLAN data
        printf("\nVLAN\n");
        cli::hexDump(ethData, ethDataSize);
    }
    else
    {
        printf("\nEtherType 0x%04x %s\n", (int)ethProtocol, ethptos(ethProtocol).c_str());
        cli::hexDump(ethData, ethDataSize);
    }

    return 0;
}

#include <mutex>
static std::mutex ___mtx;
void level2_sniffer()
{
    std::lock_guard<std::mutex> lg(___mtx); // force single threaded, easy fix stdout messup

    const int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sfd < 0)
    {
        cli::printErrno("failed to create socket", errno);
        return;
    }

    uint8_t sockData[ETH_FRAME_LEN + 4 /* VLAN */ + ETH_FCS_LEN];
    struct sockaddr sockSrcAddr;
    socklen_t sockSrcAddrSize = sizeof(sockSrcAddr);

    while (1)
    {
        const ssize_t sockDataSize = recvfrom(sfd, sockData, sizeof(sockData), 0, &sockSrcAddr, &sockSrcAddrSize);

        if (sockDataSize < 0) { cli::printErrno("recvfrom() failed", errno); }
        else
        {
            const int skipped = printL2Packet(sockData, sockDataSize, &sockSrcAddr);

            if (!skipped)
            {
                static int cnt = 0;
                printf("\n");
                printf("\033[90m%3i   ########################################\033[39m\n", ++cnt);
                printf("\n");
            }
        }
    }

    close(sfd);
}

#endif // PRJ_DEBUG



/**
 * @brief Address family to string.
 *
 * @param af `AF_*`
 */
std::string aftos(int af)
{
    std::string str;

    switch (af)
    {
        SWITCH_CASE_DEFINE_TO_STR(AF_UNSPEC);
        SWITCH_CASE_DEFINE_TO_STR(AF_LOCAL);
#if (AF_UNIX != AF_LOCAL)
        SWITCH_CASE_DEFINE_TO_STR(AF_UNIX);
#endif
        SWITCH_CASE_DEFINE_TO_STR(AF_INET);
        SWITCH_CASE_DEFINE_TO_STR(AF_AX25);
        SWITCH_CASE_DEFINE_TO_STR(AF_IPX);
        SWITCH_CASE_DEFINE_TO_STR(AF_X25);
        SWITCH_CASE_DEFINE_TO_STR(AF_INET6);
        SWITCH_CASE_DEFINE_TO_STR(AF_PACKET);

    default:
        str = "AF_#" + std::to_string(af);
        break;
    }

    return str;
}

/**
 * @brief Ethernet protocol to string
 *
 * @param proto `ETH_P_*`
 */
std::string ethptos(uint32_t proto)
{
    std::string str;

    constexpr uint32_t maxDataSize = 0x05dc;
    static_assert(maxDataSize <= ETH_P_802_3_MIN);

    if (proto <= maxDataSize) // IEEE 802.3 data length
    {
        str = "[len: " + std::to_string(proto) + ']';
    }
    else // Ethernet II EtherType
    {
        switch (proto)
        {
            SWITCH_CASE_DEFINE_TO_STR(ETH_P_LOOP);
            SWITCH_CASE_DEFINE_TO_STR(ETH_P_IP);
            SWITCH_CASE_DEFINE_TO_STR(ETH_P_X25);
            SWITCH_CASE_DEFINE_TO_STR(ETH_P_ARP);
            SWITCH_CASE_DEFINE_TO_STR(ETH_P_IPV6);

            SWITCH_CASE_DEFINE_TO_STR(ETH_P_PPP_MP);

        default:
            if (proto <= 0xFFFF) { str = "ETH_P_#" + omw::toHexStr((uint16_t)proto) + 'h'; }
            else { str = "ETH_P_#" + omw::toHexStr(proto) + 'h'; }
            break;
        }
    }

    return str;
}

/**
 * @brief IP protocol to string.
 *
 * @param proto `IPPROTO_*`
 */
std::string ipptos(uint32_t proto)
{
    std::string str;

    switch (proto)
    {
        SWITCH_CASE_DEFINE_TO_STR(IPPROTO_ICMP);
        SWITCH_CASE_DEFINE_TO_STR(IPPROTO_TCP);
        SWITCH_CASE_DEFINE_TO_STR(IPPROTO_UDP);

    default:
        if (proto <= 0xFF) { str = "IPPROTO_#" + omw::toHexStr((uint8_t)proto) + 'h'; }
        else { str = "IPPROTO_#" + omw::toHexStr(proto) + 'h'; }
        break;
    }

    return str;
}

/**
 * Converts a `sockaddr` to it's string representation, according to it's family.
 */
std::string sockaddrtos(const struct sockaddr* sa)
{
    std::string str;
    char buffer[INET6_ADDRSTRLEN];

    const int af = sa->sa_family;

    // maybe see also https://man7.org/linux/man-pages/man3/getnameinfo.3.html
    switch (af)
    {
    case AF_INET:
    {
        const struct sockaddr_in* const sa_in = ((const struct sockaddr_in*)sa);
        const in_port_t port = sa_in->sin_port;
        const char* const dst = inet_ntop(af, &(sa_in->sin_addr), buffer, sizeof(buffer));

        if (dst)
        {
            str = dst;
            if (port) { str += ':' + std::to_string(port); }
        }
    }
    break;

    case AF_INET6:
    {
        const struct sockaddr_in6* const sa_in6 = ((const struct sockaddr_in6*)sa);
        const in_port_t port = sa_in6->sin6_port;
        const char* const dst = inet_ntop(af, &(sa_in6->sin6_addr), buffer, sizeof(buffer));

        if (dst)
        {
            str = "";
            if (port) { str += '['; }
            str += dst;
            if (port) { str += "]:" + std::to_string(port); }
        }
    }
    break;

    default:
        str = "sockaddrtos " + aftos(af);
        break;
    }

    return str;
}

uint16_t inetChecksum(const uint8_t* data, size_t count)
{
    uint32_t sum = 0;

    while (count > 1)
    {
        sum += omw::bigEndian::decode_ui16(data);

        data += 2;
        count -= 2;
    }

    if (count > 0) { sum += (uint32_t)(*data) << 8; }

    while (sum & ~0x0FFFF) { sum = (sum & 0x0FFFF) + (sum >> 16); }

    return (uint16_t)(~sum);
}


#endif // OMW_PLAT_ *nix
