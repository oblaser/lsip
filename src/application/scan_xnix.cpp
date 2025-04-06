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
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ip.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ifaddrs.h>
#include <unistd.h>


#define SWITCH_CASE_DEFINE_TO_STR(_define) \
    case _define:                          \
        str = #_define;                    \
        break



/**
 * @brief Extended 802.1Q VLAN ethernet header
 */
struct ethhdr8021Q
{
    uint8_t ehq_dest[ETH_ALEN];
    uint8_t ehq_source[ETH_ALEN];
    uint16_t ehq_tpid;
    uint16_t ehq_tci;
    uint16_t ehq_proto;
} __attribute__((packed, aligned(1)));

#define ARP_HLEN 6 // hardware address length
#define ARP_PLEN 4 // protocol address length

/**
 * @brief IPv4 ARP data container.
 *
 * - hardware address: MAC/EUI48
 * - protocol address: IPv4 address
 */
struct arpdata
{
    uint8_t ar_sha[ARP_HLEN]; // sender hardware address
    uint8_t ar_spa[ARP_PLEN]; // sender protocol address
    uint8_t ar_tha[ARP_HLEN]; // target hardware address
    uint8_t ar_tpa[ARP_PLEN]; // target protocol address
} __attribute__((packed, aligned(1)));

static_assert(ARP_HLEN == ETH_ALEN);
static_assert(ARP_PLEN == sizeof(struct in_addr));



static int getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr);
static std::string aftos(int af);
static std::string ethptos(uint32_t proto);
static std::string ipptos(uint32_t proto);
static std::string sockaddrtos(const struct sockaddr* sa);
static inline std::string sockaddrtos(const struct sockaddr_in* sa) { return sockaddrtos((const struct sockaddr*)sa); }
static inline std::string sockaddrtos(const struct sockaddr_in6* sa) { return sockaddrtos((const struct sockaddr*)sa); }
static uint16_t inetChecksum(const uint8_t* data, size_t count);



#if PRJ_DEBUG && 1 // L2 sniffer

#include "application/vendor-lookup.h"

#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static int printL2Packet(const uint8_t* sockData, size_t sockDataSize, const struct sockaddr* sockSrcAddr)
{
    const struct ethhdr* const ethHeader = (const struct ethhdr*)(sockData + 0);
    const mac::Addr srcMac(ethHeader->h_source);
    const mac::Addr dstMac(ethHeader->h_dest);
    uint16_t ethProtocol = ntohs(ethHeader->h_proto);
    const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
    const uint8_t* const ethData = sockData + ethHeaderSize;
    const size_t ethDataSize = sockDataSize - ethHeaderSize;

#if 0 // filter
    if (((srcMac & mac::EUI48::oui28_mask) == mac::EUI48(0xB8D812600000)) || //
        (ethProtocol != ETH_P_ARP))                                          //
    {
        return 1;
    }
#endif

#if 0
    if (sockSrcAddr)
    {
        // looks like this is always the AF used when creating the socket
        printf("recvfrom() src addr %s: %s\n", aftos(sockSrcAddr->sa_family).c_str(), sockaddrtos(sockSrcAddr).c_str());
        cli::hexDump((uint8_t*)(sockSrcAddr->sa_data), sizeof(sockSrcAddr->sa_data));

        printf("\nrecvfrom() data [%zu]:\n", sockDataSize);
        cli::hexDump(sockData, sockDataSize);

        printf("\n");
    }
#endif

    printf("Ethernet\n");
    printf("  src   %s %s\n", srcMac.toString().c_str(), app::lookupVendor(srcMac).name().c_str());
    printf("  dst   %s %s\n", dstMac.toString().c_str(), app::lookupVendor(dstMac).name().c_str());

    if (ethProtocol == ETH_P_8021Q) // not tested
    {
        const struct ethhdr8021Q* const ethHeader = (const struct ethhdr8021Q*)(sockData + 0);
        const uint16_t ethVlanTpid = ntohs(ethHeader->ehq_tpid); // Tag Protocol Identifier
        const uint16_t ethVlanTci = ntohs(ethHeader->ehq_tci);   // Tag Control Information
        const int ethVlanPcp = ethVlanTci >> 13;                 // Priority Code Point
        const int ethVlanDei = (ethVlanTci >> 12) & 0x01;        // Drop Eligible Indicator
        const int ethVlanVid = ethVlanTci & 0x0FFF;              // VLAN-Identifier
        ethProtocol = ntohs(ethHeader->ehq_proto);

        printf("  802.1Q VLAN Extended Header (0x%04x)\n", (int)ethVlanTpid);
        printf("    PCP %i", ethVlanPcp);
        printf("    DEI %i", ethVlanDei);
        printf("    VID %i", ethVlanVid);
    }

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
        printf("  src addr  %s = 0x%08x\n", inet_ntop(AF_INET, &(ipHeader->saddr), ntopBuffer, sizeof(ntopBuffer)), srcIp);
        printf("  dst addr  %s = 0x%08x\n", inet_ntop(AF_INET, &(ipHeader->daddr), ntopBuffer, sizeof(ntopBuffer)), dstIp);
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

            printf("\033[38;2;255;194;255m");

            printf("\nTCP\n");
            printf("  src port  %i\n", (int)srcPort);
            printf("  dst port  %i\n", (int)dstPort);
            printf("  sequence  %u\n", tcpSeq);
            printf("  data off  %i\n", (int)tcpDataOff);
            printf("  flags     0x%02x\n", (int)tcpFlags);
            printf("  hdr size  %zu\n", tcpHeaderSize);
            printf("  data size %zu\n", tcpDataSize);

            cli::hexDump((const uint8_t*)tcpHeader, tcpHeaderSize);
            printf("\n");
            cli::hexDump(tcpData, tcpDataSize);

            printf("\033[39m");
            fflush(stdout);
        }
        else if (ipProtocol == IPPROTO_UDP)
        {
            const struct udphdr* const udpHeader = (const struct udphdr*)(ipData + 0);
            const size_t udpHeaderSize = 8;
            const uint16_t srcPort = ntohs(udpHeader->uh_sport);
            const uint16_t dstPort = ntohs(udpHeader->uh_dport);
            const uint16_t udpLength = ntohs(udpHeader->uh_ulen);
            const uint16_t udpCheck = ntohs(udpHeader->uh_sum);
            const uint8_t* const udpData = ipData + udpHeaderSize;
            const size_t udpDataSize = udpLength - udpHeaderSize;
            const uint8_t* const padData = ipData + udpHeaderSize + udpDataSize; // potential padding
            const size_t padDataSize = ipDataSize - udpHeaderSize - udpDataSize; // potential padding

            const uint16_t udpCheckCalc = inetChecksum(ipData + 0, udpHeaderSize + udpDataSize);

            printf("\033[38;2;156;227;255m");

            printf("\nUDP\n");
            printf("  src port  %i\n", (int)srcPort);
            printf("  dst port  %i\n", (int)dstPort);
            printf("  length    %i\n", (int)udpLength);
            printf("  check     0x%04x, calculated: 0x%04x\n", (int)udpCheck, (int)udpCheckCalc);
            printf("  hdr size  %zu\n", udpHeaderSize);
            printf("  data size %zu\n", udpDataSize);

            cli::hexDump((const uint8_t*)udpHeader, udpHeaderSize);
            printf("\n");
            cli::hexDump(udpData, udpDataSize);

            printf("\033[39m");
            fflush(stdout);

            for (size_t i = 0; i < padDataSize; ++i)
            {
                if (padData[i])
                {
                    printf("\nPadding:\n");
                    cli::hexDump(padData, padDataSize);
                    break;
                }
            }
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
            printf("\n");
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
        const size_t arpDataSize = 2 * arpHwLength + 2 * arpProtoLen;
        const uint8_t* const padData = ethData + arpHeaderSize + arpDataSize; // padding
        const size_t padDataSize = ethDataSize - arpHeaderSize - arpDataSize; // padding

        printf("\033[38;2;244;221;153m");

        printf("\nARP\n");
        printf("  hw type   %i\n", (int)arpHwType);
        printf("  proto     0x%04x %s\n", (int)arpProtocol, ethptos(arpProtocol).c_str());
        printf("  hw length %i\n", (int)arpHwLength);
        printf("  proto len %i\n", (int)arpProtoLen);
        printf("  operation %i %s\n", (int)arpOperation, (arpOperation == 1 ? "request" : (arpOperation == 2 ? "reply" : "")));
        printf("  hdr size  %zu\n", arpHeaderSize);
        printf("  data size %zu\n", arpDataSize);

        cli::hexDump((const uint8_t*)arpHeader, arpHeaderSize);
        printf("\n");

        if ((arpHwType == ARPHRD_ETHER) && (arpProtocol == ETH_P_IP) && (arpHwLength == ARP_HLEN) && (arpProtoLen == ARP_PLEN))
        {
            const struct arpdata* const data = (const struct arpdata*)(arpData + 0);
            const mac::Addr sMac(data->ar_sha);
            const mac::Addr tMac(data->ar_tha);

            char ntopBuffer[32 + 15 + 1];

            printf("  sender MAC   %s %s\n", sMac.toString().c_str(), app::lookupVendor(sMac).name().c_str());
            printf("  sender addr  %s\n", inet_ntop(AF_INET, &(data->ar_spa), ntopBuffer, sizeof(ntopBuffer)));
            printf("  target MAC   %s %s\n", tMac.toString().c_str(), app::lookupVendor(tMac).name().c_str());
            printf("  target addr  %s\n", inet_ntop(AF_INET, &(data->ar_tpa), ntopBuffer, sizeof(ntopBuffer)));
            printf("\n");
            cli::hexDump(arpData, arpDataSize);
        }
        else { cli::hexDump(arpData, arpDataSize); }

        printf("\033[39m");
        fflush(stdout);

        for (size_t i = 0; i < padDataSize; ++i)
        {
            if (padData[i])
            {
                printf("\nPadding:\n");
                cli::hexDump(padData, padDataSize);
                break;
            }
        }
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

    uint8_t sockData[ETH_FRAME_LEN + 4 /* VLAN */]; // FCS is not passed up to userspace
    struct sockaddr sockSrcAddr;
    socklen_t sockSrcAddrSize = sizeof(sockSrcAddr);

    while (1)
    {
        memset(sockData, 0, sizeof(sockData));

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

#endif // PRJ_DEBUG - L2 sniffer



/**
 * @param addrStr IPv4 address, format: `a.b.c.d`
 * @param macBuffer uint8_t[6] MAC address buffer
 * @return 0 on success, negative on error, positive on timeout
 */
int impl_scan_xnix(const char* addrStr, uint8_t* macBuffer)
{
    char ifname[50];
    struct sockaddr ifaddr;
    struct in_addr taddr;
    if (getifaddr(ifname, sizeof(ifname), &ifaddr, AF_INET, addrStr, &taddr) != 0)
    {
        // can't use ARP on remote networks
        return -(__LINE__);
    }

    const int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sfd < 0)
    {
        cli::printErrno("failed to create socket", errno);
        return -(__LINE__);
    }

    struct ifreq ifreqha; // hardware address
    memset(&ifreqha, 0, sizeof(ifreqha));
    strncpy(ifreqha.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sfd, SIOCGIFHWADDR, &ifreqha) < 0)
    {
        cli::printErrno("failed to get MAC address of interface \"" + std::string(ifname) + '"', errno);
        return -(__LINE__);
    }

    const uint8_t* const localhaddr = (uint8_t*)(ifreqha.ifr_hwaddr.sa_data);        // local hardware address
    const struct in_addr* const localpaddr = &(((sockaddr_in*)(&ifaddr))->sin_addr); // local protocol address
    const struct in_addr* const targetpaddr = &taddr;                                // target protocol address

#if PRJ_DEBUG && 0
    {
        // also works with `void*`
        // const void* const localhaddr = ifreqha.ifr_hwaddr.sa_data;
        // const void* const localpaddr = &(((sockaddr_in*)(&ifaddr))->sin_addr);

        const struct in_addr addr = *((struct in_addr*)localpaddr);
        // const uint32_t ip = *((uint32_t*)localpaddr);
        const uint32_t ip = ntohl(*((uint32_t*)localpaddr));
        const uint32_t a = ip >> 24;
        const uint32_t b = (ip >> 16) & 0x0FF;
        const uint32_t c = (ip >> 8) & 0x0FF;
        const uint32_t d = ip & 0x0FF;

        char addrStr[100];
        printf("%s   %s   %u.%u.%u.%u 0x%08x, %s\n\n", ifname, mac::EUI48((uint8_t*)localhaddr).toString().c_str(), a, b, c, d, ip,
               inet_ntop(AF_INET, &addr, addrStr, sizeof(addrStr)));
    }
#endif



    // serialise ARP packet

    constexpr size_t bufferSize = ETH_HLEN + sizeof(struct arphdr) + sizeof(struct arpdata) + /* padding */ 18;
    static_assert(bufferSize >= ETH_ZLEN, "layer 2 frame has to be at leaset 60 octets + 32bit CRC");
    uint8_t buffer[bufferSize];
    memset(buffer, 0, bufferSize);

    struct ethhdr* ethHeader = (struct ethhdr*)(buffer + 0);
    memset(ethHeader->h_dest, 0xFF, ETH_ALEN); // broadcast
    memcpy(ethHeader->h_source, &(ifreqha.ifr_hwaddr.sa_data), ETH_ALEN);
    ethHeader->h_proto = htons(ETH_P_ARP);

    struct arphdr* arpHeader = (struct arphdr*)(buffer + ETH_HLEN);
    arpHeader->ar_hrd = htons(ARPHRD_ETHER);
    arpHeader->ar_pro = htons(ETH_P_IP);
    arpHeader->ar_hln = ARP_HLEN;
    arpHeader->ar_pln = ARP_PLEN;
    arpHeader->ar_op = htons(ARPOP_REQUEST);

    struct arpdata* arpData = (struct arpdata*)(buffer + ETH_HLEN + sizeof(struct arphdr));
    memcpy(arpData->ar_sha, localhaddr, ARP_HLEN);
    memcpy(arpData->ar_spa, localpaddr, ARP_PLEN);
    memset(arpData->ar_tha, 0, ARP_HLEN);
    memcpy(arpData->ar_tpa, targetpaddr, ARP_PLEN);


    printL2Packet(buffer, bufferSize, NULL);


    close(sfd);

#if PRJ_DEBUG && 1
    for (size_t i = 0; i < 6; ++i) { macBuffer[i] = 0xFF; }
    return 0;
#else // PRJ_DEBUG
#error "TODO implement" // read doc for return codes
#endif // PRJ_DEBUG
}



/**
 * Get the network interface for wich `(if.addr ^ dst.addr) & if.mask` is zero.
 *
 * Currently only supports IPv4.
 *
 * If no interface matches, error is returned.
 *
 * @param [out] ifname
 * @param ifnameSize
 * @param [out] ifaddr
 * @param af Used to filter the list of interfaces
 * @param taddrStr Used to filter the list of interfaces
 * @param [out] taddr
 * @return 0 on success, negative on error
 */
int getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr)
{
    struct ifaddrs* iflist = NULL;
    void* pmtaddr = NULL; // polymorph target address
    struct in6_addr ___taddr6;
    struct in6_addr* const taddr6 = &___taddr6;

    if (af == AF_INET) { pmtaddr = taddr; }
    else { pmtaddr = taddr6; } // is ok here, inet_pton() failes if af is neither AF_INET nor AF_INET6

    if (inet_pton(af, taddrStr, pmtaddr) != 1)
    {
        cli::printError("invalid " + aftos(af) + " address: " + std::string(taddrStr));
        return -(__LINE__);
    }

    if (getifaddrs(&iflist) != 0)
    {
        cli::printErrno("failed to get network interfaces", errno);
        return -(__LINE__);
    }

    int err = -1;
    const struct ifaddrs* ifa = iflist;
    while (ifa && err)
    {
        if (ifa->ifa_addr && (ifa->ifa_addr->sa_family == af))
        {
            if (af == AF_INET)
            {
                const struct sockaddr_in* const sa_addr = ((const struct sockaddr_in*)ifa->ifa_addr);
                const struct sockaddr_in* const sa_mask = ((const struct sockaddr_in*)ifa->ifa_netmask);

                if ((((sa_addr->sin_addr.s_addr) ^ (taddr->s_addr)) & (sa_mask->sin_addr.s_addr)) == 0)
                {
                    strncpy(ifname, ifa->ifa_name, ifnameSize);
                    *(ifname + ifnameSize - 1) = 0;

                    *ifaddr = *(ifa->ifa_addr);

                    err = 0;
                }
            }
            else if (af == AF_INET6)
            {
                const struct sockaddr_in6* const sa_addr6 = ((const struct sockaddr_in6*)ifa->ifa_addr);
                const struct sockaddr_in6* const sa_mask6 = ((const struct sockaddr_in6*)ifa->ifa_netmask);
                cli::printError("no IPv6 support in " + std::string(__func__));
            }
        }

#if PRJ_DEBUG && 0
        if (!err || 0)
        {
            static int cnt = 0;
            if (cnt++) { printf("\n"); }

            printf("%s\n", ifa->ifa_name);
            if (ifa->ifa_addr) { printf("    addr  %s\n", sockaddrtos(ifa->ifa_addr).c_str()); }
            if (ifa->ifa_netmask) { printf("    mask  %s\n", sockaddrtos(ifa->ifa_netmask).c_str()); }
            if (ifa->ifa_flags & IFF_BROADCAST) { printf("    broad %s\n", sockaddrtos(ifa->ifa_broadaddr).c_str()); }
            if (ifa->ifa_flags & IFF_POINTOPOINT) { printf("    dst   %s\n", sockaddrtos(ifa->ifa_dstaddr).c_str()); }
            // for `ifa->ifa_data` see https://man7.org/linux/man-pages/man3/getifaddrs.3.html
        }
#endif // PRJ_DEBUG

        ifa = ifa->ifa_next;
    }

    freeifaddrs(iflist);

    return err;
}

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

    case AF_PACKET:
        str = aftos(af);
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
