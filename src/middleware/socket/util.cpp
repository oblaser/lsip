/*
author          Oliver Blaser
date            10.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstdint>
#include <string>

#include "middleware/cli.h"
#include "project.h"
#include "util.h"

#include <omw/defs.h>
#include <omw/string.h>

#if (OMW_PLAT_UNIX || OMW_PLAT_LINUX || OMW_PLAT_APPLE) // *nix

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <ifaddrs.h>
#include <linux/if_packet.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>



#define SWITCH_CASE_DEFINE_TO_STR(_define) \
    case _define:                          \
        str = #_define;                    \
        break

#define SWITCH_CASE_DEFINE_TO_SUBSTR(_define, _pos) \
    case _define:                                   \
        str = (#_define) + (_pos);                  \
        break



int sock::getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr)
{
    struct ifaddrs* iflist = NULL;
    void* pmtaddr = NULL; // polymorph target address
    struct in6_addr ___taddr6;
    struct in6_addr* const taddr6 = &___taddr6;

    if (af == AF_INET) { pmtaddr = taddr; }
    else { pmtaddr = taddr6; } // is ok here, inet_pton() failes if af is neither AF_INET nor AF_INET6

    if (inet_pton(af, taddrStr, pmtaddr) != 1)
    {
        cli::printError("invalid " + sock::util::aftos(af) + " address: " + std::string(taddrStr));
        return -(__LINE__);
    }

    if (getifaddrs(&iflist) != 0)
    {
        cli::printErrno("failed to get network interfaces", errno);
        return -(__LINE__);
    }

    int err = 1;
    const struct ifaddrs* ifa = iflist;
    while (ifa && err)
    {
        if (ifa->ifa_addr && (ifa->ifa_addr->sa_family == af))
        {
            if (af == AF_INET)
            {
                const struct sockaddr_in* const sa_addr = (const struct sockaddr_in*)(ifa->ifa_addr);
                const struct sockaddr_in* const sa_mask = (const struct sockaddr_in*)(ifa->ifa_netmask);

                const uint32_t if_xor_t = ((sa_addr->sin_addr.s_addr) ^ (taddr->s_addr));
                const uint32_t xor_and_mask = (if_xor_t & (sa_mask->sin_addr.s_addr));

#if PRJ_DEBUG && 0
                printf("if addr: %08x %s\n", (sa_addr->sin_addr.s_addr), sock::util::inaddrtos(&(sa_addr->sin_addr)).c_str());
                printf("t  addr: %08x %s\n", (taddr->s_addr), sock::util::inaddrtos(taddr).c_str());
                printf("XOR      %08x %s\n", if_xor_t, sock::util::inaddrtos(if_xor_t).c_str());
                printf("if mask: %08x %s\n", (sa_mask->sin_addr.s_addr), sock::util::inaddrtos(&(sa_mask->sin_addr)).c_str());
                printf("AND      %08x %s\n", xor_and_mask, sock::util::inaddrtos(xor_and_mask).c_str());
                printf("\n");
#endif

                if (xor_and_mask == 0) // `taddr` is in the same subnet as the interface
                {
                    strncpy(ifname, ifa->ifa_name, ifnameSize);
                    *(ifname + ifnameSize - 1) = 0;

                    *ifaddr = *(ifa->ifa_addr);

                    err = 0;
                }
            }
            else if (af == AF_INET6)
            {
                // const struct sockaddr_in6* const sa_addr6 = ((const struct sockaddr_in6*)ifa->ifa_addr);
                // const struct sockaddr_in6* const sa_mask6 = ((const struct sockaddr_in6*)ifa->ifa_netmask);
                cli::printError("no IPv6 support in " + std::string(__func__));
            }
        }

#if PRJ_DEBUG && 0
        if (!err || 0)
        {
            static int cnt = 0;
            if (cnt++) { printf("\n"); }

            printf("%s\n", ifa->ifa_name);
            if (ifa->ifa_addr) { printf("    addr  %s\n", sock::util::sockaddrtos(ifa->ifa_addr).c_str()); }
            if (ifa->ifa_netmask) { printf("    mask  %s\n", sock::util::sockaddrtos(ifa->ifa_netmask).c_str()); }
            if (ifa->ifa_flags & IFF_BROADCAST) { printf("    broad %s\n", sock::util::sockaddrtos(ifa->ifa_broadaddr).c_str()); }
            if (ifa->ifa_flags & IFF_POINTOPOINT) { printf("    dst   %s\n", sock::util::sockaddrtos(ifa->ifa_dstaddr).c_str()); }
            // for `ifa->ifa_data` see https://man7.org/linux/man-pages/man3/getifaddrs.3.html
        }
#endif // PRJ_DEBUG

        ifa = ifa->ifa_next;
    }

    freeifaddrs(iflist);

    return err;
}


int sock::sendArpRequest(const char* addrStr, const char* ifname, const struct sockaddr* ifaddr, const struct in_addr* taddr)
{
    const int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0)
    {
        cli::printErrno("failed to create socket", errno);
        return -(__LINE__);
    }

    struct ifreq ifreqifindex; // interface index
    strncpy(ifreqifindex.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifreqifindex) < 0)
    {
        cli::printErrno("failed to get index of interface \"" + std::string(ifname) + '"', errno);
        close(sockfd);
        return -(__LINE__);
    }

    struct ifreq ifreqha; // hardware address
    memset(&ifreqha, 0, sizeof(ifreqha));
    strncpy(ifreqha.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifreqha) < 0)
    {
        cli::printErrno("failed to get MAC address of interface \"" + std::string(ifname) + '"', errno);
        close(sockfd);
        return -(__LINE__);
    }

    const uint8_t* const localhaddr = (uint8_t*)(ifreqha.ifr_hwaddr.sa_data);       // local hardware address
    const struct in_addr* const localpaddr = &(((sockaddr_in*)(ifaddr))->sin_addr); // local protocol address
    const struct in_addr* const targetpaddr = taddr;                                // target protocol address

#if PRJ_DEBUG && 0
    {
        // also works with `void*`
        // const void* const localhaddr = ifreqha.ifr_hwaddr.sa_data;
        // const void* const localpaddr = &(((sockaddr_in*)(ifaddr))->sin_addr);

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

    constexpr size_t bufferSize = ETH_HLEN + sizeof(struct ether_arp) + /* padding */ 18;
    static_assert(bufferSize >= ETH_ZLEN, "layer 2 frame has to be at leaset 60 octets + 32bit CRC");
    uint8_t buffer[bufferSize];
    memset(buffer, 0, bufferSize);

    struct ethhdr* ethHeader = (struct ethhdr*)(buffer + 0);
    memset(ethHeader->h_dest, 0xFF, ETH_ALEN); // broadcast
    memcpy(ethHeader->h_source, &(ifreqha.ifr_hwaddr.sa_data), ETH_ALEN);
    ethHeader->h_proto = htons(ETH_P_ARP);

    struct ether_arp* ethArp = (struct ether_arp*)(buffer + ETH_HLEN);
    ethArp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    ethArp->ea_hdr.ar_pro = htons(ETH_P_IP);
    ethArp->ea_hdr.ar_hln = ETH_ALEN;
    ethArp->ea_hdr.ar_pln = sizeof(((struct ether_arp*)0)->arp_spa);
    ethArp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(ethArp->arp_sha, localhaddr, ETH_ALEN);
    memcpy(ethArp->arp_spa, localpaddr, sizeof(((struct ether_arp*)0)->arp_spa));
    memset(ethArp->arp_tha, 0, ETH_ALEN);
    memcpy(ethArp->arp_tpa, targetpaddr, sizeof(((struct ether_arp*)0)->arp_tpa));

#if PRJ_DEBUG && 0
    printL2Packet(buffer, bufferSize, NULL);
#endif



    // send ARP packet

    ssize_t n, transferred;
    struct sockaddr_ll dst_addr;
    dst_addr.sll_family = AF_PACKET;
    dst_addr.sll_protocol = htons(ETH_P_ARP);
    dst_addr.sll_ifindex = ifreqifindex.ifr_ifindex;
    dst_addr.sll_hatype = htons(ARPHRD_ETHER);
    // dst_addr.sll_pkttype = PACKET_BROADCAST;
    dst_addr.sll_pkttype = PACKET_OTHERHOST;
    dst_addr.sll_halen = ETH_ALEN;
    dst_addr.sll_addr[6] = 0x00;
    dst_addr.sll_addr[7] = 0x00;

    transferred = 0;
    while ((size_t)transferred < bufferSize)
    {
        n = sendto(sockfd, buffer, bufferSize, 0, (struct sockaddr*)(&dst_addr), sizeof(dst_addr));
        if (n < 0)
        {
            cli::printErrno("failed to send ARP packet for target " + std::string(addrStr), errno);
            close(sockfd);
            return -(__LINE__);
        }

        transferred += n;
    }



#if PRJ_DEBUG && 0
    printf("sent ARP to %s\n", sock::util::inaddrtos(taddr).c_str());
#endif



    close(sockfd);

    return 0;
}

int sock::sendEchoRequest(const struct in_addr* taddr)
{
    const int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        cli::printErrno("failed to create socket", errno);
        return -(__LINE__);
    }



    // serialise ICMP packet

    constexpr size_t bufferSize = sizeof(struct icmphdr);
    uint8_t buffer[bufferSize];
    memset(buffer, 0, bufferSize);

    struct icmphdr* icmpHeader = (struct icmphdr*)(buffer + 0);
    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;

    // optional data ...

    icmpHeader->checksum = htons(sock::util::inet_checksum(buffer, bufferSize));



    // send ICMP packet

    ssize_t n, transferred;
    const struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr = *taddr,
    };

    transferred = 0;
    while ((size_t)transferred < bufferSize)
    {
        n = sendto(sockfd, buffer, bufferSize, 0, (struct sockaddr*)(&dst_addr), sizeof(dst_addr));
        if (n < 0)
        {
            cli::printErrno("failed to send ICMP packet for target " + sock::util::inaddrtos(taddr), errno);
            close(sockfd);
            return -(__LINE__);
        }

        transferred += n;
    }



#if PRJ_DEBUG && 0
    printf("sent Echo to %s\n", sock::util::inaddrtos(taddr).c_str());
#endif



    close(sockfd);

    return 0;
}



struct sock::util::ippseudohdr* sock::util::ippseudohdr_init(struct sock::util::ippseudohdr* dst, const struct iphdr* iphdr)
{
    struct sockaddr_in* dst_saddr = (struct sockaddr_in*)(&(dst->saddr));
    dst_saddr->sin_family = AF_INET;
    dst_saddr->sin_port = 0;
    dst_saddr->sin_addr.s_addr = iphdr->saddr;

    struct sockaddr_in* dst_daddr = (struct sockaddr_in*)(&(dst->daddr));
    dst_daddr->sin_family = AF_INET;
    dst_daddr->sin_port = 0;
    dst_daddr->sin_addr.s_addr = iphdr->daddr;

    dst->protocol = iphdr->protocol;

    dst->length = ntohs(iphdr->tot_len) - ((uint16_t)(iphdr->ihl) * 4);

    return dst;
}

uint16_t sock::util::inet_checksum(const uint8_t* data, size_t count)
{
    uint32_t sum = 0;

    while (count > 1)
    {
        sum += (((uint16_t)(*data) << 8) | (uint16_t)(*(data + 1)));

        data += 2;
        count -= 2;
    }

    if (count > 0) { sum += (uint32_t)(*data) << 8; }

    sum = (sum & 0x0000FFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

void sock::util::inet_checksum_update(uint32_t* sum, const uint8_t* data, size_t count)
{
    while (count > 1)
    {
        *sum += (((uint16_t)(*data) << 8) | (uint16_t)(*(data + 1)));

        data += 2;
        count -= 2;
    }

    if (count > 0) { *sum += (uint32_t)(*data) << 8; }
}

void sock::util::inet_checksum_update_ippseudohdr(uint32_t* sum, const struct sock::util::ippseudohdr* pseudoHdr)
{
    const int af = pseudoHdr->saddr.ss_family;

    switch (af)
    {
    case AF_INET:
    {
        const struct sockaddr_in* saddr = (struct sockaddr_in*)(&(pseudoHdr->saddr));
        const struct sockaddr_in* daddr = (struct sockaddr_in*)(&(pseudoHdr->daddr));

        inet_checksum_update32n(sum, saddr->sin_addr.s_addr);
        inet_checksum_update32n(sum, daddr->sin_addr.s_addr);
        inet_checksum_update16h(sum, (uint16_t)(pseudoHdr->protocol));
        inet_checksum_update16h(sum, (uint16_t)(pseudoHdr->length));
    }
    break;

    case AF_INET6:
    {
        const struct sockaddr_in6* saddr = (struct sockaddr_in6*)(&(pseudoHdr->saddr));
        const struct sockaddr_in6* daddr = (struct sockaddr_in6*)(&(pseudoHdr->daddr));

        fprintf(stderr, SGR_BRED "error:" SGR_DEFAULT " %s does not yet support IPv6", __func__);
        (void)saddr;
        (void)daddr;
        inet_checksum_update32h(sum, pseudoHdr->length);
        inet_checksum_update16h(sum, (uint16_t)(pseudoHdr->protocol));
    }
    break;

    default:
        fprintf(stderr, SGR_BRED "error:" SGR_DEFAULT " %s does not support %s", __func__, aftos(af).c_str());
        break;
    }
}

uint16_t inet_checksum_final(uint32_t* sum)
{
    *sum = ~((*sum & 0x0000FFFF) + (*sum >> 16));
    return (uint16_t)(*sum);
}


std::string sock::util::aftos(int af)
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

std::string sock::util::ethptos(uint32_t proto)
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

std::string sock::util::ipptos(uint32_t proto)
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

std::string sock::util::icmpttos(uint8_t type)
{
    std::string str;

    switch (type)
    {
        SWITCH_CASE_DEFINE_TO_STR(ICMP_ECHOREPLY);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_DEST_UNREACH);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_SOURCE_QUENCH);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_REDIRECT);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_ECHO);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_TIME_EXCEEDED);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_PARAMETERPROB);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_TIMESTAMP);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_TIMESTAMPREPLY);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_INFO_REQUEST);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_INFO_REPLY);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_ADDRESS);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_ADDRESSREPLY);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_EXT_ECHO);
        SWITCH_CASE_DEFINE_TO_STR(ICMP_EXT_ECHOREPLY);

    default:
    {
        static_assert(ICMP_TYPE_STRLEN >= 12, "increase ICMP_TYPE_STRLEN");
        str = "ICMP_T#" + omw::toHexStr(type) + 'h';
    }
    break;
    }

    return str;
}

std::string sock::util::icmpctos(uint8_t type, uint8_t code)
{
    std::string str;

#define SWITCH_CASE_ICMPCTOS_DEFAULT()                                      \
    default:                                                                \
        static_assert(ICMP_CODE_STRLEN >= 12, "increase ICMP_CODE_STRLEN"); \
        str = "ICMP_C#" + omw::toHexStr(type) + 'h';                        \
        break



    switch (type)
    {
    case ICMP_ECHOREPLY:
    case ICMP_SOURCE_QUENCH:
    case ICMP_ECHO:
    case 9:
    case 10:
    case ICMP_PARAMETERPROB:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_INFO_REQUEST:
    case ICMP_INFO_REPLY:
    case ICMP_ADDRESS:
    case ICMP_ADDRESSREPLY:
    case 30:
    case ICMP_EXT_ECHO:
        // these don't use codes
        str = "";
        break;

    case ICMP_DEST_UNREACH:
        switch (code)
        {
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_NET_UNREACH, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_HOST_UNREACH, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_PROT_UNREACH, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_PORT_UNREACH, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_FRAG_NEEDED, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_SR_FAILED, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_NET_UNKNOWN, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_HOST_UNKNOWN, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_HOST_ISOLATED, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_NET_ANO, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_HOST_ANO, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_NET_UNR_TOS, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_HOST_UNR_TOS, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_PKT_FILTERED, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_PREC_VIOLATION, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_PREC_CUTOFF, 5);

            SWITCH_CASE_ICMPCTOS_DEFAULT();
        }
        break;

    case ICMP_REDIRECT:
        switch (code)
        {
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_REDIR_NET, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_REDIR_HOST, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_REDIR_NETTOS, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_REDIR_HOSTTOS, 5);

            SWITCH_CASE_ICMPCTOS_DEFAULT();
        }
        break;

    case ICMP_TIME_EXCEEDED:
        switch (code)
        {
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_EXC_TTL, 5);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_EXC_FRAGTIME, 5);

            SWITCH_CASE_ICMPCTOS_DEFAULT();
        }
        break;

    case ICMP_EXT_ECHOREPLY:
        switch (code)
        {
        case 0:
            str = "no error";
            break;

            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_EXT_CODE_MAL_QUERY, 14);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_EXT_CODE_NO_IF, 14);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_EXT_CODE_NO_TABLE_ENT, 14);
            SWITCH_CASE_DEFINE_TO_SUBSTR(ICMP_EXT_CODE_MULT_IFS, 14);

            SWITCH_CASE_ICMPCTOS_DEFAULT();
        }
        break;


        SWITCH_CASE_ICMPCTOS_DEFAULT();
    }

#undef SWITCH_CASE_ICMPCTOS_DEFAULT

    return str;
}

std::string sock::util::sockaddrtos(const struct sockaddr* sa)
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
        str = sock::util::aftos(af);
        break;

    default:
        str = "sockaddrtos " + sock::util::aftos(af);
        break;
    }

    return str;
}

std::string sock::util::inaddrtos(const struct in_addr* addr)
{
    std::string str;
    char buffer[INET_ADDRSTRLEN];

    const char* const dst = inet_ntop(AF_INET, addr, buffer, sizeof(buffer));

    if (dst) { str = dst; }

    return str;
}

std::string sock::util::inaddrtos(in_addr_t addr)
{
    const struct in_addr tmp = {
        .s_addr = addr,
    };

    return sock::util::inaddrtos(&tmp);
}



#endif // OMW_PLAT_ *nix
