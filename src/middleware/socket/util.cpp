/*
author          Oliver Blaser
date            10.08.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstdint>
#include <string>

#include "util.h"

#include <omw/defs.h>
#include <omw/string.h>

#if (OMW_PLAT_UNIX || OMW_PLAT_LINUX || OMW_PLAT_APPLE) // *nix

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <unistd.h>



#define SWITCH_CASE_DEFINE_TO_STR(_define) \
    case _define:                          \
        str = #_define;                    \
        break



std::string sock::aftos(int af)
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

std::string sock::ethptos(uint32_t proto)
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

std::string sock::ipptos(uint32_t proto)
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

std::string sock::sockaddrtos(const struct sockaddr* sa)
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
        str = sock::aftos(af);
        break;

    default:
        str = "sockaddrtos " + sock::aftos(af);
        break;
    }

    return str;
}



#endif // OMW_PLAT_ *nix
