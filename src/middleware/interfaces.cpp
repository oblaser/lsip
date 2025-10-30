/*
author          Oliver Blaser
date            29.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <string>
#include <vector>

#include "interfaces.h"
#include "middleware/cli.h"
#include "middleware/socket/util.h"
#include "project.h"

#define MWIP_DONT_DEF_NAMESPACE_IP (1)
#include "middleware/ip-addr.h"

#include <omw/defs.h>

#if OMW_PLAT_WIN
#else // OMW_PLAT_WIN

#include <ifaddrs.h>

#include <net/if.h>
#include <netinet/in.h>

#include <sys/types.h>

#endif // OMW_PLAT_WIN



#if OMW_PLAT_WIN

std::vector<std::string> getIfIpRanges()
{
    cli::printError(std::string(__FUNCTION__) + " not implemented, an address range has to be specified");
    return std::vector<std::string>()
}

#else // OMW_PLAT_WIN

std::vector<std::string> getIfIpRanges()
{
    std::vector<std::string> ranges;

    struct ifaddrs* iflist = NULL;

    if (getifaddrs(&iflist) != 0)
    {
        cli::printErrno("failed to get network interfaces", errno);
        return std::vector<std::string>();
    }

    const struct ifaddrs* ifa = iflist;
    while (ifa)
    {
        const int af = (ifa->ifa_addr ? ifa->ifa_addr->sa_family : AF_UNSPEC);

        if (af == AF_INET)
        {
            const struct sockaddr_in* const sa_addr = (const struct sockaddr_in*)(ifa->ifa_addr);
            const struct sockaddr_in* const sa_mask = (const struct sockaddr_in*)(ifa->ifa_netmask);

            const auto addr = mwip::Addr4(ntohl(sa_addr->sin_addr.s_addr));
            const auto mask = mwip::SubnetMask4(mwip::Addr4(ntohl(sa_mask->sin_addr.s_addr)));

            if (addr != mwip::Addr4(127, 0, 0, 1))
            {
                const auto rangeStr = (addr & mask).toString() + '/' + std::to_string(mask.prefixSize());

                ranges.push_back(rangeStr);
            }
        }

#if PRJ_DEBUG && 0
        if ((af == AF_INET) || 0)
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

    if (ranges.empty()) { cli::printError("no interface with IPv4 address found"); }

    return ranges;
}

#endif // OMW_PLAT_WIN
