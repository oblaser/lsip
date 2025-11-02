/*
author          Oliver Blaser
date            29.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <algorithm>
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

// clang-format off
#include <winsock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>

// these libraries are already added in scan.cpp
//#pragma comment(lib, "iphlpapi.lib")
//#pragma comment(lib, "ws2_32.lib")
// clang-format on

#else // OMW_PLAT_WIN

#include <ifaddrs.h>

#include <net/if.h>
#include <netinet/in.h>

#include <sys/types.h>

#endif // OMW_PLAT_WIN



class IfAddr4
{
public:
    IfAddr4()
        : addr(), mask()
    {}

    IfAddr4(const mwip::Addr4& _addr, const mwip::SubnetMask4& _mask)
        : addr(_addr), mask(_mask)
    {}

    virtual ~IfAddr4() {}

    mwip::Addr4 addr;
    mwip::SubnetMask4 mask;
};



#if OMW_PLAT_WIN

static int getIfAddrs(std::vector<IfAddr4>& ifAddrs)
{
    std::vector<uint8_t> buffer(sizeof(MIB_IPADDRTABLE));
    ULONG bufferSize = (ULONG)buffer.size();
    MIB_IPADDRTABLE* table = (MIB_IPADDRTABLE*)buffer.data();

    size_t loopCnt = 0;
    DWORD err;
    do {
        err = GetIpAddrTable(table, &bufferSize, 0);
        if (err == ERROR_INSUFFICIENT_BUFFER)
        {
            buffer = std::vector<uint8_t>((size_t)bufferSize);
            bufferSize = (ULONG)buffer.size();
            table = (MIB_IPADDRTABLE*)buffer.data();
        }
    }
    while ((err == ERROR_INSUFFICIENT_BUFFER) && (++loopCnt < 3));

    if (err == NO_ERROR)
    {
        ifAddrs.clear();

        for (size_t i = 0; i < (size_t)(table->dwNumEntries); ++i)
        {
            IN_ADDR tmp;
            char buffer[50];

            tmp.S_un.S_addr = (ULONG)(table->table[i].dwAddr);
            const mwip::Addr4 addr(inet_ntop(AF_INET, &tmp, buffer, sizeof(buffer)));

            tmp.S_un.S_addr = (ULONG)(table->table[i].dwMask);
            const mwip::SubnetMask4 mask(inet_ntop(AF_INET, &tmp, buffer, sizeof(buffer)));

            ifAddrs.push_back(IfAddr4(addr, mask));
        }
    }
    else
    {
        std::string errMsg;
        char* buffer;
        if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL))
        {
            errMsg = buffer;
            LocalFree(buffer);
        }

        if (!errMsg.empty()) { cli::printError(errMsg); }
        cli::printError("failed to get network interfaces (" + std::to_string(err) + ")");
        return -(__LINE__);
    }

    return 0;
}

#else // OMW_PLAT_WIN

std::vector<std::string> ___getIfIpRanges()
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

    return ranges;
}

#endif // OMW_PLAT_WIN



std::vector<std::string> interfaces::getArgIpRanges()
{
    std::vector<std::string> ranges;
    std::vector<IfAddr4> ifAddrs;

    const int err = getIfAddrs(ifAddrs);
    if (!err)
    {
        std::sort(ifAddrs.begin(), ifAddrs.end(), [](const IfAddr4& a, const IfAddr4& b) { return (a.addr < b.addr); });

        for (size_t i = 0; i < ifAddrs.size(); ++i)
        {
            const auto& ifa = ifAddrs[i];

            if (ifa.addr != mwip::Addr4(127, 0, 0, 1))
            {
                const auto rangeStr = (ifa.addr & ifa.mask).toString() + '/' + std::to_string(ifa.mask.prefixSize());

                ranges.push_back(rangeStr);
            }
        }

        if (ranges.empty()) { cli::printError("no interface with IPv4 address found"); }
    }

#if PRJ_DEBUG && 0
    printf("ifaddrs:\n");
    for (size_t i = 0; i < ifAddrs.size(); ++i) { printf("  %-15s  %-15s\n", ifAddrs[i].addr.toString().c_str(), ifAddrs[i].mask.toString().c_str()); }
    printf("\nranges:\n");
    for (size_t i = 0; i < ranges.size(); ++i) { printf("  %s\n", ranges[i].c_str()); }
    printf("\n");
#endif

    return ranges;
}
