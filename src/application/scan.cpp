/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>

#include "application/result.h"
#include "application/vendor-lookup.h"
#include "middleware/cli.h"
#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "scan.h"

#include <omw/clock.h>
#include <omw/defs.h>



static app::ScanResult impl_scan(const ip::Addr4& addr);



app::ScanResult app::scan(const ip::Addr4& addr)
{
    const app::ScanResult r = impl_scan(addr);
    return r;
}



#if OMW_PLAT_WIN



// clang-format off
// #define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Mstcpip.h>
#include <ip2string.h>
#include <iphlpapi.h>
#include <Windows.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")
// clang-format on

static IN_ADDR ip_to_IN_ADDR(const ip::Addr4& addr);
static inline IPAddr ip_to_IPAddr(const ip::Addr4& addr) { return ip_to_IN_ADDR(addr).S_un.S_addr; }
static std::string arpres_to_string(DWORD arp_res);

app::ScanResult impl_scan(const ip::Addr4& addr)
{
    app::ScanResult r;

    const IPAddr arp_dest = ip_to_IPAddr(addr);
    const IPAddr arp_src = INADDR_ANY;
    ULONG arp_mac[2];
    ULONG arp_macSize = sizeof(arp_mac); // number of bytes

    omw::clock::timepoint_t dur_us = omw::clock::now();
    const DWORD arp_res = SendARP(arp_dest, arp_src, arp_mac, &arp_macSize);
    dur_us = omw::clock::now() - dur_us;

    if (arp_res == NO_ERROR)
    {
        mac::Addr mac;
        size_t n = mac.size();
        if (n > (size_t)arp_macSize) { n = (size_t)arp_macSize; }

        for (size_t i = 0; i < mac.size(); ++i)
        {
            if (i < n)
            {
                // see https://learn.microsoft.com/en-gb/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp
                mac[i] = *(((const uint8_t*)arp_mac) + i);
            }
            else { mac[i] = 0; }
        }

        r = app::ScanResult(addr, mac, (uint32_t)((dur_us + 500) / 1000), app::lookupVendor(mac));
    }
    else
    {
        if ((arp_res != ERROR_BAD_NET_NAME) && // not on the same subnet
            (arp_res != ERROR_GEN_FAILURE))    // destination not reached, maybe not on the same subnet
        {
            cli::printError("SendARP() returned " + arpres_to_string(arp_res) + " on " + addr.toString());
        }
    }

    return r;
}

IN_ADDR ip_to_IN_ADDR(const ip::Addr4& addr)
{
    IN_ADDR r;

    r.S_un.S_un_b.s_b1 = addr.octetHigh();
    r.S_un.S_un_b.s_b2 = addr.octetMidHi();
    r.S_un.S_un_b.s_b3 = addr.octetMidLo();
    r.S_un.S_un_b.s_b4 = addr.octetLow();

#if PRJ_DEBUG
    char buffer[300];
    RtlIpv4AddressToStringA(&r, buffer);
    strcat_s(buffer, sizeof(buffer), (" <- " + addr.toString()).c_str());
#endif

    return r;
}

std::string arpres_to_string(DWORD arp_res)
{
    std::string str;

    switch (arp_res)
    {
    case ERROR_BAD_NET_NAME:
        str = "BAD_NET_NAME";
        break;

    case ERROR_BUFFER_OVERFLOW:
        str = "BUFFER_OVERFLOW";
        break;

    case ERROR_GEN_FAILURE:
        str = "GEN_FAILURE";
        break;

    case ERROR_INVALID_PARAMETER:
        str = "INVALID_PARAMETER";
        break;

    case ERROR_INVALID_USER_BUFFER:
        str = "INVALID_USER_BUFFER";
        break;

    case ERROR_NOT_FOUND:
        str = "NOT_FOUND";
        break;

    case ERROR_NOT_SUPPORTED:
        str = "NOT_SUPPORTED";
        break;

    default:
        str = "[" + std::to_string(arp_res) + "]";
        break;
    }

    return str;
}



#else // OMW_PLAT_WIN



app::ScanResult impl_scan(const ip::Addr4& addr)
{
    // TODO

    mac::Addr mac;

    static size_t cnt = 0;

    if (cnt == 0) { mac = mac::EUI48(0x1c740d030201); }
    else if (cnt == 1) { mac = mac::EUI48(0xb827eb030201); }
    else if (cnt == 2) { mac = mac::EUI48(0x00136A030201); }
    else if (cnt == 3) { mac = mac::EUI48(0xB8D812600201); }
    // else if (cnt == ) { mac = mac::EUI48(0x030201); }

    ++cnt;

    return app::ScanResult(addr, mac, 9999, app::lookupVendor(mac));
}



#endif // OMW_PLAT_WIN
