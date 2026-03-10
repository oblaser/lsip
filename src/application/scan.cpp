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
#include "middleware/interfaces.h"
#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "scan.h"

#include <omw/clock.h>
#include <omw/defs.h>



/**
 * @param dur_us Duration as microseconds
 * @return Rounded duration as milliseconds
 */
static inline uint32_t convertDuration(omw::clock::timepoint_t dur_us) { return (uint32_t)((dur_us + 500) / 1000); }

static app::ScanResult impl_scan(const ip::Addr4& addr);



app::ScanResult app::scan(const ip::Addr4& addr) { return impl_scan(addr); }



#if PRJ_DEBUG && 0

#include <atomic>
#include <curl-thread/curl.h>
app::ScanResult impl_scan(const ip::Addr4& addr)
{
    // TODO

    omw::clock::timepoint_t dur_us = omw::clock::now();

    mac::Addr mac;
    static std::atomic<size_t> ___cnt = 0;
    const size_t cnt = ___cnt;
    ++___cnt;

#if 0
    if (cnt == 0) { mac = mac::EUI48(0x1c740d030201); }
    else if (cnt == 1) { mac = mac::EUI48(0xb827eb030201); }
    else if (cnt == 2) { mac = mac::EUI48(0x00136A030201); }
    else if (cnt == 3) { mac = mac::EUI48(0xB8D812600201); }
    // else if (cnt == ) { mac = mac::EUI48(0x030201); }
#else
    // testing intermediate cache
    if (cnt == 0) { mac = mac::EUI48(0x1c740d030201); }
    else if (cnt < 10) { mac = mac::EUI48(0xb827eb030201); }
    else if (cnt < 12) { mac = mac::EUI48(0x00136A030201); }
    else if (cnt < 13) { mac = mac::EUI48(0xb827eb030201); }
    else if (cnt < 15) { mac = mac::EUI48(0xB8D812600201); }
    // else if (cnt == ) { mac = mac::EUI48(0x030201); }
    else if (cnt > 25) { ___cnt = 0; }
#endif

#if 0
    int delay_ms = curl::random(2, 400);
    // if (addr == ip::Addr4(192, 168, 1, 123)) { delay_ms = 3000; }
    const auto t = omw::clock::now();
    while (!omw::clock::elapsed_ms(omw::clock::now(), t, delay_ms)) {}
#endif

    dur_us = omw::clock::now() - dur_us;

    return app::ScanResult(addr, mac, convertDuration(dur_us), app::lookupVendor(mac));
}

#else // PRJ_DEBUG

#if OMW_PLAT_WIN



// clang-format off
// #define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <mstcpip.h>
#include <ip2string.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <Windows.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ws2_32.lib")
// clang-format on

static app::ScanResult scanArp(const ip::Addr4& addr);
static app::ScanResult scanIcmp(const ip::Addr4& addr);
static IN_ADDR ip_to_IN_ADDR(const ip::Addr4& addr);
static inline IPAddr ip_to_IPAddr(const ip::Addr4& addr) { return ip_to_IN_ADDR(addr).S_un.S_addr; }
static std::string arpres_to_string(DWORD arp_res);

app::ScanResult impl_scan(const ip::Addr4& addr)
{
    app::ScanResult r;

    const int err = interfaces::findInterface(addr);
    if (err == 1) { r = scanIcmp(addr); }
    else if (err == 0) { r = scanArp(addr); }
    // else nop, error printed by `findInterface()`

    return r;
}

app::ScanResult scanArp(const ip::Addr4& addr)
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

        r = app::ScanResult(addr, mac, convertDuration(dur_us), app::lookupVendor(mac));
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

static void fillReqPayloadDataBuffer(uint8_t* buffer, size_t count)
{
    const char a[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const size_t n = sizeof(a) - 1;

    for (size_t i = 0; i < count; ++i) { buffer[i] = (uint8_t)a[i % n]; }
}

app::ScanResult scanIcmp(const ip::Addr4& addr)
{
    app::ScanResult r;

    const IPAddr ipaddr = inet_addr(addr.toString().c_str());
    if (ipaddr == INADDR_NONE) { cli::printError("failed to convert IP address " + addr.toString()); }
    else
    {
        HANDLE icmpFileHandle = IcmpCreateFile();
        if (icmpFileHandle == INVALID_HANDLE_VALUE) { cli::printError("IcmpCreateFile() returned " + std::to_string(GetLastError())); }
        else
        {
            uint8_t reqData[32];
            fillReqPayloadDataBuffer(reqData, sizeof(reqData));

            constexpr DWORD replyBufferSize = sizeof(ICMP_ECHO_REPLY) +  //
                                              max(sizeof(reqData), 50) + // optional reply data
                                              20;                        // in case of an ICMP error a full IP header has to fit in here
            uint8_t replyBuffer[replyBufferSize];

            const DWORD nOfReply = IcmpSendEcho(icmpFileHandle, ipaddr, reqData, sizeof(reqData), NULL, replyBuffer, replyBufferSize, 30 * 1000);
            if (nOfReply != 0)
            {
                const ICMP_ECHO_REPLY* const reply = (ICMP_ECHO_REPLY*)replyBuffer;
                const ip::Addr4 srcAddr(ntohl(reply->Address));

                if (reply->Status == IP_SUCCESS)
                {
                    if (srcAddr != addr) { cli::printWarning("echo request sent to " + addr.toString() + ", reply received from " + srcAddr.toString()); }

                    const auto mac = mac::EUI48::null;
                    r = app::ScanResult(addr, mac, (uint32_t)(reply->RoundTripTime), app::lookupVendor(mac));
                }
            }
            else
            {
                // error:    IcmpSendEcho() returned 11010
                //
                // https://stackoverflow.com/questions/9368256/what-would-cause-icmpsendecho-to-fail-when-ping-exe-succeeds
                // https://stackoverflow.com/questions/23374710/icmpsendecho2-fails-with-fails-with-wsa-qos-admission-failure-and-error-noaccess
                // https://microsoft.public.windowsce.embedded.narkive.com/odS4vO0P/ping-gives-transmit-error-code-11010

                const DWORD lerr = GetLastError();
                const DWORD werr = (DWORD)WSAGetLastError();

                if ((lerr == werr) && (lerr == 11010)) // WSA_QOS_ADMISSION_FAILURE
                {
                    // using payload of 32 and 100 didn't help, so it seems SO/q23374710 is right and it indicates timeout
                    (void)0; // nop
                }
                else { cli::printError("IcmpSendEcho() lerr: " + std::to_string(lerr) + ", werr: " + std::to_string(werr)); }
            }

            IcmpCloseHandle(icmpFileHandle);
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



extern int impl_scan_xnix(const char* addrStr, uint8_t* macBuffer);

app::ScanResult impl_scan(const ip::Addr4& addr)
{
    app::ScanResult r;

    uint8_t macBuffer[mac::EUI48::octet_count];

    omw::clock::timepoint_t dur_us = omw::clock::now();
    const int err = impl_scan_xnix(addr.toString().c_str(), macBuffer);
    dur_us = omw::clock::now() - dur_us;

    if (!err)
    {
        const mac::Addr mac(macBuffer);
        r = app::ScanResult(addr, mac, convertDuration(dur_us), app::lookupVendor(mac));
    }
    else
    {
        if (err < 0) { cli::printError("failed to scan " + addr.toString() + " (" + std::to_string(err) + ")"); }
        // else nop, timeout or unreachable
    }

    return r;
}



#endif // OMW_PLAT_WIN

#endif // PRJ_DEBUG
