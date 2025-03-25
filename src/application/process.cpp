/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"
#include "process.h"
#include "project.h"

#include <omw/cli.h>
#include <omw/string.h>


using std::cout;
using std::endl;
using std::setw;



namespace app_ {
ip::Addr4 /* TODO app::ScanResult */ scan(const ip::Addr4& addr);
}



static void printError(const std::string& str, const char* const exWhat = nullptr);
static void printMaskAssumeInfo(const ip::SubnetMask4& mask);
static int getRange(std::vector<ip::Addr4>& range, const std::string& argAddrRange);



int app::process(const std::string& argAddrRange)
{
    std::vector<ip::Addr4> range;

    const int err = getRange(range, argAddrRange);
    if (err) { return -(__LINE__); }

    if (range.empty())
    {
        printError("empty IP address range");
        return -(__LINE__);
    }



    std::vector<ip::Addr4 /* TODO app::ScanResult */> result;

    // TODO app::ScanResult app::scan(const ip::Addr4& addr)
    {
        for (size_t i = 0; i < range.size(); ++i)
        {
            const auto tmp = app_::scan(range[i]);
            if (tmp != ip::Addr4::null) { result.push_back(tmp); }
        }
    }



    // cout << endl;
    // cout << " IP                 MAC                  Vendor" << endl;
    cout << endl;
    // cout << " ===============    =================    ===============" << endl;
    //  _    " 192.168.100.800    00-80-41-ae-fd-7e    asdf";

    for (size_t i = 0; i < result.size(); ++i)
    {
        const auto& ip = result[i];
        const std::string mac = "ff-ff-ff-ff-ff-ff";
        const std::string vendor = "";

        cout << " " << std::left << setw(15) << ip.toString();
        cout << "    " << std::left << setw(17) << mac;
        cout << "    " << vendor;
        cout << endl;
    }

    cout << endl;


    return 0;
}



void printError(const std::string& str, const char* const exWhat)
{
    cout << omw::fgBrightRed << std::left << std::setw(11) << "error" << omw::fgDefault;
    if (exWhat) { cout << omw::fgBrightBlack << exWhat << omw::fgDefault << " "; }
    cout << str << endl;
}

void printMaskAssumeInfo(const ip::SubnetMask4& mask)
{
#if 0 // don't, subnet mask is printed in range statistics
    cout << "assuming subnet mask of ";
    cout << omw::fgBrightWhite << "/" << (int)(mask.prefixSize()) << omw::fgDefault;
    cout << " aka ";
    cout << omw::fgBrightWhite << mask.toString() << omw::fgDefault;
    cout << endl;
#else
    (void)mask;
#endif
}

int getRange(std::vector<ip::Addr4>& range, const std::string& argAddrRange)
{
    ip::Addr4 start;
    ip::Addr4::value_type count = 0;

    ip::SubnetMask4 mask = ip::SubnetMask4::max;

    const size_t slashPos = argAddrRange.find('/');
    const size_t hyphenPos = argAddrRange.find('-');

    try
    {
        // parse subnet mask
        if (slashPos != std::string::npos) { mask = argAddrRange.substr(slashPos); }

        // parse range
        if (hyphenPos != std::string::npos)
        {
            start = argAddrRange.substr(0, hyphenPos);


            const size_t endStrPos = hyphenPos + 1;
            const size_t endStrCount = slashPos - endStrPos;
            const auto endStr = argAddrRange.substr(endStrPos, endStrCount);
            auto endTokens = omw::split(endStr, '.');

            if (mask == ip::SubnetMask4::max)
            {
                if ((start & ip::SubnetMask4(16)) == ip::Addr4(192, 168, 0, 0)) { mask = ip::SubnetMask4(24); }
                else { mask = ip::SubnetMask4((int)(ip::Addr4::bit_count - 8 * endTokens.size())); }
                printMaskAssumeInfo(mask);
            }

            while (endTokens.size() < 4)
            {
                uint8_t tmp;

                if (endTokens.size() == 1) { tmp = start.octetMidLo(); }
                else if (endTokens.size() == 2) { tmp = start.octetMidHi(); }
                else if (endTokens.size() == 3) { tmp = start.octetHigh(); }
                else
                {
                    printError("invalid end address");
                    return -(__LINE__);
                }

                endTokens.insert(endTokens.begin(), std::to_string(tmp));
            }

            const uint32_t end = ip::Addr4(omw::join(endTokens, '.')).value();
            count = end - start.value() + 1;
            static_assert(sizeof(count) == sizeof(end));
        }
        else
        {
            start = argAddrRange.substr(0, slashPos);

            if (mask == ip::SubnetMask4::max)
            {
                if (start.octetLow() == 0)
                {
                    mask = ip::SubnetMask4(24);
                    printMaskAssumeInfo(mask);

                    count = ~mask.value() + 1;
                    static_assert(sizeof(count) == sizeof(ip::SubnetMask4::value_type));
                }
            }

            if (mask == ip::SubnetMask4::max)
            {
                mask = ip::SubnetMask4(8);
                printMaskAssumeInfo(mask);

                count = 1;
            }
            else
            {
                count = ~mask.value() + 1;
                static_assert(sizeof(count) == sizeof(ip::SubnetMask4::value_type));
            }
        }
    }
    catch (const std::out_of_range& ex)
    {
        printError("out of range", ex.what());
        return -(__LINE__);
    }
    catch (const std::invalid_argument& ex)
    {
        printError("invalid argument", ex.what());
        return -(__LINE__);
    }
    catch (const std::exception& ex)
    {
        printError("std::exception", ex.what());
        return -(__LINE__);
    }
    catch (...)
    {
        printError("unknown exception");
        return -(__LINE__);
    }

    if (mask == ip::SubnetMask4::max)
    {
        printError("missing subnet mask");
        return -(__LINE__);
    }



    // create range

    const ip::SubnetMask4& netMask = mask;
    const ip::Addr4 hostMask = mask.hostMask();

#if PRJ_DEBUG && 0
    cout << "start: " << ip::cidrString(start, netMask) << endl;
    cout << "count: " << count << endl;
#endif

    range.clear();
    range.reserve(count);

    for (uint32_t i = 0; i < count; ++i)
    {
        const auto addr = ip::Addr4(start.value() + i);

        if (((addr & hostMask) != ip::Addr4::null) && ((addr & hostMask) != hostMask)) { range.push_back(addr); }
        else
        {
#if PRJ_DEBUG && 0
            cout << "skipping " << addr.toString() << endl;
#endif
        }
    }



    // print range statistics

    if (range.size() > 1)
    {
        const auto& first = range.front();
        const auto& last = range.back();

        cout << "scanning " << range.size() << " IPs from ";
        cout << omw::fgBrightWhite << ip::cidrString(first, netMask) << omw::fgDefault;
        cout << " to ";
        cout << omw::fgBrightWhite << ip::cidrString(last, netMask) << omw::fgDefault;
        cout << endl;
    }
    else if (!range.empty())
    {
        cout << "scanning IP ";
        cout << omw::fgBrightWhite << range[0].toString() << omw::fgDefault;
        cout << endl;
    }



#if PRJ_DEBUG && 1
    {
        ip::Addr4 last = ip::Addr4::null;
        for (size_t i = 0; i < range.size(); ++i)
        {
            const auto& addr = range[i];
            const auto& next = (i < (range.size() - 1) ? range[i + 1] : ip::Addr4::max);

            if (((addr.value() - last.value()) > 1) || ((next.value() - addr.value()) > 1) || (i == (range.size() - 1)))
            {
                cout << omw::fgBrightBlack << addr.toString() << omw::fgDefault << endl;
            }

            last = addr;
        }
    }
#endif



    return 0;
}



#if OMW_PLAT_WIN

#include <omw/clock.h>

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

static struct in_addr iptow(const ip::Addr4& addr)
{
    in_addr r;

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

static std::string arpres_to_string(DWORD arp_res)
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

ip::Addr4 app_::scan(const ip::Addr4& addr)
{
    ip::Addr4 r = ip::Addr4::null;

    const IPAddr arp_dest = iptow(addr).S_un.S_addr;
    const IPAddr arp_src = INADDR_ANY;
    ULONG arp_mac[2];
    ULONG arp_macSize = sizeof(arp_mac); // number of bytes

    omw::clock::timepoint_t dur_us = omw::clock::now();
    const DWORD arp_res = SendARP(arp_dest, arp_src, arp_mac, &arp_macSize);
    dur_us = omw::clock::now() - dur_us;

    if (arp_res == NO_ERROR)
    {
        mac::Address mac;
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

#if PRJ_DEBUG && 1
        const uint64_t arp_mac64 = ((uint64_t)(arp_mac[1]) << 32) | (uint64_t)(arp_mac[0]);

        const auto ___dbg_ip = addr.toString();
        const auto ___dbg_mac64 = omw::join(omw::splitLen(omw::toHexStr(arp_mac64), 2), '-');
        const auto ___dbg_mac = mac.toString();

        cout << omw::fgGreen << std::left << setw(15) << ___dbg_ip;
        cout << "    " << std::left << setw(17) << ___dbg_mac << ", nI/G: " << mac.getIG() << ", nU/L: " << mac.getUL();
        cout << "    " << ((dur_us + 500) / 1000) << "ms";
        cout << omw::fgDefault << endl;
#endif

        r = addr;
    }
    else
    {
#if PRJ_DEBUG && 1
        const auto ___dbg_ip = addr.toString();

        cout << omw::fgGreen << std::left << setw(15) << ___dbg_ip;
        cout << "    " << std::left << setw(17) << arpres_to_string(arp_res);
        cout << "    " << ((dur_us + 500) / 1000) << "ms";
        cout << omw::fgDefault << endl;
#endif

        if ((arp_res != ERROR_BAD_NET_NAME) && // not on the same subnet
            (arp_res != ERROR_GEN_FAILURE))    // destination not reached, maybe not on the same subnet
        {
            printError("SendARP() returned " + arpres_to_string(arp_res) + " on " + addr.toString());
        }
    }

    return r;
}

#else // OMW_PLAT_

ip::Addr4 app_::scan(const ip::Addr4& addr) { return ip::Addr4::null; }

#endif // OMW_PLAT_
