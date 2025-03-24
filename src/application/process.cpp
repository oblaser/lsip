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
#include "process.h"
#include "project.h"

#include <omw/cli.h>
#include <omw/string.h>


using std::cout;
using std::endl;
using std::setw;



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



    if (range.size() > 1) { cout << "scanning " << range.size() << " IPs from " << range.front().toString() << " to " << range.back().toString() << endl; }

    std::vector<ip::Addr4 /* TODO app::ScanResult */> result = range; // TODO app::ScanResult app::scan(const ip::Addr4& addr);



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
    cout << "assuming subnet mask of ";
    cout << omw::fgBrightWhite << "/" << (int)(mask.prefixSize()) << omw::fgDefault;
    cout << " aka ";
    cout << omw::fgBrightWhite << mask.toString() << omw::fgDefault;
    cout << endl;
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
                mask = ip::SubnetMask4((int)(ip::Addr4::bit_count - 8 * endTokens.size()));
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

    const ip::SubnetMask4& netMask = mask;
    const ip::Addr4 hostMask = mask.hostMask();


#if PRJ_DEBUG && 1
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
#if PRJ_DEBUG && 1
            cout << "skipping " << addr.toString() << endl;
#endif
        }
    }

    return 0;
}
