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

#include "application/result.h"
#include "application/scan.h"
#include "middleware/cli.h"
#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"
#include "process.h"
#include "project.h"

#include <omw/cli.h>
#include <omw/string.h>


using std::cout;
using std::endl;



static void printMaskAssumeInfo(const ip::SubnetMask4& mask);
static int getRange(std::vector<ip::Addr4>& range, const std::string& argAddrRange);



int app::process(const std::string& argAddrRange)
{
    std::vector<ip::Addr4> range;

    const int err = getRange(range, argAddrRange);
    if (err) { return -(__LINE__); }

    if (range.empty())
    {
        cli::printError("empty IP address range");
        return -(__LINE__);
    }



    // cout << endl;
    // cout << " IP                 MAC                  Vendor" << endl;
    cout << endl;
    // cout << " ===============    =================    ===============" << endl;
    //  _    " 192.168.100.800    00-80-41-ae-fd-7e    asdf";

    for (size_t i = 0; i < range.size(); ++i)
    {
        const auto result = app::scan(range[i]);

        if (result.ip() != ip::Addr4::null)
        {
            const std::string vendor = "";

            cout << " " << std::left << std::setw(15) << result.ip().toString();
            cout << "  " << std::left << std::setw(17) << result.mac().toString();
            cout << "  " << std::right << std::setw(4) << result.duration() << "ms";
            cout << "  " << vendor;
            cout << endl;
        }
    }

    cout << endl;


    return 0;
}



void printMaskAssumeInfo(const ip::SubnetMask4& mask)
{
#if PRJ_DEBUG && 0 // don't, subnet mask is printed in range statistics
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
                    cli::printError("invalid end address");
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
        cli::printError("out of range", ex.what());
        return -(__LINE__);
    }
    catch (const std::invalid_argument& ex)
    {
        cli::printError("invalid argument", ex.what());
        return -(__LINE__);
    }
    catch (const std::exception& ex)
    {
        cli::printError("std::exception", ex.what());
        return -(__LINE__);
    }
    catch (...)
    {
        cli::printError("unknown exception");
        return -(__LINE__);
    }

    if (mask == ip::SubnetMask4::max)
    {
        cli::printError("missing subnet mask");
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
