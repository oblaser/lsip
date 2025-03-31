/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "application/result.h"
#include "application/scan.h"
#include "middleware/cli.h"
#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"
#include "process.h"
#include "project.h"

#include <omw/cli.h>
#include <omw/defs.h>
#include <omw/string.h>

#if OMW_PLAT_WIN
#include <Windows.h>
#else
#include <time.h>
#endif


using std::cout;
using std::endl;



class Queue
{
public:
#if PRJ_DEBUG
    static constexpr size_t maxThCount = 10;
#else
    static constexpr size_t maxThCount = 20;
#endif

    using lock_guard = std::lock_guard<std::mutex>;

public:
    Queue()
        : m_thCount(0)
    {}

    virtual ~Queue() {}

    void setRange(const std::vector<ip::Addr4>& range)
    {
        lock_guard lg(mtx);
        m_ip = range;
    }

    app::ScanResult popRes()
    {
        lock_guard lg(mtx);
        app::ScanResult res;
        if (!m_res.empty())
        {
            res = m_res.front();
            m_res.erase(m_res.begin());
        }
        return res;
    }

    size_t thCount() const
    {
        lock_guard lg(mtx);
        return m_thCount;
    }

    size_t remaining() const
    {
        lock_guard lg(mtx);
        return m_ip.size();
    }

    bool done() const
    {
        lock_guard lg(mtx);
        return (m_ip.empty() && m_res.empty() && (m_thCount == 0));
    }

public: // thread internal
    ip::Addr4 popIP()
    {
        lock_guard lg(mtx);
        ++m_thCount;
        const ip::Addr4 ip = m_ip.front();
        m_ip.erase(m_ip.begin());
        return ip;
    }

    void queueRes(const app::ScanResult& res)
    {
        lock_guard lg(mtx);
        --m_thCount;
        m_res.push_back(res);
    }

private:
    mutable std::mutex mtx;
    size_t m_thCount;
    std::vector<ip::Addr4> m_ip;
    std::vector<app::ScanResult> m_res;
};



static Queue queue;



static void sleep_ms(uint16_t t_ms);
static void scanThread();
static void printMaskAssumeInfo(const ip::SubnetMask4& mask);
static void printResult(const app::ScanResult& result);
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

    queue.setRange(range);



    cout << endl;

    do {
        const size_t thCount = queue.thCount();
        const size_t remaining = queue.remaining();
        if ((remaining != 0) && (thCount < Queue::maxThCount))
        {
            std::thread th(scanThread);
            th.detach();
            while (queue.remaining() == remaining) { sleep_ms(1); } // wait until the thread has started and popped the IP
        }

        uint16_t threadSleep = 10;
        auto res = queue.popRes();
        if (!res.empty())
        {
            printResult(res);
            threadSleep = 1;
        }

        sleep_ms(threadSleep);
    }
    while (!queue.done());

    cout << endl;



    return 0;
}



void sleep_ms(uint16_t t_ms)
{
#if OMW_PLAT_WIN
    Sleep(t_ms);
#else
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = ((int32_t)t_ms * 1000);
    nanosleep(&ts, NULL);
#endif
}

void scanThread()
{
    const auto ip = queue.popIP();

    THREAD_PRINT(ip.toString());

    const auto res = app::scan(ip);
    queue.queueRes(res);
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

void printResult(const app::ScanResult& result)
{
    std::stringstream ss;

    ss << " " << std::left << std::setw(15) << result.ip().toString();

    if (result.mac().isCID()) { ss << omw::fgYellow; }
    ss << "  " << std::left << std::setw(17) << result.mac().toString();
    ss << omw::fgDefault;

    ss << "  " << std::right << std::setw(4) << result.duration() << "ms";

    const auto& vendor = result.vendor();
    if (!vendor.empty() /* && TODO cli option */)
    {
        ss << "  ";

        if (true /* TODO cli option */) { ss << omw::fgBrightBlack << '[' << vendor.source() << ']' << omw::fgDefault; }

        if (vendor.hasColour())
        {
            const auto& col = vendor.colour();
            ss << omw::foreColor(col);
        }

        ss << ' ' << vendor.name();
        ss << omw::fgDefault;
    }

    ss << '\n';
    cout << ss.str() << std::flush;
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

            // if no subnet mask is set and the last octet is 0, assume /24 subnet mask (does not catch all cases, but the most common)
            if ((mask == ip::SubnetMask4::max) && (start.octetLow() == 0))
            {
                mask = ip::SubnetMask4(24);
                printMaskAssumeInfo(mask);

                count = ~mask.value() + 1;
                static_assert(sizeof(count) == sizeof(ip::SubnetMask4::value_type));
            }

            // if no subnet mask is set at this point, it's one single IP address
            if (mask == ip::SubnetMask4::max)
            {
                mask = ip::SubnetMask4(8);
                printMaskAssumeInfo(mask);

                count = 1;
            }
            else if (start.octetLow() == 0)
            {
                count = ~mask.value() + 1;
                static_assert(sizeof(count) == sizeof(ip::SubnetMask4::value_type));
            }
            else
            {
                const uint32_t end = (start | ~mask).value();
                count = end - start.value() + 1;
                static_assert(sizeof(count) == sizeof(end));
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



#if PRJ_DEBUG && 0
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
