/*
author          Oliver Blaser
date            10.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>

#include "middleware/cli.h"
#include "middleware/socket/util.h"
#include "project.h"

#include <curl-thread/thread.h>
#include <omw/clock.h>
#include <omw/defs.h>
#include <omw/encoding.h>

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



namespace sniffer {

class SharedData : public thread::ThreadCtl
{
public:
    SharedData()
        : thread::ThreadCtl(), m_error(0)
    {}

    virtual ~SharedData() {}


    // clang-format off
    int error() const { lock_guard lg(m_mtx); return m_error; }
    // clang-format on


private:
    int m_error;
    mutable std::mutex m_mtx;

public:
    // thread intern

    // clang-format off
    void setError(int error) { lock_guard lg(m_mtx); m_error = error; }
    // clang-format on
};

static SharedData sd = SharedData();

void thread();

} // namespace sniffer



std::thread thread_sniffer;



int xnix_init()
{
    int err = 0;

    thread_sniffer = std::thread(sniffer::thread);

    while (!sniffer::sd.booted() && !err) { err = sniffer::sd.error(); }

    return err;
}

void xnix_deinit()
{
    sniffer::sd.shutdown();
    thread_sniffer.join();
}

/**
 * @param addrStr IPv4 address, format: `a.b.c.d`
 * @param [out] macBuffer MAC address buffer
 * @return 0 on success, negative on error, positive on timeout
 */
int impl_scan_xnix(const char* addrStr, uint8_t* macBuffer)
{
    int err;



    char ifname[50];
    struct sockaddr ifaddr;
    struct in_addr taddr;
    err = sock::getifaddr(ifname, sizeof(ifname), &ifaddr, AF_INET, addrStr, &taddr);
    if (err)
    {
        cli::printWarning("currently only ARP is implemented, devices can't be ARPed through NAT");
        return -(__LINE__);
    }

    err = sock::sendArpRequest(addrStr, ifname, &ifaddr, &taddr);
    if (err)
    {
        // error print is done in sendArpRequest()
        return err;
    }



    int r = -(__LINE__);
    const omw::clock::timepoint_t tpStart = omw::clock::now();
    while (1)
    {
        // timeout
        if (omw::clock::elapsed_ms(omw::clock::now(), tpStart, 30 * omw::clock::second_ms))
        {
            r = 1;
            break;
        }

#if PRJ_DEBUG
        auto tryPop = [](const in_addr* taddr, uint8_t* macBuffer) { return true; };
#endif

        // check if result is available
        if (tryPop(&taddr, macBuffer))
        {
            r = 0;
            break;
        }

        const struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 500 * 1000,
        };
        nanosleep(&ts, NULL);
    }

    return r;
}



void sniffer::thread()
{
    // open socket
    if (0)
    {
        cli::printErrno("TODO open socket", -1);
        sd.setError(__LINE__);
        return;
    }



    sd.setBooted(true);

    while (!sd.doShutdown() && !sd.doTerminate())
    {
        // ...
    }



    // close socket
}



#endif // OMW_PLAT_ *nix
