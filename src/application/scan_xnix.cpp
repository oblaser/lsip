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
#include "middleware/mac-addr.h"
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
// #include <net/if_ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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
        auto tryPop = [](const in_addr* taddr, uint8_t* macBuffer) {
            // TODO check for `sniffer::sd.error()`
            sleep(1);
            return false;
        };
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



static void handlePacket_arp(const uint8_t* data, size_t size)
{
    using sock::util::arpdata;

    const struct arphdr* const arpHeader = (const struct arphdr*)(data);
    const size_t arpHeaderSize = 8;
    const uint16_t arpHwType = ntohs(arpHeader->ar_hrd);
    const uint16_t arpProtocol = ntohs(arpHeader->ar_pro);
    const uint8_t arpHwLength = arpHeader->ar_hln;
    const uint8_t arpProtoLen = arpHeader->ar_pln;
    const uint16_t arpOperation = ntohs(arpHeader->ar_op);
    const uint8_t* const arpData = data + arpHeaderSize;
    const size_t arpDataSize = 2 * arpHwLength + 2 * arpProtoLen;
    const uint8_t* const padData = data + arpHeaderSize + arpDataSize; // padding
    const size_t padDataSize = size - arpHeaderSize - arpDataSize;     // padding

    char buffer[100];

#define SGR_ARP SGR_BGREEN

    printf(SGR_ARP);

    printf("ARP\n");
    printf("  hw type   %i %s\n", (int)arpHwType, (arpHwType == ARPHRD_ETHER ? "ETH" : ""));
    printf("  proto     0x%04x %s\n", (int)arpProtocol, sock::util::ethptos(arpProtocol).c_str());
    printf("  hw length %i\n", (int)arpHwLength);
    printf("  proto len %i\n", (int)arpProtoLen);
    printf("  operation %i %s\n", (int)arpOperation, (arpOperation == 1 ? "request" : (arpOperation == 2 ? "reply" : "")));
    printf("  hdr size  %zu\n", arpHeaderSize);
    printf("  data size %zu + %zu pad\n", arpDataSize, padDataSize);

    // hexDump((const uint8_t*)arpHeader, arpHeaderSize);
    // printf("\n");

    if ((arpHwType == ARPHRD_ETHER) && (arpProtocol == ETH_P_IP) && (arpHwLength == ARPDATA_HLEN) && (arpProtoLen == ARPDATA_PLEN))
    {
        const struct arpdata* const arpdata = (const struct arpdata*)(arpData);
        const uint8_t* sMacData = arpdata->ar_sha;
        const uint8_t* tMacData = arpdata->ar_tha;

        const mac::EUI48 sMac(sMacData);
        const mac::EUI48 tMac(tMacData);

        char buffer[100];

        printf("  sender MAC   %s\n", sMac.toString().c_str());
        printf("  sender addr  %s\n", inet_ntop(AF_INET, &(arpdata->ar_spa), buffer, sizeof(buffer)));
        printf("  target MAC   %s\n", tMac.toString().c_str());
        printf("  target addr  %s\n", inet_ntop(AF_INET, &(arpdata->ar_tpa), buffer, sizeof(buffer)));

        // hexDump(arpData, arpDataSize);
    }
    else
    {
        // hexDump(arpData, arpDataSize);
    }

    printf(SGR_DEFAULT);
    fflush(stdout);

    // printPacket_padding(padData, padDataSize);
}

static void handlePacket_icmp(const uint8_t* data, size_t size)
{
    const struct icmphdr* const icmpHeader = (const struct icmphdr*)(data);
    const size_t icmpHeaderSize = 8;
    const uint8_t icmpType = icmpHeader->type;
    const uint8_t icmpCode = icmpHeader->code;
    const uint16_t icmpCheck = ntohs(icmpHeader->checksum);
    // ...
    __attribute__((unused)) const uint8_t* const icmpData = data + icmpHeaderSize;
    __attribute__((unused)) const size_t icmpDataSize = size - icmpHeaderSize;
    __attribute__((unused)) const uint8_t* const padData = data + icmpHeaderSize + icmpDataSize; // potential padding
    __attribute__((unused)) const size_t padDataSize = size - icmpHeaderSize - icmpDataSize;     // potential padding

    const uint16_t icmpCheckCalc = sock::util::inet_checksum(data, icmpHeaderSize + icmpDataSize);

    char buffer[100];

#define SGR_ICMP SGR_BCYAN

    printf(SGR_ICMP);

    printf("ICMP\n");
    printf("  type      %i %s\n", (int)icmpType, ""); // icmpttos(icmpType, buffer, sizeof(buffer)));
    printf("  code      %i\n", (int)icmpCode);
    printf("  check     %s0x%04x" SGR_ICMP "\n", ((icmpCheckCalc == 0) ? "" : SGR_RED), (int)icmpCheck);
    printf("  hdr size  %zu\n", icmpHeaderSize);
    printf("  data size %zu + %zu pad\n", icmpDataSize, padDataSize);

    // hexDump((const uint8_t*)icmpHeader, icmpHeaderSize);

    printf(SGR_DEFAULT);
    fflush(stdout);
}

void sniffer::thread()
{
    const int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        cli::printErrno("failed to create socket", errno);
        sd.setError(__LINE__);
        return;
    }

    uint8_t sockData[ETH_FRAME_LEN + 4 /* VLAN Extended Header */];
    struct sockaddr_storage sockSrcAddr;
    socklen_t sockSrcAddrSize = sizeof(sockSrcAddr);



    sd.setBooted(true);

    while (!sd.doShutdown() && !sd.doTerminate())
    {
        const ssize_t sockDataSize = recvfrom(sockfd, sockData, sizeof(sockData), 0, (struct sockaddr*)(&sockSrcAddr), &sockSrcAddrSize);

        if (sockDataSize < 0)
        {
            cli::printErrno("sniffer recvfrom() failed", errno);

            const int err = close(sockfd);
            if (err)
            {
                cli::printErrno("sniffer close() failed", errno);
                sd.setError(__LINE__);
            }
            else { sd.setError(__LINE__); }

            sd.shutdown();
        }
        else
        {
            const struct ethhdr* const ethHeader = (const struct ethhdr*)(sockData);
            const uint16_t ethProtocol = ntohs(ethHeader->h_proto);
            const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
            __attribute__((unused)) const uint8_t* const ethData = sockData + ethHeaderSize;
            __attribute__((unused)) const size_t ethDataSize = sockDataSize - ethHeaderSize;

            const struct iphdr* const ipHeader = (const struct iphdr*)(ethData);
            const uint8_t ipIhl = ipHeader->ihl;
            const size_t ipHeaderSize = ipIhl * 4u;
            const uint8_t ipProtocol = ipHeader->protocol;
            __attribute__((unused)) const uint8_t* const ipData = ethData + ipHeaderSize;
            __attribute__((unused)) const size_t ipDataSize = ethDataSize - ipHeaderSize;

            const uint16_t ipCheckCalc = sock::util::inet_checksum(ethData, ipHeaderSize);

            struct sock::util::ippseudohdr ___pseudoHdr;
            const struct sock::util::ippseudohdr* const pseudoHdr = &___pseudoHdr;
            ippseudohdr_init(&___pseudoHdr, ipHeader);

            __attribute__((unused)) uint16_t srcPort = 0;
            __attribute__((unused)) uint16_t dstPort = 0;
            __attribute__((unused)) uint8_t icmpType;

            __attribute__((unused)) bool checksumOk = true;
            if (ipCheckCalc != 0) { checksumOk = false; }



            if (ethProtocol == ETH_P_ARP) { handlePacket_arp(ethData, ethDataSize); }
            else if ((ethProtocol == ETH_P_IP) && (ipProtocol == IPPROTO_ICMP)) { handlePacket_icmp(ethData, ethDataSize); }
        }
    }



    errno = 0;
    if (close(sockfd) != 0) { cli::printErrno("close socket failed", errno); }
}



#endif // OMW_PLAT_ *nix
