/*
author          Oliver Blaser
date            10.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

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



constexpr omw::clock::timepoint_t timeout_arp_s = 10;
constexpr omw::clock::timepoint_t timeout_icmp_s = 30;



namespace sniffer {

class Resolution
{
public:
    enum class Type
    {
        null,
        unreach, // special value so that the scanner does not need to wait for it's full timeout duration
        arp,
        echo,
    };

public:
    Resolution()
        : type(Type::null), mac(mac::EUI48::null), ip{ .s_addr = 0 }
    {}

    Resolution(const mac::EUI48& _mac, const struct in_addr* _ip)
        : type(Type::arp), mac(_mac), ip{ .s_addr = 0 }
    {
        if (_ip) { this->ip.s_addr = _ip->s_addr; }
    }

    Resolution(const Type& _type, const struct in_addr* _ip)
        : type(_type), mac(mac::EUI48::null), ip{ .s_addr = 0 }
    {
        if (_ip) { this->ip.s_addr = _ip->s_addr; }
    }

    virtual ~Resolution() {}

    std::string toString() const;

    Type type;
    mac::EUI48 mac;
    struct in_addr ip;
};

class SharedData : public thread::ThreadCtl
{
public:
    SharedData()
        : thread::ThreadCtl(), m_error(0)
    {}

    virtual ~SharedData() {}


    // clang-format off
    int error() const { lock_guard lg(m_mtx); return m_error; }
    std::vector<Resolution> getResolutions() const { lock_guard lg(m_mtx); return m_res; }
    // clang-format on

    Resolution popResolution(const struct in_addr* ip);

private:
    mutable std::mutex m_mtx;
    int m_error;
    std::vector<Resolution> m_res;

public:
    // thread intern

    // clang-format off
    void setError(int error) { lock_guard lg(m_mtx); m_error = error; }
    // clang-format on

    void pushResolution(const Resolution& res);
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

#if PRJ_DEBUG && 0
    const auto res = sniffer::sd.getResolutions();
    printf("\nunpopped resolutions:\n");
    for (size_t i = 0; i < res.size(); ++i) { printf("%3zu   %s\n", i, res[i].toString().c_str()); }
#endif
}

/**
 * @param addrStr IPv4 address, format: `a.b.c.d`
 * @param [out] macBuffer MAC address buffer
 * @return 0 on success, negative on error, 1 on timeout, 2 if not reachable
 */
int impl_scan_xnix(const char* addrStr, uint8_t* macBuffer)
{
    int err;



    // wireshark filters
    // (icmp && ip == x.x.x.x) || (arp && eth == xx:xx:xx:xx:xx:xx)
    // (icmp && ip.src == x.x.x.x) || (arp && eth.src == xx:xx:xx:xx:xx:xx)
    // (icmp && ip.dst == x.x.x.x) || (arp && eth.dst == xx:xx:xx:xx:xx:xx)



    bool isArp = false;

    char ifname[50];
    struct sockaddr ifaddr;
    struct in_addr taddr;
    err = sock::getifaddr(ifname, sizeof(ifname), &ifaddr, AF_INET, addrStr, &taddr);
    if (err == 1)
    {
        isArp = false;
        err = sock::sendEchoRequest(&taddr);
        if (err) { return (err * 1000000) + -(__LINE__); }
    }
    else if (err == 0)
    {
        isArp = true;
        err = sock::sendArpRequest(addrStr, ifname, &ifaddr, &taddr);
        if (err) { return (err * 1000000) + -(__LINE__); }
    }
    else { return ((err * 1000000) - (__LINE__)); }



    int r = -(__LINE__);
    bool done = false;
    const omw::clock::timepoint_t tpStart = omw::clock::now();
    while (!done)
    {
        // timeout
        if (omw::clock::elapsed_ms(omw::clock::now(), tpStart, (isArp ? timeout_arp_s : timeout_icmp_s) * omw::clock::second_ms))
        {
#if PRJ_DEBUG && 0
            printf(SGR_BBLACK "%s timeout" SGR_DEFAULT "\n", addrStr);
#endif
            r = 1;
            done = true;
        }

        const sniffer::Resolution res = sniffer::sd.popResolution(&taddr);

        switch (res.type)
        {
        case sniffer::Resolution::Type::null:
            // nop, no resolution for the requested IP adderss available
            break;

        case sniffer::Resolution::Type::arp:
        case sniffer::Resolution::Type::echo:
            for (size_t i = 0; i < res.mac.size(); ++i) { macBuffer[i] = res.mac[i]; }
            r = 0;
            done = true;
            break;

        case sniffer::Resolution::Type::unreach:
#if PRJ_DEBUG && 0
            printf(SGR_BBLACK "%s unreachable" SGR_DEFAULT "\n", addrStr);
#endif
            r = 2;
            done = true;
            break;
        }

        if (!done)
        {
            const struct timespec ts = {
                .tv_sec = 0,
                .tv_nsec = 500 * 1000,
            };
            nanosleep(&ts, NULL);
        }
    }

    return r;
}



namespace sniffer {

std::string Resolution::toString() const
{
    std::string str;

    char buffer[INET_ADDRSTRLEN];
    const char* const ipStr = inet_ntop(AF_INET, &(this->ip), buffer, sizeof(buffer));

    if (ipStr) { str = ipStr; }

    if (this->mac != mac::EUI48::null) { str += " " + this->mac.toString(); }

    return str;
}

Resolution SharedData::popResolution(const struct in_addr* ip)
{
    lock_guard lg(m_mtx);

    Resolution res = Resolution();

    for (size_t i = 0; i < m_res.size(); ++i)
    {
        if (m_res[i].ip.s_addr == ip->s_addr)
        {
            res = m_res[i];
            m_res.erase(m_res.begin() + i);

#if PRJ_DEBUG && 0
            char buffer[100];
            const uint32_t net_saddr = htonl(res.ip.s_addr);
            printf("popped (%zu) %15s %s\n", m_res.size(), inet_ntop(AF_INET, &net_saddr, buffer, sizeof(buffer)), res.mac.toString().c_str());
#endif // PRJ_DEBUG

            break;
        }
    }

    return res;
}

void SharedData::pushResolution(const Resolution& res)
{
    lock_guard lg(m_mtx);

    bool replaced = false;

    for (size_t i = 0; i < m_res.size(); ++i)
    {
        if (m_res[i].ip.s_addr == res.ip.s_addr)
        {
            m_res[i] = res;

#if PRJ_DEBUG && 0
#define ___pushResolution_printEntry (1)
            char buffer[100];
            printf(SGR_BBLACK "repl res   #%zu: %15s %s" SGR_DEFAULT "\n", i, inet_ntop(AF_INET, &(res.ip.s_addr), buffer, sizeof(buffer)),
                   res.mac.toString().c_str());
#endif // PRJ_DEBUG

            replaced = true;
            break;
        }
    }

    if (!replaced)
    {
        m_res.push_back(res);

#ifdef ___pushResolution_printEntry
        char buffer[100];
        printf(SGR_BBLACK "resolution #%zu: %15s %s" SGR_DEFAULT "\n", (m_res.size() - 1), inet_ntop(AF_INET, &(res.ip.s_addr), buffer, sizeof(buffer)),
               res.mac.toString().c_str());
#endif // PRJ_DEBUG
    }
}

static void handlePacket_arp(const uint8_t* data, size_t size)
{
    const struct arphdr* const arpHeader = (const struct arphdr*)(data);
    const size_t arpHeaderSize = 8;
    const uint16_t arpHwType = ntohs(arpHeader->ar_hrd);
    const uint16_t arpProtocol = ntohs(arpHeader->ar_pro);
    const uint8_t arpHwLength = arpHeader->ar_hln;
    const uint8_t arpProtoLen = arpHeader->ar_pln;
    const uint16_t arpOperation = ntohs(arpHeader->ar_op);
    const uint8_t* const arpData = data + arpHeaderSize;
    // const size_t arpDataSize = 2 * arpHwLength + 2 * arpProtoLen;
    // const uint8_t* const padData = data + arpHeaderSize + arpDataSize; // padding
    // const size_t padDataSize = size - arpHeaderSize - arpDataSize;     // padding



#if PRJ_DEBUG && 0

    if (arpOperation != ARPOP_REQUEST)
    {
        const size_t arpDataSize = 2 * arpHwLength + 2 * arpProtoLen;
        const uint8_t* const padData = data + arpHeaderSize + arpDataSize; // padding
        const size_t padDataSize = size - arpHeaderSize - arpDataSize;     // padding

        char buffer[100];

        printf(SGR_ARP);

        printf("ARP\n");
        // printf("  hw type   %i %s\n", (int)arpHwType, (arpHwType == ARPHRD_ETHER ? "ETH" : ""));
        // printf("  proto     0x%04x %s\n", (int)arpProtocol, sock::util::ethptos(arpProtocol).c_str());
        // printf("  hw length %i\n", (int)arpHwLength);
        // printf("  proto len %i\n", (int)arpProtoLen);
        printf("  operation %i %s\n", (int)arpOperation, (arpOperation == ARPOP_REQUEST ? "request" : (arpOperation == ARPOP_REPLY ? "reply" : "")));
        // printf("  hdr size  %zu\n", arpHeaderSize);
        // printf("  data size %zu + %zu pad\n", arpDataSize, padDataSize);
        //
        //// hexDump((const uint8_t*)arpHeader, arpHeaderSize);
        // printf("\n");

        {
            const struct sock::util::arpdata* const arpdata = (const struct sock::util::arpdata*)(arpData);
            const uint8_t* sMac = arpdata->ar_sha;
            const uint8_t* tMac = arpdata->ar_tha;

            char buffer[100];

            auto mactos = [](const uint8_t* mac, char* dst, size_t size) {
                char* r = NULL;
                const size_t res = (size_t)snprintf(dst, size, "%02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                if (res < size) { r = dst; }
                return r;
            };

            printf("  sender MAC   %s\n", mactos(sMac, buffer, sizeof(buffer)));
            printf("  sender addr  %s\n", inet_ntop(AF_INET, &(arpdata->ar_spa), buffer, sizeof(buffer)));
            printf("  target MAC   %s\n", mactos(tMac, buffer, sizeof(buffer)));
            printf("  target addr  %s\n", inet_ntop(AF_INET, &(arpdata->ar_tpa), buffer, sizeof(buffer)));

            // hexDump(arpData, arpDataSize);
        }

        printf("\n");
        fflush(stdout);
    }

#endif // PRJ_DEBUG



    if ((arpHwType == ARPHRD_ETHER) && (arpProtocol == ETH_P_IP) && (arpHwLength == ARPDATA_HLEN) && (arpProtoLen == ARPDATA_PLEN) &&
        (arpOperation == ARPOP_REPLY))
    {
        const struct sock::util::arpdata* const arpdata = (const struct sock::util::arpdata*)(arpData);

        // IP address in host encoding
        const uint32_t addr_he = (((uint32_t)(arpdata->ar_spa[0]) << 24) | ((uint32_t)(arpdata->ar_spa[1]) << 16) | ((uint32_t)(arpdata->ar_spa[2]) << 8) |
                                  ((uint32_t)(arpdata->ar_spa[3]) << 0));

        const uint8_t* sMacData = arpdata->ar_sha;
        const in_addr sIpAddr = {
            .s_addr = htonl(addr_he),
        };

        sd.pushResolution(Resolution(mac::EUI48(sMacData), &sIpAddr));
    }
}

static void handlePacket_icmp(const struct in_addr* saddr, const uint8_t* data, size_t size)
{
    const struct icmphdr* const icmpHeader = (const struct icmphdr*)(data);
    const size_t icmpHeaderSize = 8;
    const uint8_t icmpType = icmpHeader->type;
    // const uint8_t icmpCode = icmpHeader->code;
    // const uint16_t icmpCheck = ntohs(icmpHeader->checksum);
    const uint8_t* const icmpData = data + icmpHeaderSize;
    const size_t icmpDataSize = size - icmpHeaderSize;
    // const uint8_t* const padData = data + icmpHeaderSize + icmpDataSize; // potential padding
    // const size_t padDataSize = size - icmpHeaderSize - icmpDataSize;     // potential padding

    // const uint16_t icmpCheckCalc = sock::util::inet_checksum(data, icmpHeaderSize + icmpDataSize);
    // const bool checksumOk = (icmpCheckCalc == 0);



#if PRJ_DEBUG && 0

    const uint8_t icmpCode = icmpHeader->code;
    const uint16_t icmpCheck = ntohs(icmpHeader->checksum);
    // const uint8_t* const padData = data + icmpHeaderSize + icmpDataSize; // potential padding
    const size_t padDataSize = size - icmpHeaderSize - icmpDataSize; // potential padding

    const uint16_t icmpCheckCalc = sock::util::inet_checksum(data, icmpHeaderSize + icmpDataSize);

    if (icmpType != ICMP_ECHO)
    {
        char buffer[100];

        printf(SGR_ICMP);

        printf("ICMP from %s\n", sock::util::inaddrtos(saddr).c_str());
        printf("  type      %i %s\n", (int)icmpType, sock::util::icmpttos(icmpType).c_str());
        printf("  code      %i %s\n", (int)icmpCode, sock::util::icmpctos(icmpType, icmpCode).c_str());
        printf("  check     %s0x%04x" SGR_ICMP "\n", ((icmpCheckCalc == 0) ? "" : SGR_RED), (int)icmpCheck);
        printf("  hdr size  %zu\n", icmpHeaderSize);
        printf("  data size %zu + %zu pad\n", icmpDataSize, padDataSize);

        if (((icmpType == ICMP_DEST_UNREACH) || (icmpType == ICMP_TIME_EXCEEDED)) && (icmpDataSize >= sizeof(struct iphdr)))
        {
            const struct iphdr* const ipHeader = (const struct iphdr*)(icmpData);
            // const uint8_t ipVersion = ipHeader->version;
            const uint8_t ipIhl = ipHeader->ihl;
            const size_t ipHeaderSize = ipIhl * 4u;
            // const uint8_t ipTos = ipHeader->tos;
            // const uint16_t ipTotalLen = ntohs(ipHeader->tot_len);
            // const uint16_t ipId = ntohs(ipHeader->id);
            // const uint8_t ipFlags = (uint8_t)(ntohs(ipHeader->frag_off) >> 13);
            // const uint16_t ipFragOff = (ntohs(ipHeader->frag_off) & 0x1FFF);
            const uint8_t ipTtl = ipHeader->ttl;
            const uint8_t ipProtocol = ipHeader->protocol;
            const uint16_t ipCheck = ntohs(ipHeader->check);
            // const uint32_t srcIp = ntohl(ipHeader->saddr);
            // const uint32_t dstIp = ntohl(ipHeader->daddr);
            // const size_t ipDataSize = size - ipHeaderSize;

            const uint16_t ipCheckCalc = sock::util::inet_checksum(icmpData, ipHeaderSize);

            printf(SGR_ICMP_ERR);
            printf("  original packet:\n");
            printf("    TTL       %i\n", (int)ipTtl);
            printf("    protocol  %02x %s\n", ipProtocol, sock::util::ipptos(ipProtocol).c_str());
            printf("    check     %s0x%04x" SGR_ICMP_ERR "\n", ((ipCheckCalc == 0) ? "" : SGR_RED), (int)ipCheck);
            printf("    src addr  %s\n", inet_ntop(AF_INET, &(ipHeader->saddr), buffer, sizeof(buffer)));
            printf("    dst addr  %s\n", inet_ntop(AF_INET, &(ipHeader->daddr), buffer, sizeof(buffer)));
        }

        printf(SGR_DEFAULT);
        fflush(stdout);
    }
#endif // PRJ_DEBUG



    if (icmpType == ICMP_ECHOREPLY)
    {
#if 0 // it seems to be common for echo replies to not calculate the checksum
        if (!checksumOk)
        {
            const struct sockaddr_in tmp = {
                .sin_family = AF_INET,
                .sin_port = 0,
                .sin_addr = { .s_addr = saddr->s_addr },
            };

            cli::printWarning("invalid IP checksum for echo reply from " + sock::util::sockaddrtos(&tmp));
        }
#endif
        sd.pushResolution(Resolution(Resolution::Type::echo, saddr));
    }
    else if (((icmpType == ICMP_DEST_UNREACH) || (icmpType == ICMP_TIME_EXCEEDED)) && (icmpDataSize >= sizeof(struct iphdr)))
    {
        const struct iphdr* const ipHeader = (const struct iphdr*)(icmpData);
        const uint8_t ipProtocol = ipHeader->protocol;
        const in_addr tmpAddr = {
            .s_addr = (in_addr_t)(ipHeader->daddr),
        };

        if (ipProtocol == IPPROTO_ICMP) { sd.pushResolution(Resolution(Resolution::Type::unreach, &tmpAddr)); }
    }
}

void thread()
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
                cli::printErrno("sniffer close socket failed", errno);
                sd.setError(__LINE__);
            }
            else { sd.setError(__LINE__); }

            sd.shutdown();
        }
        else if (sockDataSize >= 42)
        {
            // min ARP packet size: ETH_HDR + ARP_PACKET = 14 + 28 = 42
            // min ICMP packet size: ETH_HDR + IP_HDR + ICMP_HDR = 14 + 20 + 8 = 42

            const struct ethhdr* const ethHeader = (const struct ethhdr*)(sockData);
            const uint16_t ethProtocol = ntohs(ethHeader->h_proto);
            const size_t ethHeaderSize = ((ethProtocol == ETH_P_8021Q) ? (ETH_HLEN + 4) : (ETH_HLEN));
            const uint8_t* const ethData = sockData + ethHeaderSize;
            const size_t ethDataSize = sockDataSize - ethHeaderSize;

            const struct iphdr* const ipHeader = (const struct iphdr*)(ethData);
            const uint8_t ipIhl = ipHeader->ihl;
            const size_t ipHeaderSize = ipIhl * 4u;
            const uint8_t ipProtocol = ipHeader->protocol;
            const struct in_addr saddr = { .s_addr = (in_addr_t)(ipHeader->saddr) };
            const uint8_t* const ipData = ethData + ipHeaderSize;
            const size_t ipDataSize = ethDataSize - ipHeaderSize;



            if (ethProtocol == ETH_P_ARP) { handlePacket_arp(ethData, ethDataSize); }
            else if ((ethProtocol == ETH_P_IP) && (ipProtocol == IPPROTO_ICMP)) { handlePacket_icmp(&saddr, ipData, ipDataSize); }
        }
    }



    errno = 0;
    if (close(sockfd) != 0) { cli::printErrno("sniffer close socket failed", errno); }
}

} // namespace sniffer



#endif // OMW_PLAT_ *nix
