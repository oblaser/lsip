/*
author          Oliver Blaser
date            05.04.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>

#include "middleware/cli.h"
#include "middleware/socket/util.h"
#include "project.h"

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



static int getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr);
static int sendArpRequest(const char* addrStr, const char* ifname, const struct sockaddr* ifaddr, const struct in_addr* taddr);



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
    err = getifaddr(ifname, sizeof(ifname), &ifaddr, AF_INET, addrStr, &taddr);
    if (err)
    {
        cli::printWarning("currently only ARP is implemented, devices can't be ARPed through NAT");
        return -(__LINE__);
    }

    err = sendArpRequest(addrStr, ifname, &ifaddr, &taddr);
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
        auto tryPop = [](const in_addr* taddr, uint8_t* macBuffer) { return false; };
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



/**
 * Get the network interface for wich `(if.addr ^ dst.addr) & if.mask` is zero.
 *
 * Currently only supports IPv4.
 *
 * If no interface matches, error is returned.
 *
 * @param [out] ifname
 * @param ifnameSize
 * @param [out] ifaddr
 * @param af Used to filter the list of interfaces
 * @param taddrStr Used to filter the list of interfaces
 * @param [out] taddr
 * @return 0 on success, negative on error
 */
int getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr)
{
    struct ifaddrs* iflist = NULL;
    void* pmtaddr = NULL; // polymorph target address
    struct in6_addr ___taddr6;
    struct in6_addr* const taddr6 = &___taddr6;

    if (af == AF_INET) { pmtaddr = taddr; }
    else { pmtaddr = taddr6; } // is ok here, inet_pton() failes if af is neither AF_INET nor AF_INET6

    if (inet_pton(af, taddrStr, pmtaddr) != 1)
    {
        cli::printError("invalid " + sock::aftos(af) + " address: " + std::string(taddrStr));
        return -(__LINE__);
    }

    if (getifaddrs(&iflist) != 0)
    {
        cli::printErrno("failed to get network interfaces", errno);
        return -(__LINE__);
    }

    int err = -1;
    const struct ifaddrs* ifa = iflist;
    while (ifa && err)
    {
        if (ifa->ifa_addr && (ifa->ifa_addr->sa_family == af))
        {
            if (af == AF_INET)
            {
                const struct sockaddr_in* const sa_addr = ((const struct sockaddr_in*)ifa->ifa_addr);
                const struct sockaddr_in* const sa_mask = ((const struct sockaddr_in*)ifa->ifa_netmask);

                if ((((sa_addr->sin_addr.s_addr) ^ (taddr->s_addr)) & (sa_mask->sin_addr.s_addr)) == 0)
                {
                    strncpy(ifname, ifa->ifa_name, ifnameSize);
                    *(ifname + ifnameSize - 1) = 0;

                    *ifaddr = *(ifa->ifa_addr);

                    err = 0;
                }
            }
            else if (af == AF_INET6)
            {
                // const struct sockaddr_in6* const sa_addr6 = ((const struct sockaddr_in6*)ifa->ifa_addr);
                // const struct sockaddr_in6* const sa_mask6 = ((const struct sockaddr_in6*)ifa->ifa_netmask);
                cli::printError("no IPv6 support in " + std::string(__func__));
            }
        }

#if PRJ_DEBUG && 0
        if (!err || 0)
        {
            static int cnt = 0;
            if (cnt++) { printf("\n"); }

            printf("%s\n", ifa->ifa_name);
            if (ifa->ifa_addr) { printf("    addr  %s\n", sockaddrtos(ifa->ifa_addr).c_str()); }
            if (ifa->ifa_netmask) { printf("    mask  %s\n", sockaddrtos(ifa->ifa_netmask).c_str()); }
            if (ifa->ifa_flags & IFF_BROADCAST) { printf("    broad %s\n", sockaddrtos(ifa->ifa_broadaddr).c_str()); }
            if (ifa->ifa_flags & IFF_POINTOPOINT) { printf("    dst   %s\n", sockaddrtos(ifa->ifa_dstaddr).c_str()); }
            // for `ifa->ifa_data` see https://man7.org/linux/man-pages/man3/getifaddrs.3.html
        }
#endif // PRJ_DEBUG

        ifa = ifa->ifa_next;
    }

    freeifaddrs(iflist);

    return err;
}

int sendArpRequest(const char* addrStr, const char* ifname, const struct sockaddr* ifaddr, const struct in_addr* taddr)
{
    const int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0)
    {
        cli::printErrno("failed to create socket", errno);
        return -(__LINE__);
    }

    struct ifreq ifreqifindex; // interface index
    strncpy(ifreqifindex.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifreqifindex) < 0)
    {
        cli::printErrno("failed to get index of interface \"" + std::string(ifname) + '"', errno);
        close(sockfd);
        return -(__LINE__);
    }

    struct ifreq ifreqha; // hardware address
    memset(&ifreqha, 0, sizeof(ifreqha));
    strncpy(ifreqha.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifreqha) < 0)
    {
        cli::printErrno("failed to get MAC address of interface \"" + std::string(ifname) + '"', errno);
        close(sockfd);
        return -(__LINE__);
    }

    const uint8_t* const localhaddr = (uint8_t*)(ifreqha.ifr_hwaddr.sa_data);       // local hardware address
    const struct in_addr* const localpaddr = &(((sockaddr_in*)(ifaddr))->sin_addr); // local protocol address
    const struct in_addr* const targetpaddr = taddr;                                // target protocol address

#if PRJ_DEBUG && 0
    {
        // also works with `void*`
        // const void* const localhaddr = ifreqha.ifr_hwaddr.sa_data;
        // const void* const localpaddr = &(((sockaddr_in*)(ifaddr))->sin_addr);

        const struct in_addr addr = *((struct in_addr*)localpaddr);
        // const uint32_t ip = *((uint32_t*)localpaddr);
        const uint32_t ip = ntohl(*((uint32_t*)localpaddr));
        const uint32_t a = ip >> 24;
        const uint32_t b = (ip >> 16) & 0x0FF;
        const uint32_t c = (ip >> 8) & 0x0FF;
        const uint32_t d = ip & 0x0FF;

        char addrStr[100];
        printf("%s   %s   %u.%u.%u.%u 0x%08x, %s\n\n", ifname, mac::EUI48((uint8_t*)localhaddr).toString().c_str(), a, b, c, d, ip,
               inet_ntop(AF_INET, &addr, addrStr, sizeof(addrStr)));
    }
#endif



    // serialise ARP packet

    constexpr size_t bufferSize = ETH_HLEN + sizeof(struct ether_arp) + /* padding */ 18;
    static_assert(bufferSize >= ETH_ZLEN, "layer 2 frame has to be at leaset 60 octets + 32bit CRC");
    uint8_t buffer[bufferSize];
    memset(buffer, 0, bufferSize);

    struct ethhdr* ethHeader = (struct ethhdr*)(buffer + 0);
    memset(ethHeader->h_dest, 0xFF, ETH_ALEN); // broadcast
    memcpy(ethHeader->h_source, &(ifreqha.ifr_hwaddr.sa_data), ETH_ALEN);
    ethHeader->h_proto = htons(ETH_P_ARP);

    struct ether_arp* ethArp = (struct ether_arp*)(buffer + ETH_HLEN);
    ethArp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    ethArp->ea_hdr.ar_pro = htons(ETH_P_IP);
    ethArp->ea_hdr.ar_hln = ETH_ALEN;
    ethArp->ea_hdr.ar_pln = sizeof(((struct ether_arp*)0)->arp_spa);
    ethArp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(ethArp->arp_sha, localhaddr, ETH_ALEN);
    memcpy(ethArp->arp_spa, localpaddr, sizeof(((struct ether_arp*)0)->arp_spa));
    memset(ethArp->arp_tha, 0, ETH_ALEN);
    memcpy(ethArp->arp_tpa, targetpaddr, sizeof(((struct ether_arp*)0)->arp_tpa));

#if PRJ_DEBUG && 0
    printL2Packet(buffer, bufferSize, NULL);
#endif



    // send ARP packet

    ssize_t n, transferred;
    struct sockaddr_ll dst_addr;
    dst_addr.sll_family = AF_PACKET;
    dst_addr.sll_protocol = htons(ETH_P_ARP);
    dst_addr.sll_ifindex = ifreqifindex.ifr_ifindex;
    dst_addr.sll_hatype = htons(ARPHRD_ETHER);
    // dst_addr.sll_pkttype = PACKET_BROADCAST;
    dst_addr.sll_pkttype = PACKET_OTHERHOST;
    dst_addr.sll_halen = ETH_ALEN;
    dst_addr.sll_addr[6] = 0x00;
    dst_addr.sll_addr[7] = 0x00;

    transferred = 0;
    while ((size_t)transferred < bufferSize)
    {
        n = sendto(sockfd, buffer, bufferSize, 0, (struct sockaddr*)(&dst_addr), sizeof(dst_addr));
        if (n < 0)
        {
            cli::printErrno("failed to send ARP packet for target " + std::string(addrStr), errno);
            close(sockfd);
            return -(__LINE__);
        }

        transferred += n;
    }



    close(sockfd);

    return 0;
}



#endif // OMW_PLAT_ *nix
