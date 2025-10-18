/*
author          Oliver Blaser
date            10.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_SOCKET_UTIL_H
#define IG_MIDDLEWARE_SOCKET_UTIL_H

#include <cstdint>
#include <string>

#include <omw/defs.h>

#if (OMW_PLAT_UNIX || OMW_PLAT_LINUX || OMW_PLAT_APPLE) // *nix

#include <netinet/in.h>
#include <netinet/ip.h>

#include <sys/socket.h>



#define MAC_ADDRSTRLEN   18
#define AF_STRLEN        14
#define ETH_P_STRLEN     17
#define IPPROTO_STRLEN   17
#define ICMP_TYPE_STRLEN 15
#define SOCKADDRSTRLEN   54

#define SGR_BLACK           "\033[30m"
#define SGR_RED             "\033[31m"
#define SGR_GREEN           "\033[32m"
#define SGR_YELLOW          "\033[33m"
#define SGR_BLUE            "\033[34m"
#define SGR_MAGENTA         "\033[35m"
#define SGR_CYAN            "\033[36m"
#define SGR_WHITE           "\033[37m"
#define SGR_RGB(_r, _g, _b) "\033[38;2;" #_r ";" #_g ";" #_b "m"
#define SGR_DEFAULT         "\033[39m"
#define SGR_BBLACK          "\033[90m"
#define SGR_BRED            "\033[91m"
#define SGR_BGREEN          "\033[92m"
#define SGR_BYELLOW         "\033[93m"
#define SGR_BBLUE           "\033[94m"
#define SGR_BMAGENTA        "\033[95m"
#define SGR_BCYAN           "\033[96m"
#define SGR_BWHITE          "\033[97m"



namespace sock {


/**
 * Get the network interface for wich `(if.addr ^ dst.addr) & if.mask` is zero.
 *
 * Currently only supports IPv4.
 *
 * @param [out] ifname
 * @param ifnameSize
 * @param [out] ifaddr
 * @param af Used to filter the list of interfaces
 * @param taddrStr Used to filter the list of interfaces
 * @param [out] taddr
 * @return 0 on success, negative on error, 1 if no interface matches
 */
int getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr);

int sendArpRequest(const char* addrStr, const char* ifname, const struct sockaddr* ifaddr, const struct in_addr* taddr);

int sendEchoRequest(const struct in_addr* taddr);


namespace util {


#define ARPDATA_HLEN (6) // hardware address length
#define ARPDATA_PLEN (4) // protocol address length

    /**
     * @brief Ethernet IPv4 ARP data container.
     *
     * - hardware address: MAC/EUI48
     * - protocol address: IPv4 address
     */
    struct arpdata
    {
        uint8_t ar_sha[ARPDATA_HLEN]; // sender hardware address
        uint8_t ar_spa[ARPDATA_PLEN]; // sender protocol address
        uint8_t ar_tha[ARPDATA_HLEN]; // target hardware address
        uint8_t ar_tpa[ARPDATA_PLEN]; // target protocol address
    } __attribute__((packed));



    struct ippseudohdr
    {
        struct sockaddr_storage saddr;
        struct sockaddr_storage daddr;
        uint32_t length; // number of TCP/UDP packet octets = TCP/UDP header size + TCP/UDP payload size
                         //                                 = IP packet size - IP header size (=IHL*4)
        uint8_t protocol;
    };

    /**
     * @param [out] dst
     * @param iphdr
     * @return `dst`
     */
    struct ippseudohdr* ippseudohdr_init(struct ippseudohdr* dst, const struct iphdr* iphdr);

    uint16_t inet_checksum(const uint8_t* data, size_t count);

    static inline void inet_checksum_init(uint32_t* sum) { *sum = 0; }

    void inet_checksum_update(uint32_t* sum, const uint8_t* data, size_t count);

    static inline void inet_checksum_update16h(uint32_t* sum, uint16_t value) { *sum += value; }
    static inline void inet_checksum_update16n(uint32_t* sum, uint16_t value) { *sum += ntohs(value); }
    static inline void inet_checksum_update32h(uint32_t* sum, uint32_t value) { *sum += (value >> 16) + (value & 0x0000FFFF); }
    static inline void inet_checksum_update32n(uint32_t* sum, uint32_t value) { inet_checksum_update32h(sum, ntohl(value)); }

    void inet_checksum_update_ippseudohdr(uint32_t* sum, const struct ippseudohdr* pseudoHdr);
    uint16_t inet_checksum_final(uint32_t* sum);

    /**
     * @brief Address family to string.
     *
     * @param af `AF_*`
     */
    std::string aftos(int af);

    /**
     * @brief Ethernet protocol to string
     *
     * @param proto `ETH_P_*`
     */
    std::string ethptos(uint32_t proto);

    /**
     * @brief IP protocol to string.
     *
     * @param proto `IPPROTO_*`
     */
    std::string ipptos(uint32_t proto);

    /**
     * @brief ICMP type to string.
     */
    std::string icmpttos(uint8_t type);

    /**
     * Converts a `sockaddr` to it's string representation, according to it's family.
     */
    std::string sockaddrtos(const struct sockaddr* sa);
    static inline std::string sockaddrtos(const struct sockaddr_in* sa) { return sockaddrtos((const struct sockaddr*)sa); }
    static inline std::string sockaddrtos(const struct sockaddr_in6* sa) { return sockaddrtos((const struct sockaddr*)sa); }

    std::string inaddrtos(const struct in_addr* addr);
    std::string inaddrtos(in_addr_t addr);

} // namespace util
} // namespace sock



#endif // OMW_PLAT_ *nix

#endif // IG_MIDDLEWARE_SOCKET_UTIL_H
