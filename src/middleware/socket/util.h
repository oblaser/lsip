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

#include <sys/socket.h>



namespace sock {


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
int getifaddr(char* ifname, size_t ifnameSize, struct sockaddr* ifaddr, int af, const char* taddrStr, struct in_addr* taddr);

int sendArpRequest(const char* addrStr, const char* ifname, const struct sockaddr* ifaddr, const struct in_addr* taddr);


namespace util {

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
     * Converts a `sockaddr` to it's string representation, according to it's family.
     */
    std::string sockaddrtos(const struct sockaddr* sa);
    static inline std::string sockaddrtos(const struct sockaddr_in* sa) { return sockaddrtos((const struct sockaddr*)sa); }
    static inline std::string sockaddrtos(const struct sockaddr_in6* sa) { return sockaddrtos((const struct sockaddr*)sa); }

} // namespace util
} // namespace sock



#endif // OMW_PLAT_ *nix

#endif // IG_MIDDLEWARE_SOCKET_UTIL_H
