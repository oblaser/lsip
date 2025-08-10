/*
author          Oliver Blaser
date            10.08.2025
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

} // namespace sock


#endif // OMW_PLAT_ *nix

#endif // IG_MIDDLEWARE_SOCKET_UTIL_H
