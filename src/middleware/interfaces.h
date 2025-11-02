/*
author          Oliver Blaser
date            29.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_INTERFACES_H
#define IG_MIDDLEWARE_INTERFACES_H

#include <string>
#include <vector>

#define MWIP_DONT_DEF_NAMESPACE_IP (1)
#include "middleware/ip-addr.h"



namespace interfaces {

/**
 * @brief Get IP ranges of all interfaces.
 *
 * @return Formatted as cli arg strings
 */
std::vector<std::string> getArgIpRanges();

/**
 * Searches for the network interface for wich `(if.addr ^ dst.addr) & if.mask` is zero.
 *
 * @param addr `dst.addr` see description
 * @return 0 on success, negative on error, 1 if no interface matches
 */
int findInterface(const mwip::Addr4& addr);

}


#endif // IG_MIDDLEWARE_INTERFACES_H
