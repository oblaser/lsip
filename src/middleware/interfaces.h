/*
author          Oliver Blaser
date            29.10.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_INTERFACES_H
#define IG_MIDDLEWARE_INTERFACES_H

#include <string>
#include <vector>


/**
 * @brief Get IP ranges of all interfaces.
 *
 * @return Formatted as cli arg strings
 */
std::vector<std::string> getIfIpRanges();


#endif // IG_MIDDLEWARE_INTERFACES_H
