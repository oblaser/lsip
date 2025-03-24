/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_MACADDR_H
#define IG_MIDDLEWARE_MACADDR_H

#include <cstddef>
#include <cstdint>
#include <string>


namespace mac {

class Address
{
public:
    Address() noexcept(true) {}

    virtual ~Address() {}
};

} // namespace mac


#endif // IG_MIDDLEWARE_MACADDR_H
