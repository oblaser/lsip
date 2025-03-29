/*
author          Oliver Blaser
date            29.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_APPLICATION_VENDORCACHE_H
#define IG_APPLICATION_VENDORCACHE_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "middleware/mac-addr.h"


namespace app::cache {

class Vendor
{
public:
    Vendor()
        : m_name(), m_colour(0)
    {}

    Vendor(const char* name)
        : m_name(name), m_colour(0)
    {}

    Vendor(const std::string& name)
        : m_name(name), m_colour(0)
    {}

    /**
     * @brief Construct a new Vendor object
     *
     * @param name
     * @param colour format: `0x00RRGGBB`
     */
    Vendor(const std::string& name, const uint32_t colour)
        : m_name(name), m_colour(colour)
    {}

    virtual ~Vendor() {}

    const std::string& name() const { return m_name; }

    /**
     * @return format: `0x00RRGGBB`
     */
    uint32_t colour() const { return m_colour; }

private:
    std::string m_name;
    uint32_t m_colour;
};

void load();
app::cache::Vendor get(const mac::Addr& mac);
void add(const app::cache::Vendor& vendor);

} // namespace app::cache


#endif // IG_APPLICATION_VENDORCACHE_H
