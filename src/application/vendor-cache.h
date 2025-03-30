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

#include <omw/color.h>


namespace app::cache {

class Vendor
{
public:
    Vendor()
        : m_addrBlock(mac::Type::CID), m_name(), m_colour(0)
    {}

    Vendor(const mac::Type& addrBlock, const char* name)
        : m_addrBlock(addrBlock), m_name(name), m_colour(0)
    {}

    Vendor(const mac::Type& addrBlock, const std::string& name)
        : m_addrBlock(addrBlock), m_name(name), m_colour(0)
    {}

    Vendor(const mac::Type& addrBlock, const std::string& name, const omw::Color& colour)
        : m_addrBlock(addrBlock), m_name(name), m_colour(colour)
    {}

    virtual ~Vendor() {}

    const mac::Type& addrBlock() const { return m_addrBlock; }
    const std::string& name() const { return m_name; }
    const omw::Color& colour() const { return m_colour; }

    bool empty() const { return m_name.empty(); }

protected:
    void setName(const std::string& name) { m_name = name; }
    void setColour(const omw::Color& colour) { m_colour = colour; }

private:
    mac::Type m_addrBlock;
    std::string m_name;
    omw::Color m_colour;
};

void load();
void save();

app::cache::Vendor get(const mac::Addr& mac);

/**
 * @brief Adds a new record in the MAC vendor lookup cache-
 *
 * @param mac Vendors OUI or any of it's MAC addresses
 * @param vendor
 */
void add(const mac::EUI48& mac, const app::cache::Vendor& vendor);

} // namespace app::cache


#endif // IG_APPLICATION_VENDORCACHE_H
