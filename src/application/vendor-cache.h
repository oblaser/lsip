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

#include "application/vendor.h"
#include "middleware/mac-addr.h"

#include <omw/color.h>


namespace app::cache {

class Vendor : public app::Vendor
{
public:
    Vendor()
        : app::Vendor(), m_addrBlock(mac::Type::CID)
    {}

    Vendor(const source_type& source, const mac::Type& addrBlock, const std::string& name)
        : app::Vendor(source, name), m_addrBlock(addrBlock)
    {}

    Vendor(const source_type& source, const mac::Type& addrBlock, const std::string& name, const omw::Color& colour)
        : app::Vendor(source, name, colour), m_addrBlock(addrBlock)
    {}

    virtual ~Vendor() {}

    const mac::Type& addrBlock() const { return m_addrBlock; }

private:
    mac::Type m_addrBlock;
};

void load();
void save();

app::Vendor get(const mac::Addr& mac);

/**
 * @brief Adds a new record in the MAC vendor lookup cache-
 *
 * @param mac Vendors OUI or any of it's MAC addresses
 * @param vendor
 */
void add(const mac::EUI48& mac, const app::cache::Vendor& vendor);

} // namespace app::cache


#endif // IG_APPLICATION_VENDORCACHE_H
