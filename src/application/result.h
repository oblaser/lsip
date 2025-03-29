/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_APPLICATION_RESULT_H
#define IG_APPLICATION_RESULT_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"

#include <omw/color.h>


namespace app {

class Vendor
{
public:
    Vendor()
        : m_name(), m_colour(0, 0, 0, 0)
    {}

    Vendor(const char* name)
        : m_name(name), m_colour(0, 0, 0, 0)
    {}

    Vendor(const std::string& name)
        : m_name(name), m_colour(0, 0, 0, 0)
    {}

    Vendor(const std::string& name, const omw::Color colour)
        : m_name(name), m_colour(colour)
    {}

    virtual ~Vendor() {}

    const std::string& name() const { return m_name; }
    const omw::Color& colour() const { return m_colour; }

    bool hasColour() const { return (m_colour.a() == 0xFF); }

private:
    std::string m_name;
    omw::Color m_colour;
};

class ScanResult
{
public:
    ScanResult()
        : m_ip(ip::Addr4::null), m_mac(), m_duration(0), m_vendor()
    {}

    ScanResult(const ip::Addr4& ip, const mac::Addr& mac, uint32_t duration_ms, const Vendor& vendor)
        : m_ip(ip), m_mac(mac), m_duration(duration_ms), m_vendor(vendor)
    {}

    virtual ~ScanResult() {}

    const ip::Addr4& ip() const { return m_ip; }
    const mac::Addr& mac() const { return m_mac; }
    uint32_t duration() const { return m_duration; } ///< [ms]
    const Vendor& vendor() const { return m_vendor; }

    bool hostFound() const { return (m_ip != ip::Addr4::null); }
    bool knownVendor() const { return !m_vendor.name().empty(); }

private:
    ip::Addr4 m_ip;
    mac::Addr m_mac;
    uint32_t m_duration; // [ms]
    Vendor m_vendor;
};

} // namespace app


#endif // IG_APPLICATION_RESULT_H
