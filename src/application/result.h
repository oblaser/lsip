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

#include "application/vendor.h"
#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"

#include <omw/color.h>


namespace app {

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

    bool empty() const { return (m_ip == ip::Addr4::null); }

private:
    ip::Addr4 m_ip;
    mac::Addr m_mac;
    uint32_t m_duration; // [ms]
    Vendor m_vendor;
};

} // namespace app


#endif // IG_APPLICATION_RESULT_H
