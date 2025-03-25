/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_APPLICATION_RESULT_H
#define IG_APPLICATION_RESULT_H

#include <cstddef>
#include <cstdint>

#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"


namespace app {

class ScanResult
{
public:
    ScanResult()
        : m_ip(ip::Addr4::null), m_mac(), m_duration(0)
    {}

    ScanResult(const ip::Addr4& ip, const mac::Address& mac, uint32_t duration_ms)
        : m_ip(ip), m_mac(mac), m_duration(duration_ms)
    {}

    virtual ~ScanResult() {}

    const ip::Addr4& ip() const { return m_ip; }
    const mac::Address& mac() const { return m_mac; }
    uint32_t duration() const { return m_duration; } ///< [ms]

private:
    ip::Addr4 m_ip;
    mac::Address m_mac;
    uint32_t m_duration; // [ms]
};

} // namespace app


#endif // IG_APPLICATION_RESULT_H
