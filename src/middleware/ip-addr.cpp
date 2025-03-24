/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>


#include "ip-addr.h"

#include <omw/defs.h>
#include <omw/int.h>
#include <omw/string.h>



// these two are not static on purpose
ip::Addr4::value_type ___ip_addr_getDummy();
void ___ip_addr_setDummy(ip::Addr4::value_type addr);



const ip::Addr4 ip::Addr4::null = ip::Addr4(0, 0, 0, 0);
const ip::Addr4 ip::Addr4::max = ip::Addr4(255, 255, 255, 255);
const ip::Addr4 ip::Addr4::broadcast = ip::Addr4(255, 255, 255, 255);

void ip::Addr4::set(const std::string& str) noexcept(false)
{
    constexpr std::string_view fnName = "ip::Addr4::set";

    const auto tokens = omw::split(str, '.');

    if ((tokens.size() == 4) && omw::isUInteger(tokens[0]) && omw::isUInteger(tokens[1]) && omw::isUInteger(tokens[2]) && omw::isUInteger(tokens[3]))
    {
        const int hi = std::stoi(tokens[0]);
        const int mh = std::stoi(tokens[1]);
        const int ml = std::stoi(tokens[2]);
        const int lo = std::stoi(tokens[3]);

        if ((hi <= UINT8_MAX) && (mh <= UINT8_MAX) && (ml <= UINT8_MAX) && (lo <= UINT8_MAX)) { this->set(hi, mh, ml, lo); }
        else { throw std::out_of_range(fnName.data()); }
    }
    else { throw std::invalid_argument(fnName.data()); }
}



const ip::SubnetMask4 ip::SubnetMask4::null = ip::SubnetMask4(0);
const ip::SubnetMask4 ip::SubnetMask4::max = ip::SubnetMask4(ip::Addr4::bit_count);

void ip::SubnetMask4::set(const std::string& str) noexcept(false)
{
    constexpr std::string_view fnName = "ip::SubnetMask4::set";

    const size_t slashPos = str.find('/');

    if (slashPos != std::string::npos)
    {
        // check the format of IP
        if (slashPos > 0)
        {
            try
            {
                const Addr4 ip = str.substr(0, slashPos);
                ___ip_addr_setDummy(ip.value());
            }
            catch (const std::invalid_argument& ex)
            {
                if (omw::contains(ex.what(), "ip::")) { throw std::invalid_argument(fnName.data()); }
                else { throw ex; }
            }
            catch (const std::out_of_range& ex)
            {
                if (omw::contains(ex.what(), "ip::")) { throw std::out_of_range(fnName.data()); }
                else { throw ex; }
            }
            // other exceptions are not handled here
        }

        const auto prefixSizeStr = str.substr(slashPos + 1);

        if (omw::isUInteger(prefixSizeStr))
        {
            const int prefixSize = std::stoi(prefixSizeStr);
            this->setPrefixSize(prefixSize);
        }
        else { throw std::invalid_argument(fnName.data()); }
    }
    else { Addr4::set(str); }

    this->check();
}

void ip::SubnetMask4::setPrefixSize(int size)
{
    constexpr std::string_view fnName = "ip::SubnetMask4::setPrefixSize";

    constexpr int max = (int)bit_count;

    if ((size > 0) && (size < max)) { m_value = ~(((value_type)1 << (max - size)) - 1); }
    else if (size == 0) { m_value = 0; }
    else if (size == max) { m_value = 0xFFFFFFFF; }
    else { throw std::out_of_range(fnName.data()); }
}

uint8_t ip::SubnetMask4::prefixSize() const
{
    uint8_t r = 0;
    static_assert(UINT8_MAX >= bit_count);

    uint32_t mask = 0x01;
    static_assert(sizeof(mask) * 8 == bit_count);

    while (mask)
    {
        if (m_value & mask) { ++r; }

        mask <<= 1;
    }

    return r;
}

void ip::SubnetMask4::check() const noexcept(false)
{
    constexpr std::string_view fnName = "ip::SubnetMask4::check";

    bool hostIdentifier = false;

    uint32_t mask = OMW_32BIT_MSB;
    static_assert(sizeof(mask) * 8 == bit_count);

    while (mask)
    {
        if (m_value & mask)
        {
            if (hostIdentifier) { throw std::invalid_argument(fnName.data()); }
        }
        else { hostIdentifier = true; }

        mask >>= 1;
    }
}



//======================================================================================================================
// this prevents certain code from getting optimised away

static ip::Addr4::value_type ___ip_addr_dummy;
static std::mutex ___ip_addr_dummy_mtx;

ip::Addr4::value_type ___ip_addr_getDummy()
{
    std::lock_guard<std::mutex> lg(___ip_addr_dummy_mtx);
    return ___ip_addr_dummy;
}

void ___ip_addr_setDummy(ip::Addr4::value_type addr)
{
    std::lock_guard<std::mutex> lg(___ip_addr_dummy_mtx);
    ___ip_addr_dummy = addr;
}
