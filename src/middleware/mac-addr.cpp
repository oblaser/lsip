/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <string>

#include "mac-addr.h"

#include <omw/string.h>



std::string mac::toString(const Type& type)
{
    std::string str;

    switch (type)
    {
    case mac::Type::OUI:
        str = "OUI";
        break;

    case mac::Type::OUI28:
        str = "OUI28";
        break;

    case mac::Type::OUI36:
        str = "OUI36";
        break;

    case mac::Type::CID:
        str = "CID";
        break;
    }

    return str;
}

std::string mac::toAddrBlockString(const Type& type)
{
    std::string str;

    switch (type)
    {
    case mac::Type::OUI:
        str = "MA-L";
        break;

    case mac::Type::OUI28:
        str = "MA-M";
        break;

    case mac::Type::OUI36:
        str = "MA-S";
        break;

    case mac::Type::CID:
        str = "CID";
        break;
    }

    return str;
}



const mac::EUI48 mac::EUI48::null = mac::EUI48((uint64_t)0);
const mac::EUI48 mac::EUI48::max = mac::EUI48(0x0000FFFFFFFFFFFFllu);
const mac::EUI48 mac::EUI48::broadcast = mac::EUI48(0x0000FFFFFFFFFFFFllu);
const mac::EUI48 mac::EUI48::oui_mask = mac::EUI48(0x0000FFFFFF000000llu);
const mac::EUI48 mac::EUI48::oui28_mask = mac::EUI48(0x0000FFFFFFf00000llu);
const mac::EUI48 mac::EUI48::oui36_mask = mac::EUI48(0x0000FFFFFFfff000llu);

void mac::EUI48::set(const uint8_t* data) noexcept(true)
{
    if (data)
    {
        for (size_t i = 0; i < this->size(); ++i) { m_buffer[i] = *(data + i); }
    }
}

void mac::EUI48::set(uint64_t value) noexcept(true)
{
    m_buffer[0] = (uint8_t)(value >> 40);
    m_buffer[1] = (uint8_t)(value >> 32);
    m_buffer[2] = (uint8_t)(value >> 24);
    m_buffer[3] = (uint8_t)(value >> 16);
    m_buffer[4] = (uint8_t)(value >> 8);
    m_buffer[5] = (uint8_t)(value);
}

std::string mac::EUI48::toString(char delimiter) const { return omw::toHexStr(this->data(), this->size(), delimiter).toLower_ascii(); }



const mac::EUI64 mac::EUI64::null = mac::EUI64((uint64_t)0);
const mac::EUI64 mac::EUI64::max = mac::EUI64(0xFFFFFFFFFFFFFFFFllu);

void mac::EUI64::set(const uint8_t* data) noexcept(true)
{
    if (data)
    {
        for (size_t i = 0; i < this->size(); ++i) { m_buffer[i] = *(data + i); }
    }
}

void mac::EUI64::set(uint64_t value) noexcept(true)
{
    m_buffer[0] = (uint8_t)(value >> 56);
    m_buffer[1] = (uint8_t)(value >> 48);
    m_buffer[2] = (uint8_t)(value >> 40);
    m_buffer[3] = (uint8_t)(value >> 32);
    m_buffer[4] = (uint8_t)(value >> 24);
    m_buffer[5] = (uint8_t)(value >> 16);
    m_buffer[6] = (uint8_t)(value >> 8);
    m_buffer[7] = (uint8_t)(value);
}

std::string mac::EUI64::toString() const { return omw::toHexStr(this->data(), this->size(), '-').toLower_ascii(); }



mac::EUI64 mac::toEUI64(const mac::EUI48& EUI48)
{
    uint64_t r = 0;

    r |= (uint64_t)(EUI48[0]);
    r <<= 8;
    r |= (uint64_t)(EUI48[1]);
    r <<= 8;
    r |= (uint64_t)(EUI48[2]);
    r <<= 8;
    r |= (uint64_t)0xFF;
    r <<= 8;
    r |= (uint64_t)0xFE;
    r <<= 8;
    r |= (uint64_t)(EUI48[3]);
    r <<= 8;
    r |= (uint64_t)(EUI48[4]);
    r <<= 8;
    r |= (uint64_t)(EUI48[5]);

    return mac::EUI64(r | 0x0200000000000000llu);
}


bool mac::operator==(const mac::EUI48& a, const mac::EUI48& b)
{
    return ((a[0] == b[0]) && //
            (a[1] == b[1]) && //
            (a[2] == b[2]) && //
            (a[3] == b[3]) && //
            (a[4] == b[4]) && //
            (a[5] == b[5])    //
    );
}

mac::EUI48 mac::operator~(const mac::EUI48& a)
{
    mac::EUI48 r;
    r[0] = ~(a[0]);
    r[1] = ~(a[1]);
    r[2] = ~(a[2]);
    r[3] = ~(a[3]);
    r[4] = ~(a[4]);
    r[5] = ~(a[5]);
    return r;
}

mac::EUI48 mac::operator&(const mac::EUI48& a, const mac::EUI48& b)
{
    mac::EUI48 r;
    r[0] = (a[0] & b[0]);
    r[1] = (a[1] & b[1]);
    r[2] = (a[2] & b[2]);
    r[3] = (a[3] & b[3]);
    r[4] = (a[4] & b[4]);
    r[5] = (a[5] & b[5]);
    return r;
}

mac::EUI48 mac::operator|(const mac::EUI48& a, const mac::EUI48& b)
{
    mac::EUI48 r;
    r[0] = (a[0] | b[0]);
    r[1] = (a[1] | b[1]);
    r[2] = (a[2] | b[2]);
    r[3] = (a[3] | b[3]);
    r[4] = (a[4] | b[4]);
    r[5] = (a[5] | b[5]);
    return r;
}

mac::EUI48 mac::operator^(const mac::EUI48& a, const mac::EUI48& b)
{
    mac::EUI48 r;
    r[0] = (a[0] ^ b[0]);
    r[1] = (a[1] ^ b[1]);
    r[2] = (a[2] ^ b[2]);
    r[3] = (a[3] ^ b[3]);
    r[4] = (a[4] ^ b[4]);
    r[5] = (a[5] ^ b[5]);
    return r;
}
