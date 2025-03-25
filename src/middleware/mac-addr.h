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
    Address() noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0 }
    {}

    explicit Address(const uint8_t* mac) noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0 }
    {
        if (mac)
        {
            for (size_t i = 0; i < this->size(); ++i) { m_buffer[i] = *(mac + i); }
        }
    }

    virtual ~Address() {}

    uint8_t* data() { return m_buffer; }
    const uint8_t* data() const { return m_buffer; }
    static constexpr size_t size() { return bufferSize; }

    uint8_t& operator[](std::size_t idx) { return m_buffer[idx]; }
    const uint8_t& operator[](std::size_t idx) const { return m_buffer[idx]; }

    bool getIG() const { return ((m_buffer[0] & 0x01) != 0); } ///< Returns the nI/G bit.
    bool getUL() const { return ((m_buffer[0] & 0x02) != 0); } ///< Returns the nU/L bit.

    bool isIndividual() const { return !getIG(); }
    bool isGroup() const { return getIG(); }
    bool isUniversal() const { return !getUL(); }
    bool isLocal() const { return getUL(); }

    std::string toString() const;

private:
    static constexpr size_t bufferSize = 6;
    uint8_t m_buffer[bufferSize];
};

} // namespace mac


#endif // IG_MIDDLEWARE_MACADDR_H
