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

enum class Type
{
    OUI,
    OUI28,
    OUI36,
    CID,
};

class EUI48
{
public:
    static constexpr size_t octet_count = 6;
    static constexpr size_t bit_count = octet_count * 8;

    static const EUI48 null;       ///< all bits 0
    static const EUI48 max;        ///< all bits 1
    static const EUI48 broadcast;  ///< broadcast address, all bits 1
    static const EUI48 oui_mask;   ///< MA-L mask `ff-ff-ff-00-00-00`
    static const EUI48 oui28_mask; ///< MA-M mask `ff-ff-ff-f0-00-00`
    static const EUI48 oui36_mask; ///< MA-S mask `ff-ff-ff-ff-f0-00`

public:
    EUI48() noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0 }
    {}

    /**
     * Six bytes are read from `data`.
     */
    explicit EUI48(const uint8_t* data) noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0 }
    {
        this->set(data);
    }

    /**
     * Format (big endian): `0x0000gghhjjkkmmoo` <=> `gg-hh-jj-kk-mm-oo`
     */
    explicit EUI48(uint64_t value) noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0 }
    {
        this->set(value);
    }

    virtual ~EUI48() {}



    /**
     * Six bytes are read from `data`.
     */
    void set(const uint8_t* data) noexcept(true);

    /**
     * Format (big endian): `0x0000gghhjjkkmmoo` <=> `gg-hh-jj-kk-mm-oo`
     */
    void set(uint64_t value) noexcept(true);

    bool getIG() const { return ((m_buffer[0] & 0x01) != 0); } ///< Returns the nI/G bit.
    bool getUL() const { return ((m_buffer[0] & 0x02) != 0); } ///< Returns the nU/L bit.

    bool isIndividual() const { return !getIG(); }
    bool isGroup() const { return getIG(); }
    bool isUniversal() const { return !getUL(); }
    bool isLocal() const { return getUL(); }

    bool isCID() const { return ((m_buffer[0] & 0x0F) == 0x0A); }

    std::string toString() const;


    //! \name Container like members
    /// @{

    uint8_t* data() { return m_buffer; }
    const uint8_t* data() const { return m_buffer; }
    static constexpr size_t size() { return octet_count; }

    uint8_t& operator[](std::size_t idx) { return m_buffer[idx]; }
    const uint8_t& operator[](std::size_t idx) const { return m_buffer[idx]; }

    /// @}


private:
    uint8_t m_buffer[octet_count];
};

using Addr = EUI48;



class EUI64
{
public:
    static constexpr size_t octet_count = 8;
    static constexpr size_t bit_count = octet_count * 8;

    static const EUI64 null; ///< all bits 0
    static const EUI64 max;  ///< all bits 1

public:
    EUI64() noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0, 0, 0 }
    {}

    /**
     * Eight bytes are read from `data`.
     */
    explicit EUI64(const uint8_t* data) noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0, 0, 0 }
    {
        this->set(data);
    }

    /**
     * Format (big endian): `0xgghhjjkkmmoopptt` <=> `gg-hh-jj-kk-mm-oo-pp-tt`
     */
    explicit EUI64(uint64_t value) noexcept(true)
        : m_buffer{ 0, 0, 0, 0, 0, 0, 0, 0 }
    {
        this->set(value);
    }

    virtual ~EUI64() {}



    /**
     * Eight bytes are read from `data`.
     */
    void set(const uint8_t* data) noexcept(true);

    /**
     * Format (big endian): `0xgghhjjkkmmoopptt` <=> `gg-hh-jj-kk-mm-oo-pp-tt`
     */
    void set(uint64_t value) noexcept(true);

    std::string toString() const;


    //! \name Container like members
    /// @{

    uint8_t* data() { return m_buffer; }
    const uint8_t* data() const { return m_buffer; }
    static constexpr size_t size() { return octet_count; }

    uint8_t& operator[](std::size_t idx) { return m_buffer[idx]; }
    const uint8_t& operator[](std::size_t idx) const { return m_buffer[idx]; }

    /// @}


private:
    uint8_t m_buffer[octet_count];
};



mac::EUI64 toEUI64(const mac::EUI48& EUI48);



//! \name Operators
/// @{

bool operator==(const mac::EUI48& a, const mac::EUI48& b);
static inline bool operator!=(const mac::EUI48& a, const mac::EUI48& b) { return !(a == b); }

mac::EUI48 operator~(const mac::EUI48& a);
mac::EUI48 operator&(const mac::EUI48& a, const mac::EUI48& b);
mac::EUI48 operator|(const mac::EUI48& a, const mac::EUI48& b);
mac::EUI48 operator^(const mac::EUI48& a, const mac::EUI48& b);

/// @}



} // namespace mac


#endif // IG_MIDDLEWARE_MACADDR_H
