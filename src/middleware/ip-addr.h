/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_IPADDR_H
#define IG_MIDDLEWARE_IPADDR_H

#include <cstddef>
#include <cstdint>
#include <string>


namespace ip {

/**
 * @brief Interface class.
 */
class Address
{
public:
    Address() {}
    virtual ~Address() {}

    virtual std::string toString() const = 0;
};

class Addr4 : public Address
{
public:
    using value_type = uint32_t;
    static constexpr size_t octet_count = 4;
    static constexpr size_t bit_count = octet_count * 8;

    static const Addr4 null;      ///< all bits 0
    static const Addr4 max;       ///< all bits 1
    static const Addr4 broadcast; ///< broadcast address, all bits 1

public:
    Addr4() noexcept(true)
        : m_value(0)
    {}

    explicit Addr4(value_type addr) noexcept(true)
        : m_value(addr)
    {}

    Addr4(const char* str) noexcept(false)
        : m_value(0)
    {
        this->set(str);
    }

    Addr4(const std::string& str) noexcept(false)
        : m_value(0)
    {
        this->set(str);
    }

    Addr4(uint8_t hi, uint8_t mh, uint8_t ml, uint8_t lo) noexcept(true)
        : m_value(((value_type)hi << 24) | ((value_type)mh << 16) | ((value_type)ml << 8) | ((value_type)lo))
    {}

    virtual ~Addr4() {}

    /**
     * Expected format: `X.X.X.X`
     */
    virtual void set(const std::string& str) noexcept(false);

    virtual void set(value_type addr) noexcept(false) // might throw in derived class
    {
        m_value = addr;
    }

    virtual void set(uint8_t hi, uint8_t mh, uint8_t ml, uint8_t lo) noexcept(false) // might throw in derived class
    {
        m_value = (((value_type)hi << 24) | ((value_type)mh << 16) | ((value_type)ml << 8) | ((value_type)lo));
    }

    uint8_t octetHigh() const { return (uint8_t)(m_value >> 24); }
    uint8_t octetMidHi() const { return (uint8_t)(m_value >> 16); }
    uint8_t octetMidLo() const { return (uint8_t)(m_value >> 8); }
    uint8_t octetLow() const { return (uint8_t)(m_value); }

    value_type value() const { return m_value; }

    virtual std::string toString() const
    {
        return std::to_string(this->octetHigh()) + '.' + std::to_string(this->octetMidHi()) + '.' + std::to_string(this->octetMidLo()) + '.' +
               std::to_string(this->octetLow());
    }

protected:
    value_type m_value;
};

/**
 * @brief Interface class.
 */
class SubnetMask
{
public:
    SubnetMask() {}
    virtual ~SubnetMask() {}

    /**
     * Set the subnet mask as number of consecutive leading 1 bits. This is `X` in the CIDR notation `<IP>/X`.
     */
    virtual void setPrefixSize(int size) = 0;

    /**
     * Returns the number of consecutive leading 1 bits. This is `X` in the CIDR notation `<IP>/X`.
     */
    virtual uint8_t prefixSize() const = 0;

protected:
    /**
     * Has to be called after the value has been setted. Throws `std::invalid_argument` if the mask has non consecutive
     * leading 1 bits.
     */
    virtual void check() const noexcept(false) = 0;
};

class SubnetMask4 : public Addr4,
                    public SubnetMask
{
public:
    static const SubnetMask4 null; ///< all bits 0
    static const SubnetMask4 max;  ///< all bits 1

public:
    SubnetMask4() noexcept(true)
        : Addr4(0xFFFFFFFF)
    {}

    SubnetMask4(const ip::Addr4& mask) noexcept(false)
        : Addr4(mask)
    {
        this->check();
    }

    explicit SubnetMask4(int prefixSize) noexcept(false)
        : Addr4()
    {
        this->setPrefixSize(prefixSize);
        this->check();
    }

    SubnetMask4(const char* str) noexcept(false)
        : Addr4()
    {
        this->set(str);
        this->check();
    }

    SubnetMask4(const std::string& str) noexcept(false)
        : Addr4()
    {
        this->set(str);
        this->check();
    }

    SubnetMask4(uint8_t hi, uint8_t mh, uint8_t ml, uint8_t lo) noexcept(false)
        : Addr4(hi, mh, ml, lo)
    {
        this->check();
    }

    virtual ~SubnetMask4() {}

    /**
     * Expected format: `X.X.X.X`, `/X` or `<IP>/X` (where only `/X` is used, the format of IP is checked anyway)
     */
    virtual void set(const std::string& str) noexcept(false);

    virtual void set(value_type addr) noexcept(false)
    {
        Addr4::set(addr);
        this->check();
    }

    virtual void set(uint8_t hi, uint8_t mh, uint8_t ml, uint8_t lo) noexcept(false)
    {
        Addr4::set(hi, mh, ml, lo);
        this->check();
    }

    Addr4 hostMask() const { return Addr4(~m_value); }

    /**
     * See `ip::SubnetMask::setPrefixSize(int size)`.
     */
    virtual void setPrefixSize(int size);

    /**
     * See `ip::SubnetMask::prefixSize()`.
     */
    virtual uint8_t prefixSize() const;

protected:
    virtual void check() const noexcept(false);



    // hiding
private:
    static const Addr4 broadcast; // doesn't make sense in subnet mask
};



static inline std::string cidrString(const ip::Address& addr, const ip::SubnetMask& subnetMask)
{
    return addr.toString() + '/' + std::to_string(subnetMask.prefixSize());
}



//! \name Operators
/// @{

static inline bool operator==(const ip::Addr4& a, const ip::Addr4& b) { return (a.value() == b.value()); }
static inline bool operator!=(const ip::Addr4& a, const ip::Addr4& b) { return !(a == b); }
static inline bool operator<(const ip::Addr4& a, const ip::Addr4& b) { return (a.value() < b.value()); }
static inline bool operator>(const ip::Addr4& a, const ip::Addr4& b) { return (b < a); }
static inline bool operator<=(const ip::Addr4& a, const ip::Addr4& b) { return !(a > b); }
static inline bool operator>=(const ip::Addr4& a, const ip::Addr4& b) { return !(a < b); }

static inline ip::Addr4 operator~(const ip::Addr4& a) { return ip::Addr4(~a.value()); }
static inline ip::Addr4 operator&(const ip::Addr4& a, const ip::Addr4& b) { return ip::Addr4(a.value() & b.value()); }
static inline ip::Addr4 operator|(const ip::Addr4& a, const ip::Addr4& b) { return ip::Addr4(a.value() | b.value()); }
static inline ip::Addr4 operator^(const ip::Addr4& a, const ip::Addr4& b) { return ip::Addr4(a.value() ^ b.value()); }

static inline ip::SubnetMask4 operator~(const ip::SubnetMask4& a) { return ip::SubnetMask4(~a.value()); }
static inline ip::SubnetMask4 operator&(const ip::SubnetMask4& a, const ip::SubnetMask4& b) { return ip::SubnetMask4(a.value() & b.value()); }
static inline ip::SubnetMask4 operator|(const ip::SubnetMask4& a, const ip::SubnetMask4& b) { return ip::SubnetMask4(a.value() | b.value()); }
static inline ip::SubnetMask4 operator^(const ip::SubnetMask4& a, const ip::SubnetMask4& b) { return ip::SubnetMask4(a.value() ^ b.value()); }

static inline ip::Addr4 operator&(const ip::Addr4& a, const ip::SubnetMask4& b) { return ip::Addr4(a.value() & b.value()); }
static inline ip::Addr4 operator|(const ip::Addr4& a, const ip::SubnetMask4& b) { return ip::Addr4(a.value() | b.value()); }
static inline ip::Addr4 operator^(const ip::Addr4& a, const ip::SubnetMask4& b) { return ip::Addr4(a.value() ^ b.value()); }
static inline ip::Addr4 operator&(const ip::SubnetMask4& a, const ip::Addr4& b) { return ip::Addr4(a.value() & b.value()); }
static inline ip::Addr4 operator|(const ip::SubnetMask4& a, const ip::Addr4& b) { return ip::Addr4(a.value() | b.value()); }
static inline ip::Addr4 operator^(const ip::SubnetMask4& a, const ip::Addr4& b) { return ip::Addr4(a.value() ^ b.value()); }

/// @}



} // namespace ip


#endif // IG_MIDDLEWARE_IPADDR_H
