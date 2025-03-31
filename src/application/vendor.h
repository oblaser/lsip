/*
author          Oliver Blaser
date            31.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_APPLICATION_VENDOR_H
#define IG_APPLICATION_VENDOR_H

#include <cstddef>
#include <cstdint>
#include <string>

#include <omw/color.h>


namespace app {

class Vendor
{
public:
    using source_type = char;
    class Source
    {
    public:
        static constexpr char api = 'a';
        static constexpr char cache = 'c';
        static constexpr char intermediate_cache = 'i';
    };

public:
    Vendor()
        : m_name(), m_colour(0), m_source('-')
    {}

    Vendor(const source_type& source, const char* name)
        : m_name(name), m_colour(0), m_source(source)
    {}

    Vendor(const source_type& source, const std::string& name)
        : m_name(name), m_colour(0), m_source(source)
    {}

    Vendor(const source_type& source, const std::string& name, const omw::Color colour)
        : m_name(name), m_colour(colour), m_source(source)
    {}

    virtual ~Vendor() {}

    const std::string& name() const { return m_name; }
    const omw::Color& colour() const { return m_colour; }
    const source_type& source() const { return m_source; }

    bool hasColour() const { return (m_colour.toRGB() != 0); }

    bool empty() const { return m_name.empty(); }

private:
    std::string m_name;
    omw::Color m_colour;
    source_type m_source;
};

} // namespace app


#endif // IG_APPLICATION_VENDOR_H
