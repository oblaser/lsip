/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <string>

#include "middleware/ip-addr.h"
#include "middleware/mac-addr.h"
#include "result.h"

#include <omw/color.h>



namespace vl // vendor list
{

struct Vendor
{
    Vendor() = delete;

    Vendor(uint64_t _oui, const std::string& _name)
        : oui(_oui), name(_name), colour(0, 0, 0, 0)
    {}

    /**
     * @brief Construct a new Vendor object
     *
     * @param _oui
     * @param _name
     * @param _colour format: `0x00RRGGBB`
     */
    Vendor(uint64_t _oui, const std::string& _name, uint32_t _colour)
        : oui(_oui), name(_name), colour(_colour)
    {}

    mac::EUI48 oui;
    std::string name;
    omw::Color colour;
};

constexpr uint32_t col_raspi = 0xC51A4A; // 0xC7053D;

const Vendor ma_l[] = {
    Vendor(0xB827EB000000, "Raspberry Pi Foundation", col_raspi),
    Vendor(0x2CCF67000000, "Raspberry Pi (Trading) Ltd", col_raspi),
    Vendor(0x88A29E000000, "Raspberry Pi (Trading) Ltd", col_raspi),
    Vendor(0xDCA632000000, "Raspberry Pi Trading Ltd", col_raspi),
    Vendor(0xD83ADD000000, "Raspberry Pi Trading Ltd", col_raspi),
    Vendor(0xE45F01000000, "Raspberry Pi Trading Ltd", col_raspi),
    Vendor(0x28CDC1000000, "Raspberry Pi Trading Ltd", col_raspi),

    Vendor(0xA8032A000000, "Espressif Inc."),
};

const Vendor ma_m[] = {
    Vendor(0xB8D812600000, "Vonger Electronic Technology Co.,Ltd."),
};

const Vendor ma_s[] = {
    Vendor(0, ""), // none
};

constexpr size_t ma_l_size = (sizeof(ma_l) / sizeof(ma_l[0]));
constexpr size_t ma_m_size = (sizeof(ma_m) / sizeof(ma_m[0]));
constexpr size_t ma_s_size = (sizeof(ma_s) / sizeof(ma_s[0]));

vl::Vendor get(const mac::Addr& mac);

} // namespace vl



void app::Vendor::set(const mac::Addr& mac)
{
    const auto v = vl::get(mac);
    m_name = v.name;
    m_colour = v.colour;
}



vl::Vendor vl::get(const mac::Addr& mac)
{
    for (size_t i = 0; i < ma_s_size; ++i)
    {
        if ((mac & mac::EUI48::oui36_mask) == ma_s[i].oui) { return ma_s[i]; }
    }

    for (size_t i = 0; i < ma_m_size; ++i)
    {
        if ((mac & mac::EUI48::oui28_mask) == ma_m[i].oui) { return ma_m[i]; }
    }

    for (size_t i = 0; i < ma_l_size; ++i)
    {
        if ((mac & mac::EUI48::oui_mask) == ma_l[i].oui) { return ma_l[i]; }
    }

    return vl::Vendor(0, "");
}
