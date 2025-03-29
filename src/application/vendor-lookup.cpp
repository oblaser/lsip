/*
author          Oliver Blaser
date            29.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "application/result.h"
#include "middleware/cli.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "vendor-lookup.h"

#include <curl-thread/curl.h>
#include <json/json.hpp>
#include <omw/color.h>
#include <omw/string.h>



namespace db = app;



static app::Vendor cacheLookup(const mac::Addr& mac);
static db::Vendor onlineLookup(const mac::Addr& mac);
static omw::Color getVendorColor(const std::string& name);



app::Vendor app::lookupVendor(const mac::Addr& mac)
{
    app::Vendor vendor = cacheLookup(mac);

    if (vendor.name().empty())
    {
        const auto tmp = onlineLookup(mac);

        // TODO add to cache

        vendor = app::Vendor(tmp.name(), getVendorColor(tmp.name()));
    }

    return vendor;
}



#ifndef ___REGION_TODO_REMOVE // TODO remove and implement cache

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

constexpr uint32_t col_raspi = 0xC51A4A;

const Vendor ma_l[] = {
    Vendor(0xB827EB000000, "Raspberry Pi Foundation", col_raspi),
    Vendor(0x2CCF67000000, "Raspberry Pi (Trading) Ltd", col_raspi),
    Vendor(0x88A29E000000, "Raspberry Pi (Trading) Ltd", col_raspi),
    Vendor(0xDCA632000000, "Raspberry Pi Trading Ltd", col_raspi),
    Vendor(0xD83ADD000000, "Raspberry Pi Trading Ltd", col_raspi),
    Vendor(0xE45F01000000, "Raspberry Pi Trading Ltd", col_raspi),
    Vendor(0x28CDC1000000, "Raspberry Pi Trading Ltd", col_raspi),

    Vendor(0x00136A000000, "Hach Lange Sarl"),

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

vl::Vendor get(const mac::Addr& mac)
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

} // namespace vl

#endif //___REGION_TODO_REMOVE



app::Vendor cacheLookup(const mac::Addr& mac)
{
    const auto v = vl::get(mac);
    return app::Vendor(v.name, v.colour);
}

db::Vendor onlineLookup(const mac::Addr& mac)
{
    db::Vendor vendor;

#if 0
    const auto req = curl::Request(curl::Method::GET, "https://www.macvendorlookup.com/api/v2/" + mac.toString() + "/json", 30, 90);
    const auto curlId = curl::queueRequest(req, curl::Priority::normal);
    if (curlId.isValid())
    {
        while (!curl::responseReady(curlId)) {}
        const auto res = curl::popResponse();

        if (res.good())
        {
            // TODO parse response
        }
        else { std::cout << res.toString() << std::endl; }
    }
    else { std::cout << "curl queue ID: " << curlId.toString() << std::endl; }

    if (!vendor.isValid()) { cli::printError("failed to lookup " + mac.toString() + " online"); }
#endif

    return vendor;
}

omw::Color getVendorColor(const std::string& name)
{
    omw::Color c;

    omw::string ___tmp = name;
    const std::string lower = ___tmp.toLower_ascii();

    if (omw::contains(name, "Raspberry Pi")) { c = 0xC51A4A; }
    else
    {
        c.setARGB(0); // no vendor colour
    }

    return c;
}
