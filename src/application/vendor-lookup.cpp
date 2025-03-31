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
#include "application/vendor-cache.h"
#include "middleware/cli.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "vendor-lookup.h"

#include <curl-thread/curl.h>
#include <json/json.hpp>
#include <omw/clock.h>
#include <omw/color.h>
#include <omw/string.h>


#define USE_API (0) // only affects debug builds


using json = nlohmann::json;



static app::Vendor cacheLookup(const mac::Addr& mac);
static app::cache::Vendor onlineLookup(const mac::Addr& mac);
static app::cache::Vendor parseApiResponse(const std::string& body);
static omw::Color getVendorColour(const std::string& name);



app::Vendor app::lookupVendor(const mac::Addr& mac)
{
    app::Vendor vendor = cacheLookup(mac);

    if (vendor.empty())
    {
        const auto tmp = onlineLookup(mac);
        if (!tmp.empty()) { app::cache::add(mac, tmp); }

        vendor = app::Vendor(tmp.name(), getVendorColour(tmp.name()));
    }

    return vendor;
}



app::Vendor cacheLookup(const mac::Addr& mac)
{
    const auto v = app::cache::get(mac);
    return app::Vendor(v.name(), v.colour());
}

app::cache::Vendor onlineLookup(const mac::Addr& mac)
{
    app::cache::Vendor vendor;

#if USE_API || !PRJ_DEBUG

    const auto req = curl::Request(curl::Method::GET, "https://www.macvendorlookup.com/api/v2/" + mac.toString() + "/json", 30, 90);
    const auto curlId = curl::queueRequest(req, curl::Priority::normal);
    if (curlId.isValid())
    {
        while (!curl::responseReady(curlId)) {}
        const auto res = curl::popResponse();

        if (res.good()) { vendor = parseApiResponse(res.body()); }
        else
        {
#if PRJ_DEBUG && 1
            std::cout << res.toString() << std::endl;
#endif
        }
    }
    else { cli::printError("curl queue ID: " + curlId.toString()); }

    if (vendor.empty()) { cli::printError("failed to lookup " + mac.toString() + " online"); }

#else // USE_API

    mac::Type addrBlock;
    std::string name;

    if ((mac & mac::EUI48::oui28_mask) == mac::Addr(0xB8D812600000))
    {
        addrBlock = mac::Type::OUI28;
        name = "Vonger Electronic Technology Co.,Ltd.";
    }
    else if ((mac & mac::EUI48::oui_mask) == mac::Addr(0xB827EB000000))
    {
        addrBlock = mac::Type::OUI;
        name = "Raspberry Pi Foundation";
    }
    else if (((mac & mac::EUI48::oui_mask) == mac::Addr(0x2CCF67000000)) || ((mac & mac::EUI48::oui_mask) == mac::Addr(0x88A29E000000)))
    {
        addrBlock = mac::Type::OUI;
        name = "Raspberry Pi (Trading) Ltd";
    }
    else if (((mac & mac::EUI48::oui_mask) == mac::Addr(0xDCA632000000)) || ((mac & mac::EUI48::oui_mask) == mac::Addr(0xD83ADD000000)) ||
             ((mac & mac::EUI48::oui_mask) == mac::Addr(0xE45F01000000)) || ((mac & mac::EUI48::oui_mask) == mac::Addr(0x28CDC1000000)))
    {
        addrBlock = mac::Type::OUI;
        name = "Raspberry Pi Trading Ltd";
    }
    else if ((mac & mac::EUI48::oui_mask) == mac::Addr(0x00136A000000))
    {
        addrBlock = mac::Type::OUI;
        name = "Hach Lange Sarl";
    }
    else if ((mac & mac::EUI48::oui_mask) == mac::Addr(0xA8032A000000))
    {
        addrBlock = mac::Type::OUI;
        name = "Espressif Inc.";
    }

    vendor = app::cache::Vendor(addrBlock, name, getVendorColour(name));

#endif // USE_API

    return vendor;
}

app::cache::Vendor parseApiResponse(const std::string& body)
{
    app::cache::Vendor vendor;

    try
    {
        const json j = json::parse(body)[0];

        const std::string name = j["company"];
        const std::string type = omw::string(j["type"]).toLower_ascii();
        mac::Type addrBlock;

        if ((type == "oui36") || (type == "ma-s")) { addrBlock = mac::Type::OUI36; }
        else if ((type == "oui28") || (type == "ma-m")) { addrBlock = mac::Type::OUI28; }
        else if ((type == "oui24") || (type == "oui") || (type == "ma-l")) { addrBlock = mac::Type::OUI; }
        else { throw -(__LINE__); }

#if PRJ_DEBUG && 1
        std::cout << "API: " << type << " => " << mac::toAddrBlockString(addrBlock) << " \"" << name << '"' << std::endl;
#endif

        vendor = app::cache::Vendor(addrBlock, name, getVendorColour(name));
    }
    catch (...)
    {}

    return vendor;
}

omw::Color getVendorColour(const std::string& name)
{
    omw::Color c;

    omw::string ___tmp = name;
    const std::string lower = ___tmp.toLower_ascii();

    if (omw::contains(lower, "raspberry pi")) { c = 0xc51a4a; }
    else if (omw::contains(lower, "hach lange")) { c = 0x0098db; }
    else { c = 0; }

    return c;
}
