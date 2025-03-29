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
#include <omw/color.h>
#include <omw/string.h>



static app::Vendor cacheLookup(const mac::Addr& mac);
static app::cache::Vendor onlineLookup(const mac::Addr& mac);
static omw::Color getVendorColor(const std::string& name);



app::Vendor app::lookupVendor(const mac::Addr& mac)
{
    app::Vendor vendor = cacheLookup(mac);

    if (vendor.name().empty())
    {
        const auto tmp = onlineLookup(mac);

        if (!tmp.name().empty() && (tmp.colour() != 0)) { app::cache::add(tmp); }

        vendor = app::Vendor(tmp.name(), getVendorColor(tmp.name()));
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

    const auto req = curl::Request(curl::Method::GET, "https://www.macvendorlookup.com/api/v2/" + mac.toString() + "/json", 30, 90);

#if PRJ_DEBUG && 0
    std::cout << req.toString() << std::endl;
#endif

#if 0 // don't enable until cache is implemented
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
#else
    vendor = app::cache::get(mac);
#endif

    return vendor;
}

omw::Color getVendorColor(const std::string& name)
{
    omw::Color c;

    omw::string ___tmp = name;
    const std::string lower = ___tmp.toLower_ascii();

    if (omw::contains(lower, "raspberry pi")) { c = 0xc51a4a; }
    else if (omw::contains(lower, "hach lange")) { c = 0x0098db; }
    else { c = 0; }

    return c;
}
