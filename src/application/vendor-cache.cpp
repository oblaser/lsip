/*
author          Oliver Blaser
date            29.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include "middleware/cli.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "vendor-cache.h"

#include <json/json.hpp>
#include <omw/string.h>



class Record : public app::cache::Vendor
{
public:
    Record()
        : Vendor(), m_type(), m_oui(mac::EUI48::null)
    {}

    Record(const std::string& name, const uint32_t colour, const mac::Type& type, const mac::EUI48& oui)
        : Vendor(name, colour), m_type(type), m_oui(oui)
    {}

    virtual ~Record() {}

    const mac::Type& type() const { return m_type; }
    const mac::EUI48& oui() const { return m_oui; }

private:
    mac::Type m_type;
    mac::EUI48 m_oui;
};



static std::mutex ___cache_mtx;
using lock_guard = std::lock_guard<std::mutex>;
#define MTX_LG()     lock_guard ___lg_cache_mtx(___cache_mtx)
#define MTX_LOCK()   ___cache_mtx.lock()
#define MTX_UNLOCK() ___cache_mtx.unlock()

static std::vector<Record> ma_l, ma_m, ma_s;



void app::cache::load() { MTX_LG(); }

app::cache::Vendor app::cache::get(const mac::Addr& mac)
{
    MTX_LG();

    app::cache::Vendor v = app::cache::Vendor();
    bool found = false;



    const auto oui36 = (mac & mac::EUI48::oui36_mask);

    for (size_t i = 0; (i < ma_s.size()) && !found; ++i)
    {
        if (oui36 == ma_s[i].oui()) { return ma_s[i]; }
    }



    const auto oui28 = (mac & mac::EUI48::oui28_mask);

    for (size_t i = 0; (i < ma_m.size()) && !found; ++i)
    {
        if (oui28 == ma_m[i].oui()) { return ma_m[i]; }
    }



    const auto oui = (mac & mac::EUI48::oui_mask);

    for (size_t i = 0; (i < ma_l.size()) && !found; ++i)
    {
        if (oui == ma_l[i].oui()) { return ma_l[i]; }
    }



    return v;
}

void app::cache::add(const app::cache::Vendor& vendor) { MTX_LG(); }
