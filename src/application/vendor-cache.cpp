/*
author          Oliver Blaser
date            29.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include "application/vendor.h"
#include "middleware/cli.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "vendor-cache.h"

#include <json/json.hpp>
#include <omw/clock.h>
#include <omw/string.h>
#include <omw/version.h>
#include <omw/windows/windows.h>


#define USE_DEBUG_PATH (1)


namespace fs = std::filesystem;



template <app::Vendor::source_type __src> class ___Record : public app::Vendor
{
public:
    ___Record()
        : app::Vendor(), m_oui(mac::EUI48::null)
    {}

    ___Record(const std::string& name, const omw::Color colour, const mac::EUI48& oui)
        : app::Vendor(__src, name, colour), m_oui(oui)
    {}

    virtual ~___Record() {}

    const mac::EUI48& oui() const { return m_oui; }

private:
    mac::EUI48 m_oui;
};

using Record = ___Record<app::Vendor::Source::cache>;
using IntermediateRecord = ___Record<app::Vendor::Source::intermediate_cache>;



#if 1 // write precedence is not guaranteed
#include <shared_mutex>

static std::shared_mutex ___shmtx;

#define MTX_EX_LOCK()                                                       \
    {                                                                       \
        const auto t = omw::clock::now();                                   \
        ___shmtx.lock();                                                    \
        THREAD_PRINT("EX " + std::to_string(omw::clock::now() - t) + "us"); \
    }

#define MTX_EX_UNLOCK()    \
    {                      \
        ___shmtx.unlock(); \
    }

#define MTX_SH_LOCK()                                                       \
    {                                                                       \
        const auto t = omw::clock::now();                                   \
        ___shmtx.lock_shared();                                             \
        THREAD_PRINT("SH " + std::to_string(omw::clock::now() - t) + "us"); \
    }

#define MTX_SH_UNLOCK()           \
    {                             \
        ___shmtx.unlock_shared(); \
    }


#define MTX_LOCK_WR()   MTX_EX_LOCK()
#define MTX_UNLOCK_WR() MTX_EX_UNLOCK()
#define MTX_LOCK_RD()   MTX_SH_LOCK()
#define MTX_UNLOCK_RD() MTX_SH_UNLOCK()

#else // only one thread can lookup at once

#ifndef _MSC_VER
#warning "the other option fits better to the philosophy of having a cache"
#endif

// #error "does not make sens in combination with the intermediate cache"

static std::mutex ___mtx_data, ___mtx_prio, ___mtx_lo;

#define MTX_PRIO_HI_LOCK()                                                  \
    {                                                                       \
        const auto t = omw::clock::now();                                   \
        ___mtx_prio.lock();                                                 \
        ___mtx_data.lock();                                                 \
        ___mtx_prio.unlock();                                               \
        THREAD_PRINT("HI " + std::to_string(omw::clock::now() - t) + "us"); \
    }

#define MTX_PRIO_HI_UNLOCK()  \
    {                         \
        ___mtx_data.unlock(); \
    }

#define MTX_PRIO_LO_LOCK()                                                  \
    {                                                                       \
        const auto t = omw::clock::now();                                   \
        ___mtx_lo.lock();                                                   \
        ___mtx_prio.lock();                                                 \
        ___mtx_data.lock();                                                 \
        ___mtx_prio.unlock();                                               \
        THREAD_PRINT("LO " + std::to_string(omw::clock::now() - t) + "us"); \
    }

#define MTX_PRIO_LO_UNLOCK()  \
    {                         \
        ___mtx_data.unlock(); \
        ___mtx_lo.unlock();   \
    }

#define MTX_LOCK_WR()   MTX_PRIO_HI_LOCK()
#define MTX_UNLOCK_WR() MTX_PRIO_HI_UNLOCK()
#define MTX_LOCK_RD()   MTX_PRIO_LO_LOCK()
#define MTX_UNLOCK_RD() MTX_PRIO_LO_UNLOCK()
#endif



static std::vector<Record> ma_l, ma_m, ma_s;
static bool changed = false;



static fs::path getFilePath();
static void readCacheFile(const fs::path& filepath);
static void writeCacheFile(const fs::path& filepath);



void app::cache::load()
{
    MTX_LOCK_WR();

    const fs::path filepath = getFilePath();

    if (fs::exists(filepath)) { readCacheFile(filepath); }
    else
    {
        changed = true;

        const auto parentpath = filepath.parent_path();
        if (!fs::exists(parentpath))
        {
            try
            {
                if (!fs::create_directory(parentpath)) { throw -(__LINE__); }
            }
            catch (const std::exception& ex)
            {
                cli::printError("failed to create directory \"" + parentpath.u8string() + "\"", ex.what());
            }
            catch (...)
            {
                cli::printError("failed to create directory \"" + parentpath.u8string() + "\"");
            }
        }
    }

    MTX_UNLOCK_WR();
}

void app::cache::save()
{
    MTX_LOCK_RD();

    if (changed) { writeCacheFile(getFilePath()); }

    MTX_UNLOCK_RD();
}

app::Vendor app::cache::get(const mac::Addr& mac)
{
    MTX_LOCK_RD();

    const std::vector<Record>& rd_ma_l = ma_l;
    const std::vector<Record>& rd_ma_m = ma_m;
    const std::vector<Record>& rd_ma_s = ma_s;

    app::Vendor v = app::Vendor();
    bool found = false;



    const auto oui36 = (mac & mac::EUI48::oui36_mask);

    for (size_t i = 0; (i < rd_ma_s.size()) && !found; ++i)
    {
        if (oui36 == rd_ma_s[i].oui()) { v = rd_ma_s[i]; }
    }



    const auto oui28 = (mac & mac::EUI48::oui28_mask);

    for (size_t i = 0; (i < rd_ma_m.size()) && !found; ++i)
    {
        if (oui28 == rd_ma_m[i].oui()) { v = rd_ma_m[i]; }
    }



    const auto oui = (mac & mac::EUI48::oui_mask);

    for (size_t i = 0; (i < rd_ma_l.size()) && !found; ++i)
    {
        if (oui == rd_ma_l[i].oui()) { v = rd_ma_l[i]; }
    }



    MTX_UNLOCK_RD();

    return v;
}

void app::cache::add(const mac::EUI48& mac, const app::cache::Vendor& vendor)
{
    MTX_LOCK_WR();

    try
    {
        switch (vendor.addrBlock())
        {
        case mac::Type::OUI:
            ma_l.push_back(Record(vendor.name(), vendor.colour(), (mac & mac::EUI48::oui_mask)));
            changed = true;
            break;

        case mac::Type::OUI28:
            ma_m.push_back(Record(vendor.name(), vendor.colour(), (mac & mac::EUI48::oui28_mask)));
            changed = true;
            break;

        case mac::Type::OUI36:
            ma_s.push_back(Record(vendor.name(), vendor.colour(), (mac & mac::EUI48::oui36_mask)));
            changed = true;
            break;

        case mac::Type::CID:
            cli::printWarning("can't add CID to cache");
            break;
        }
    }
    catch (const std::exception& ex)
    {
        cli::printError("failed to add \"" + vendor.name() + "\" to cache", ex.what());
    }
    catch (...)
    {
        cli::printError("failed to add \"" + vendor.name() + "\" to cache");
    }

    MTX_UNLOCK_WR();
}



//======================================================================================================================
// platform

#if OMW_PLAT_WIN

static fs::path getEnvVarPath(const std::string& name)
{
    fs::path path;

    try
    {
        path = omw::windows::getEnvironmentVariable(name);
    }
    catch (const std::exception& ex)
    {
        cli::printError("failed to get %" + name + "%", ex.what());
    }
    catch (...)
    {
        cli::printError("failed to get %" + name + "%");
    }

    return path;
}

#else  // OMW_PLAT_WIN
#endif // OMW_PLAT_WIN

// platform
//======================================================================================================================
// static

fs::path getFilePath()
{
    static fs::path path;

    const std::string filename = "vendors.json";
    const std::string dirname = prj::dirName;

    if (path.empty())
    {
#if PRJ_DEBUG && USE_DEBUG_PATH

#if OMW_PLAT_WIN
        const fs::path basePath_a = "Debug";
#else
        const fs::path basePath_a = ".";
#endif
        const fs::path basePath_b = basePath_a;
        const fs::path fallback = basePath_a / ("cache-dbg-" + dirname) / filename;
        const fs::path filePath_a = fallback;
        const fs::path filePath_b = fallback;

#else // PRJ_DEBUG

#if OMW_PLAT_WIN
        const fs::path fallback = fs::path("C:/") / dirname / filename;
        const fs::path basePath_a = getEnvVarPath("APPDATA");
        const fs::path basePath_b = getEnvVarPath("PROGRAMDATA");
        fs::path filePath_a, filePath_b;

        if (basePath_a.empty() && basePath_b.empty()) // failed to get env variables
        {
            filePath_a = fallback;
            filePath_b = fallback;
        }
        else if (basePath_a.empty())
        {
            filePath_a = basePath_b / dirname / filename;
            filePath_b = filePath_a;
        }
        else if (basePath_b.empty())
        {
            filePath_a = basePath_a / dirname / filename;
            filePath_b = filePath_a;
        }
        else
        {
            filePath_a = basePath_a / dirname / filename;
            filePath_b = basePath_b / dirname / filename;
        }
#else  // OMW_PLAT_WIN
        const fs::path fallback = fs::path("/var/tmp") / dirname / filename;
        const fs::path basePath_a = "~/.cache";
        const fs::path basePath_b = "~";
        const fs::path filePath_a = basePath_a / dirname / filename;
        const fs::path filePath_b = basePath_b / ('.' + dirname) / filename;
#endif // OMW_PLAT_WIN

#endif // PRJ_DEBUG

        if (fs::exists(filePath_a)) { path = filePath_a; }
        else if (fs::exists(filePath_b)) { path = filePath_b; }
        else
        {
            if (fs::exists(basePath_a)) { path = filePath_a; }
            else if (fs::exists(basePath_b)) { path = filePath_b; }
            else { path = fallback; }
        }
    }

    return path;
}



using json = nlohmann::json;

// JSON keys
namespace key {

static const char* const version = "Version";

namespace v1 {
    static const char* const ma_l = "MA-L";
    static const char* const ma_m = "MA-M";
    static const char* const ma_s = "MA-S";

    namespace record {
        static const char* const oui = "OUI";
        static const char* const name = "Name";
        static const char* const colour = "Colour";
    }
} // namespace v1

} // namespace key

static Record parseRecord_v1_0(const json& j)
{
    if (json::value_t::object != j.type()) { throw -(__LINE__); }

    Record r;

    try
    {
        std::string oui = j[key::v1::record::oui];
        while (oui.length() < (2 * mac::EUI48::octet_count)) { oui += '0'; }

        const std::string name = j[key::v1::record::name];
        const std::string colour = j[key::v1::record::colour];

        r = Record(name, omw::Color(colour), mac::EUI48(omw::hexstoui64(oui)));
    }
    catch (...)
    {
        // nop, ignoring invalid entries
    }

    return r;
}

static void parse_v1_0(const json& j)
{
    try
    {
        for (const auto& jRec : j.at(key::v1::ma_l))
        {
            const auto rec = parseRecord_v1_0(jRec);
            if (!rec.empty()) { ma_l.push_back(rec); }
        }
    }
    catch (...)
    {
        cli::printWarning("cache failed to parse MA-L");
    }

    try
    {
        for (const auto& jRec : j.at(key::v1::ma_m))
        {
            const auto rec = parseRecord_v1_0(jRec);
            if (!rec.empty()) { ma_m.push_back(rec); }
        }
    }
    catch (...)
    {
        cli::printWarning("cache failed to parse MA-M");
    }

    try
    {
        for (const auto& jRec : j.at(key::v1::ma_s))
        {
            const auto rec = parseRecord_v1_0(jRec);
            if (!rec.empty()) { ma_s.push_back(rec); }
        }
    }
    catch (...)
    {
        cli::printWarning("cache failed to parse MA-S");
    }
}

static json serialiseRecord_v1_0(const Record& record)
{
    json j = json(json::value_t::object);

    j[key::v1::record::oui] = record.oui().toString('\0');
    j[key::v1::record::name] = record.name();
    j[key::v1::record::colour] = record.colour().toCssStr();

    return j;
}

static json serialise_v1_0()
{
    json j = json(json::value_t::object);

    j[key::version] = "1.0.0";

    j[key::v1::ma_l] = json(json::value_t::array);
    for (size_t i = 0; i < ma_l.size(); ++i) { j[key::v1::ma_l].push_back(serialiseRecord_v1_0(ma_l[i])); }

    j[key::v1::ma_m] = json(json::value_t::array);
    for (size_t i = 0; i < ma_m.size(); ++i) { j[key::v1::ma_m].push_back(serialiseRecord_v1_0(ma_m[i])); }

    j[key::v1::ma_s] = json(json::value_t::array);
    for (size_t i = 0; i < ma_s.size(); ++i) { j[key::v1::ma_s].push_back(serialiseRecord_v1_0(ma_s[i])); }

    return j;
}



void readCacheFile(const fs::path& filepath)
{
    try
    {
        std::ifstream ifs;
        ifs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ifs.open(filepath, std::ios::in | std::ios::binary);

        const json j = json::parse(ifs);
        const omw::Version v = j.at(key::version);

        if (v.major() == 1) { parse_v1_0(j); }
        else { cli::printError("can't parse cache file v" + v.toString()); }
    }
    catch (const std::exception& ex)
    {
        cli::printError("failed to read cache file \"" + filepath.u8string() + "\"", ex.what());
    }
    catch (...)
    {
        cli::printError("failed to read cache file \"" + filepath.u8string() + "\"");
    }
}

void writeCacheFile(const fs::path& filepath)
{
    try
    {
        const json j = serialise_v1_0();

        std::ofstream ofs;
        ofs.exceptions(std::ifstream::badbit | std::ifstream::failbit);
        ofs.open(filepath, std::ios::out | std::ios::binary);

#if PRJ_DEBUG && 1
        ofs << std::setw(4);
#endif
        ofs << j << std::endl;
    }
    catch (const std::exception& ex)
    {
        cli::printError("failed to write cache file \"" + filepath.u8string() + "\"", ex.what());
    }
    catch (...)
    {
        cli::printError("failed to write cache file \"" + filepath.u8string() + "\"");
    }
}
