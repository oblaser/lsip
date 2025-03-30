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

#include "middleware/cli.h"
#include "middleware/mac-addr.h"
#include "project.h"
#include "vendor-cache.h"

#include <json/json.hpp>
#include <omw/string.h>
#include <omw/version.h>
#include <omw/windows/windows.h>


#define USE_DEBUG_PATH (1)


namespace fs = std::filesystem;



class Record : public app::cache::Vendor
{
public:
    Record()
        : Vendor(), m_oui(mac::EUI48::null)
    {}

    Record(const std::string& name, const omw::Color colour, const mac::EUI48& oui)
        : Vendor(), m_oui(oui)
    {
        this->setName(name);
        this->setColour(colour);
    }

    virtual ~Record() {}

    const mac::EUI48& oui() const { return m_oui; }

    bool empty() const { return this->name().empty(); }

private:
    mac::EUI48 m_oui;
};



static std::mutex ___cache_mtx;
using lock_guard = std::lock_guard<std::mutex>;
#define MTX_LG()     lock_guard ___lg_cache_mtx(___cache_mtx)
#define MTX_LOCK()   ___cache_mtx.lock()
#define MTX_UNLOCK() ___cache_mtx.unlock()

static std::vector<Record> ma_l, ma_m, ma_s;
static bool changed = false;



static fs::path getFilePath();
static void readCacheFile(const fs::path& filepath);
static void writeCacheFile(const fs::path& filepath);



void app::cache::load()
{
    MTX_LG();

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
}

void app::cache::save()
{
    MTX_LG();

    if (changed) { writeCacheFile(getFilePath()); }
}

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

void app::cache::add(const mac::EUI48& mac, const app::cache::Vendor& vendor)
{
    MTX_LG();

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
#if OMW_PLAT_WIN

#if PRJ_DEBUG && USE_DEBUG_PATH
        const fs::path basePath_a = "Debug";
        const fs::path basePath_b = basePath_a;
        const fs::path fallback = basePath_a / dirname / filename;
        const fs::path filePath_a = fallback;
        const fs::path filePath_b = fallback;
#else  // PRJ_DEBUG
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
#endif // PRJ_DEBUG

#else // OMW_PLAT_WIN

#if PRJ_DEBUG && USE_DEBUG_PATH
        const fs::path basePath_a = ".";
        const fs::path basePath_b = basePath_a;
        const fs::path fallback = basePath_a / ("cache-dbg-" + dirname) / filename;
        const fs::path filePath_a = fallback;
        const fs::path filePath_b = fallback;
#else  // PRJ_DEBUG
        const fs::path fallback = fs::path("/var/tmp") / dirname / filename;
        const fs::path basePath_a = "~/.cache";
        const fs::path basePath_b = "~";
        const fs::path filePath_a = basePath_a / dirname / filename;
        const fs::path filePath_b = basePath_b / ('.' + dirname) / filename;
#endif // PRJ_DEBUG

#endif // OMW_PLAT_WIN

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
