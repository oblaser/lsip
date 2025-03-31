/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "application/process.h"
#include "application/vendor-cache.h"
#include "project.h"

#include <curl-thread/curl.h>
#include <omw/cli.h>
#include <omw/windows/windows.h>


using std::cout;
using std::endl;
using std::setw;


namespace argstr {

const char* const noColor = "--no-colour";
const char* const help = "--help";
const char* const version = "--version";

bool contains(const std::vector<std::string>& rawArgs, const char* arg)
{
    bool r = false;

    for (size_t i = 0; i < rawArgs.size(); ++i)
    {
        if (rawArgs[i] == arg)
        {
            r = true;
            break;
        }
    }

    return r;
}

bool isOption(const std::string& arg) { return (!arg.empty()) && (arg[0] == '-'); }

bool isKnownOption(const std::string& arg) { return ((arg == noColor) || (arg == help) || (arg == version)); }

bool check(const std::vector<std::string>& args);

} // namespace argstr



namespace {

enum EXITCODE // https://tldp.org/LDP/abs/html/exitcodes.html / on MSW are no preserved codes
{
    EC_OK = 0,
    EC_ERROR = 1,

    EC__begin_ = 79,

    // EC_asdf = EC__begin_,
    // EC_..,

    EC__end_,

    EC__max_ = 113
};
static_assert(EC__end_ <= EC__max_, "too many error codes defined");

const std::string usageString = std::string(prj::exeName) + " [options] ADDR [ADDR [ADDR [...]]]";

void printHelp()
{
    constexpr int lw = 20;

    cout << prj::appName << endl;
    cout << endl;
    cout << "Usage:" << endl;
    cout << "  " << usageString << endl;
    cout << endl;
    cout << "ADDR:" << endl;
    cout << "  IPv4 address range to scan, specified by subnet mask or range:" << endl;
    cout << "   - 192.168.1.0 = 192.168.1.0/24" << endl;
    cout << "   - 192.168.1.200-254/26 or 192.168.3.0-4.255 etc." << endl;
    cout << endl;
    cout << "Options:" << endl;
    cout << std::left << setw(lw) << std::string("  ") + argstr::noColor << "monochrome console output" << endl;
    cout << std::left << setw(lw) << std::string("  ") + argstr::help << "prints this help text" << endl;
    cout << std::left << setw(lw) << std::string("  ") + argstr::version << "prints version info" << endl;
    cout << endl;
    cout << "Website: <" << prj::website << ">" << endl;
}

void printUsageAndTryHelp()
{
    cout << "Usage: " << usageString << "\n\n";
    cout << "Try '" << prj::exeName << " --help' for more options." << endl;
}

void printVersion()
{
    const omw::Version& v = prj::version;

    cout << prj::appName << "   ";
    if (v.isPreRelease()) { cout << omw::fgBrightMagenta; }
    cout << v.toString();
    if (v.isPreRelease()) { cout << omw::defaultForeColor; }
#ifdef PRJ_DEBUG
    cout << "   " << omw::fgBrightRed << "DEBUG" << omw::defaultForeColor << "   " << __DATE__ << " " << __TIME__;
#endif
    cout << endl;

    cout << endl;
    cout << "project page: " << prj::website << endl;
    cout << endl;
    cout << "Copyright (c) " << prj::copyrightYear << " Oliver Blaser." << endl;
    cout << "License: GNU GPLv3 <http://gnu.org/licenses/>." << endl;
    cout << "This is free software. There is NO WARRANTY." << endl;
}

} // namespace



int main(int argc, char** argv)
{
    std::vector<std::string> rawArgs(argc);
    for (int i = 0; i < argc; ++i) { rawArgs[i] = argv[i]; }

#ifndef PRJ_DEBUG
    const
#endif // PRJ_DEBUG
        auto args = std::vector<std::string>(rawArgs.begin() + 1, rawArgs.end());

#if PRJ_DEBUG && 1
    if (args.empty())
    {
        // args.push_back("--no-color");
        // args.push_back("--help");
        // args.push_back("--version");

        // args.push_back("192.168.1.0"); // help example
        // args.push_back("192.168.1.0/24"); // help example
        // args.push_back("192.168.1.200-254/26"); // help example
        // args.push_back("192.168.3.0-4.255"); // help example

        // args.push_back("192.168.1.99");

        // args.push_back("192.168.1.0/24");
        // args.push_back("192.168.1.0/26");

        // args.push_back("192.168.1.120/24");

        args.push_back("192.168.1.120-140");
        // args.push_back("192.168.3.253-5.3");
        // args.push_back("10.55.3.253-5.3");
        // args.push_back("192.168.0.253-1.10/24");
        // args.push_back("192.168.10.0-11.255");
    }
#endif

    if (argstr::contains(args, argstr::noColor)) { omw::ansiesc::disable(); }
    else
    {
#ifdef OMW_PLAT_WIN
        omw::ansiesc::enable(omw::windows::consoleEnVirtualTermProc());
#else
        omw::ansiesc::enable(true);
#endif
    }

#ifdef OMW_PLAT_WIN
    const auto winOutCodePage = omw::windows::consoleGetOutCodePage();
    bool winOutCodePageRes = omw::windows::consoleSetOutCodePage(omw::windows::UTF8CP);
#endif

#if PRJ_DEBUG && 1
    cout << omw::foreColor(26) << "--======# args #======--\n";
    for (size_t i = 0; i < args.size(); ++i) { cout << " " << args[i] << endl; }
    cout << "--======# end args #======--" << endl << omw::defaultForeColor;
#endif



    int r = EC_ERROR;

    if (/*args.isValid()*/ argstr::check(args))
    {
        r = EC_OK;

        if (argstr::contains(args, argstr::help)) { printHelp(); }
        else if (argstr::contains(args, argstr::version)) { printVersion(); }
        else
        {
            THREAD_PRINT("parent");

            app::cache::load();
            std::thread thread_curl = std::thread(curl::thread);

            for (size_t i = 0; i < args.size(); ++i)
            {
                const auto& arg = args[i];

                if (!argstr::isOption(arg))
                {
                    const int err = app::process(arg);
                    if (err) { r = EC_ERROR; }
                }
            }

            curl::shutdown();
            thread_curl.join();

            app::cache::save();
        }
    }
    // else
    //{
    //     r = EC_ERROR;
    //
    //    if (args.count() == 0)
    //    {
    //        cout << "No arguments." << endl;
    //        printUsageAndTryHelp();
    //    }
    //    else if (!args.options().isValid())
    //    {
    //        cout << prj::exeName << ": unrecognized option: '" << args.options().unrecognized() << "'" << endl;
    //        printUsageAndTryHelp();
    //    }
    //    else
    //    {
    //        cout << "Error" << endl;
    //        printUsageAndTryHelp();
    //    }
    //}



#if PRJ_DEBUG && 1
    cout << omw::foreColor(26) << "===============\nreturn " << r << "\npress enter..." << omw::normal << endl;
#ifdef OMW_PLAT_WIN
    int dbg___getc_ = getc(stdin);
#endif
#endif

    cout << omw::normal << std::flush;

#ifdef OMW_PLAT_WIN
    winOutCodePageRes = omw::windows::consoleSetOutCodePage(winOutCodePage);
#endif

    return r;
}



bool argstr::check(const std::vector<std::string>& args)
{
    bool ok = false;

    if (!args.empty())
    {
        ok = true;

        for (size_t i = 0; ok && (i < args.size()); ++i)
        {
            const auto& arg = args[i];

            if (!argstr::isKnownOption(arg) && argstr::isOption(arg))
            {
                ok = false;

                cout << "unknown option: " << arg << endl;
            }
        }
    }

    if (!ok)
    {
        cout << endl;
        printUsageAndTryHelp();
    }

    return ok;
}
