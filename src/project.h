/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_PROJECT_H
#define IG_PROJECT_H

#include <omw/defs.h>
#include <omw/version.h>


namespace prj {

const char* const appName = "lsip";
const char* const exeName = "lsip"; // eq to the linker setting
const char* const dirName = "lsip";

const char* const website = "https://github.com/oblaser/lsip";

const omw::Version version(0, 1, 0, "alpha.1");
constexpr int copyrightYear = 2025;

} // namespace prj


#ifdef _DEBUG
#define PRJ_DEBUG (1)
#else
#undef PRJ_DEBUG
#endif

#define PRJ_THREAD_DEBUG (0)


#if PRJ_THREAD_DEBUG && PRJ_DEBUG
#include <iostream>
#include <omw/clock.h>
#include <omw/string.h>
#include <thread>
#define THREAD_PRINT(_str)                                                                                                   \
    std::cout << ("\033[90m" + omw::toHexStr(std::hash<std::thread::id>{}(std::this_thread::get_id())).lower_ascii() + " " + \
                  /*std::to_string(omw::clock::now()) + "us " +*/ std::string(_str) + "\033[39m")                            \
              << std::endl
#else
#define THREAD_PRINT(_str) (void)(_str)
#endif


#endif // IG_PROJECT_H
