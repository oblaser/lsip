/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_PROJECT_H
#define IG_PROJECT_H

// #include <omw/defs.h>
// #include <omw/version.h>


namespace prj {

const char* const appName = "lsip";
const char* const exeName = "lsip"; // eq to the linker setting

const char* const website = "https://github.com/oblaser/lsip";

// const omw::Version version(0, 1, 0, "alpha");
constexpr int copyrightYear = 2025;

} // namespace prj


#ifdef _DEBUG
#define PRJ_DEBUG (1)
#else
#undef PRJ_DEBUG
#endif


#endif // IG_PROJECT_H
