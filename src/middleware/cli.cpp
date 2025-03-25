/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <iomanip>
#include <iostream>
#include <string>

#include "cli.h"

#include <omw/cli.h>



static constexpr int ewiWidth = 10;



void cli::printError(const std::string& str, const char* const exWhat)
{
    std::cout << omw::fgBrightRed << std::left << std::setw(ewiWidth) << "error:" << omw::fgDefault;

    if (exWhat) { std::cout << omw::fgBrightBlack << exWhat << omw::fgDefault << " "; }

    std::cout << str; // printFormattedText(str);
    std::cout << std::endl;
}

void cli::printWarning(const std::string& str)
{
    std::cout << omw::fgBrightYellow << std::left << std::setw(ewiWidth) << "warning:" << omw::fgDefault;
    std::cout << str; // printFormattedText(str);
    std::cout << std::endl;
}
