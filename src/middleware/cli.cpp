/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cctype>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "cli.h"

#include <omw/cli.h>


using std::isprint;
using std::printf;
using std::strerror;



static constexpr int ewiWidth = 10;



static void hdDataToString(char* buffer, const uint8_t* p, const uint8_t* end);



void cli::printError(const std::string& str, const char* const exWhat)
{
    std::cout << omw::fgBrightRed << std::left << std::setw(ewiWidth) << "error:" << omw::fgDefault;

    if (exWhat) { std::cout << omw::fgBrightBlack << exWhat << omw::fgDefault << " "; }

    std::cout << str; // printFormattedText(str);
    std::cout << std::endl;
}

void cli::printErrno(const std::string& str, int eno)
{
    std::cout << omw::fgBrightRed << std::left << std::setw(ewiWidth) << "error:" << omw::fgDefault;
    std::cout << str; // printFormattedText(str);
    std::cout << ", " << eno << ' ' << strerror(eno);
    std::cout << std::endl;
}

void cli::printWarning(const std::string& str)
{
    std::cout << omw::fgBrightYellow << std::left << std::setw(ewiWidth) << "warning:" << omw::fgDefault;
    std::cout << str; // printFormattedText(str);
    std::cout << std::endl;
}

void cli::hexDump(const uint8_t* data, size_t count)
{
    const uint8_t* const end = (data + count);

    for (size_t i = 0; i < count; ++i)
    {
        const int byte = *(data + i);
        const size_t row = (i / 16);
        const size_t col = (i % 16);

        if (col == 0)
        {
            if (i == 0) { printf("%05zx ", i); }
            else
            {
                char str[17];
                hdDataToString(str, data + 16 * (row - 1), end);
                printf("  | %s\n%05zx ", str, i);
            }
        }
        else if (col == 8) { printf(" "); }

        printf(" %02x", byte);
    }

    if (count == 0) { printf("%05x ", 0); }



    size_t lastRowSize = (count % 16);
    if ((lastRowSize == 0) && (count != 0)) { lastRowSize = 16; }
    const size_t remaining = (16 - lastRowSize);

    if (remaining >= 8) { printf(" "); }
    for (size_t i = 0; i < remaining; ++i) { printf("   "); }

    char str[17];
    hdDataToString(str, end - lastRowSize, end);
    printf("  | %s", str);

    printf("\n");
}



/**
 * @brief Converts the data buffer bytes to printable characters.
 *
 * Writes 16 characters and a terminating null to `buffer`.
 *
 * @param buffer Destination string buffer
 * @param p First element to parse, points into the source data buffer
 * @param end First element after the source data buffer
 */
void hdDataToString(char* buffer, const uint8_t* p, const uint8_t* end)
{
    size_t i = 0;

    while ((i < 16) && (p < end))
    {
        const char c = (char)(*p);

        if (isprint(c)) { buffer[i] = c; }
        else { buffer[i] = '.'; }

        ++p;
        ++i;
    }

    while (i < 16)
    {
        buffer[i] = ' ';
        ++i;
    }

    buffer[i] = 0;
}
