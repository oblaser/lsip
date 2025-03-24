/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <iomanip>
#include <iostream>

#include "project.h"


using std::cout;
using std::endl;
using std::setw;


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



int main(int argc, char** argv)
{
    int r = EC_ERROR;

    cout << "test" << endl;

    return r;
}
