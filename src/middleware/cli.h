/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_CLI_H
#define IG_MIDDLEWARE_CLI_H

#include <string>


namespace cli {

void printError(const std::string& str, const char* const exWhat = nullptr);
void printWarning(const std::string& str);

}


#endif // IG_MIDDLEWARE_CLI_H
