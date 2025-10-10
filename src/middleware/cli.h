/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_MIDDLEWARE_CLI_H
#define IG_MIDDLEWARE_CLI_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>


namespace cli {

void printError(const std::string& str, const char* const exWhat = nullptr);
void printErrno(const std::string& str, int eno);
void printWarning(const std::string& str);

void hexDump(const uint8_t* data, size_t count);
static inline void hexDump(const std::vector<uint8_t>& data) { hexDump(data.data(), data.size()); }
static inline void hexDump(const char* str) { hexDump((const uint8_t*)str, strlen(str)); }
static inline void hexDump(const std::string& str) { hexDump((const uint8_t*)str.data(), str.size()); }

} // namespace cli


#endif // IG_MIDDLEWARE_CLI_H
