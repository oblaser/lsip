/*
author          Oliver Blaser
date            24.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#include <cstddef>
#include <cstdint>
#include <string>

#include "mac-addr.h"

#include <omw/string.h>



std::string mac::Address::toString() const { return omw::toHexStr(this->data(), this->size(), '-').toLower_ascii(); }
