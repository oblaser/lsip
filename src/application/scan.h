/*
author          Oliver Blaser
date            25.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_APPLICATION_SCAN_H
#define IG_APPLICATION_SCAN_H

#include <cstddef>
#include <cstdint>

#include "application/result.h"
#include "middleware/ip-addr.h"


namespace app {

app::ScanResult scan(const ip::Addr4& addr);

}


#endif // IG_APPLICATION_SCAN_H
