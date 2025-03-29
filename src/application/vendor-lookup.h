/*
author          Oliver Blaser
date            29.03.2025
copyright       GPL-3.0 - Copyright (c) 2025 Oliver Blaser
*/

#ifndef IG_APPLICATION_VENDORLOOKUP_H
#define IG_APPLICATION_VENDORLOOKUP_H

#include <cstddef>
#include <cstdint>

#include "application/result.h"
#include "middleware/mac-addr.h"


namespace app {

app::Vendor lookupVendor(const mac::Addr& mac);

}


#endif // IG_APPLICATION_VENDORLOOKUP_H
