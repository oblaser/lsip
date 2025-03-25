
# author        Oliver Blaser
# date          24.03.2025
# copyright     GPL-3.0 - Copyright (c) 2025 Oliver Blaser

cmake_minimum_required(VERSION 3.13)

project(lsip)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)



#
# SDK
#

# omw
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../sdk/omw/build/cmake/libomw.a/ ${CMAKE_CURRENT_LIST_DIR}/../../sdk/omw/build/cmake/libomw.a/)
include_directories(../../sdk/omw/include)



#
# the application
#

set(BINNAME lsip)

if(_DEBUG)
    add_definitions(-D_DEBUG)
endif()

include_directories(../../src/)

set(SOURCES
    ../../src/application/process.cpp
    ../../src/application/result.cpp
    ../../src/application/scan.cpp
    ../../src/middleware/cli.cpp
    ../../src/middleware/ip-addr.cpp
    ../../src/middleware/mac-addr.cpp
    ../../src/main.cpp
)



add_executable(${BINNAME} ${SOURCES})
target_link_libraries(${BINNAME} omw)
target_compile_options(${BINNAME} PRIVATE -Werror=implicit
    -Wall
    -Werror=int-conversion
    -Werror=discarded-qualifiers
    -Werror=return-type
    -Werror=format
    -Wdouble-promotion
    -Werror=switch
    -Werror=reorder
)
