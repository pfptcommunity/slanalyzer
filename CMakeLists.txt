cmake_minimum_required(VERSION 3.16.3)

project(slanalyzer LANGUAGES CXX)

# =========================================================
# General compiler configuration
# =========================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Verbose makefile output
set(CMAKE_VERBOSE_MAKEFILE OFF)

# =========================================================
# Dependencies
# =========================================================

find_package(PkgConfig REQUIRED)
pkg_check_modules(RE2 REQUIRED re2)

# =========================================================
# Executable
# =========================================================

add_executable(slanalyzer
        slanalyzer.cpp
        src/Subnet.cpp
        src/SubnetSet.cpp
        src/GlobalList.cpp
        src/UserList.cpp
        src/GlobalStringMatcher.cpp
        src/GlobalAddressMatcher.cpp
        src/GlobalAnalyzer.cpp
        src/UserAnalyzer.cpp
        src/Utils.cpp
)

# =========================================================
# Include / Link configuration
# =========================================================

target_include_directories(slanalyzer PRIVATE
        ${RE2_INCLUDE_DIRS}
)

target_link_directories(slanalyzer PRIVATE
        ${RE2_LIBRARY_DIRS}
)

target_compile_options(slanalyzer PRIVATE
        ${RE2_CFLAGS_OTHER}

        # Common warnings
        -Wall
        -Wextra
        -Wpedantic

        # Debug build
        $<$<CONFIG:Debug>:
        -O0
        -g3
        -fno-omit-frame-pointer
        >

        # RelWithDebInfo build
        $<$<CONFIG:RelWithDebInfo>:
        -O2
        -g
        -fno-omit-frame-pointer
        >

        # Release build
        $<$<CONFIG:Release>:
        -O3
        -DNDEBUG
        -march=native
        -mtune=native
        >
)

target_link_libraries(slanalyzer PRIVATE
        ${RE2_LIBRARIES}
        pthread
)

# =========================================================
# IPO / LTO
# =========================================================

include(CheckIPOSupported)

check_ipo_supported(
        RESULT ipo_supported
        OUTPUT ipo_error
)

if(ipo_supported)
    set_property(
            TARGET slanalyzer
            PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
    )

    message(STATUS "IPO/LTO enabled for Release builds")
else()
    message(WARNING "IPO/LTO not supported: ${ipo_error}")
endif()

# =========================================================
# Debug output
# =========================================================

message(STATUS "")
message(STATUS "========== BUILD CONFIGURATION ==========")
message(STATUS "CMAKE_BUILD_TYPE           = ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_CXX_COMPILER         = ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER_ID      = ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_CXX_COMPILER_VERSION = ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "CMAKE_CXX_STANDARD         = ${CMAKE_CXX_STANDARD}")

get_target_property(SLANALYZER_COMPILE_OPTIONS slanalyzer COMPILE_OPTIONS)
message(STATUS "slanalyzer COMPILE_OPTIONS = ${SLANALYZER_COMPILE_OPTIONS}")

get_target_property(SLANALYZER_INCLUDE_DIRS slanalyzer INCLUDE_DIRECTORIES)
message(STATUS "slanalyzer INCLUDE_DIRS    = ${SLANALYZER_INCLUDE_DIRS}")

get_target_property(SLANALYZER_LINK_DIRS slanalyzer LINK_DIRECTORIES)
message(STATUS "slanalyzer LINK_DIRS       = ${SLANALYZER_LINK_DIRS}")

get_target_property(SLANALYZER_LINK_LIBS slanalyzer LINK_LIBRARIES)
message(STATUS "slanalyzer LINK_LIBRARIES  = ${SLANALYZER_LINK_LIBS}")

message(STATUS "RE2_INCLUDE_DIRS           = ${RE2_INCLUDE_DIRS}")
message(STATUS "RE2_LIBRARY_DIRS           = ${RE2_LIBRARY_DIRS}")
message(STATUS "RE2_LIBRARIES              = ${RE2_LIBRARIES}")
message(STATUS "RE2_CFLAGS_OTHER           = ${RE2_CFLAGS_OTHER}")

message(STATUS "=========================================")
message(STATUS "")