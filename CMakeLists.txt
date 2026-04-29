cmake_minimum_required(VERSION 3.16.3)
project(slanalyzer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

# --- Find RE2 via pkg-config (pulls in Abseil correctly) ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(RE2 REQUIRED re2)

add_executable(slanalyzer
    slanalyzer.cpp
    src/Subnet.cpp
    src/GlobalList.cpp
    src/UserList.cpp
    src/GlobalStringMatcher.cpp
    src/GlobalAddressMatcher.cpp
    src/GlobalAnalyzer.cpp
    src/UserAnalyzer.cpp
    src/Utils.cpp
)

# RE2 include paths
target_include_directories(slanalyzer PRIVATE
    ${RE2_INCLUDE_DIRS}
)

# RE2 + Abseil link libraries
target_link_libraries(slanalyzer PRIVATE
    ${RE2_LIBRARIES}
)

