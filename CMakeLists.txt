cmake_minimum_required(VERSION 3.16.3)
project(slanalyzer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

target_include_directories(slanalyzer PRIVATE ${RE2_INCLUDE_DIRS})
target_link_libraries(slanalyzer PRIVATE ${RE2_LIBRARIES} pthread)
target_link_directories(slanalyzer PRIVATE ${RE2_LIBRARY_DIRS})
target_compile_options(slanalyzer PRIVATE ${RE2_CFLAGS_OTHER})