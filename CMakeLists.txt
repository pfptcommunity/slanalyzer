cmake_minimum_required(VERSION 3.16.3)
project(slanalyzer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

link_libraries(libre2.a)

add_executable(slanalyzer slanalyzer.cpp src/Subnet.cpp src/GlobalList.cpp src/UserList.cpp src/GlobalStringMatcher.cpp src/GlobalAddressMatcher.cpp src/GlobalAnalyzer.cpp src/UserAnalyzer.cpp src/Utils.cpp)