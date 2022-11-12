cmake_minimum_required(VERSION 3.22)
project(slparser)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

link_libraries(libre2.a)

add_executable(slparser main.cpp)
