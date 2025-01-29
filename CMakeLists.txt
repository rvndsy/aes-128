cmake_minimum_required(VERSION 3.10)
project(AES)

set(CMAKE_CXX_FLAGS "-Wall -Wpedantic")

add_subdirectory(src)
add_subdirectory(gui)
add_subdirectory(tests)
