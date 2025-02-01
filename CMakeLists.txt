cmake_minimum_required(VERSION 3.10)
project(AES)

set(CMAKE_CXX_FLAGS "-Wall -Wpedantic -g")
set(CMAKE_C_FLAGS "-Wall -Wpedantic -g")

add_subdirectory(src)
add_subdirectory(gui)
add_subdirectory(tests)
