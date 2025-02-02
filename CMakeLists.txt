cmake_minimum_required(VERSION 3.10)
project(AES)

set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall -Wpedantic -O3")
set(CMAKE_C_FLAGS_RELEASE_INIT "-Wall -Wpedantic -O3")

# Flags for GDB
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall -Wpedantic -O3 -g")
set(CMAKE_C_FLAGS_DEBUG_INIT "-Wall -Wpedantic -O3 -g")

add_subdirectory(src)
add_subdirectory(gui)
add_subdirectory(tests)
