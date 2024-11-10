cmake_minimum_required(VERSION 3.10)
project(aes)
add_library(utils
    src/utils.c)
add_executable(aes
    src/aes.c)
target_link_libraries(aes utils)
