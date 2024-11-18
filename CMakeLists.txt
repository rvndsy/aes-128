cmake_minimum_required(VERSION 3.10)
project(AES)
#add_compile_definitions(AES_128)
add_subdirectory(include)
#add_subdirectory(src)

enable_testing()
add_subdirectory(tests)
