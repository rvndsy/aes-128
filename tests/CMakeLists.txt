file(COPY ${CMAKE_SOURCE_DIR}/tests/samples/ DESTINATION ${CMAKE_BINARY_DIR}/tests/samples)

##Debug flags for valgrind
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_C_FLAGS_DEBUG "-g")
#set(CMAKE_CXX_FLAGS_DEBUG "-g")

add_executable(aes-byte-test aes-byte-test.c)
target_link_libraries(aes-byte-test PRIVATE aes filecrypt utils)

add_executable(aes-file-test aes-file-test.c)
target_link_libraries(aes-file-test PRIVATE aes filecrypt)
