add_library(aes STATIC aes.c)
target_include_directories(aes PUBLIC ${CMAKE_SOURCE_DIR}/include)

# This speeds file encryption and decryption with AES by 10x... doing the same to filecrypt doesn't do anything
target_compile_options(aes PRIVATE -O3)

add_library(utils STATIC utils.c)
target_include_directories(utils PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_library(filecrypt STATIC filecrypt.c utils.c)
target_include_directories(filecrypt PUBLIC ${CMAKE_SOURCE_DIR}/include)
