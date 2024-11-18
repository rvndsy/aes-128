project(aes)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(aes SHARED
    aes.c
    utils.c
)

project(filecrypto)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(filecrypto SHARED
    filecrypto.c
    aes.c
    utils.c
)
