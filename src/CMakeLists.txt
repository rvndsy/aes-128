include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(aes SHARED
    aes.c
    utils.c
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(filecrypt SHARED
    filecrypt.c
    aes.c
    utils.c
)

add_executable(main main.c)
target_link_libraries(main filecrypt aes)
