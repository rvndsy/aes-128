add_library(aes STATIC aes.c)
target_include_directories(aes PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_library(utils STATIC utils.c)
target_include_directories(utils PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_library(filecrypt STATIC filecrypt.c)
target_include_directories(filecrypt PUBLIC ${CMAKE_SOURCE_DIR}/include)
