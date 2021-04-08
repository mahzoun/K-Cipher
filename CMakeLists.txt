cmake_minimum_required(VERSION 3.15)
project(K_Cipher)


set(CMAKE_CXX_STANDARD 14)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")






add_executable(K_Cipher main.cpp KCipher.cpp KCipher.h)
add_library(libgivaro SHARED IMPORTED)
set_target_properties(libgivaro PROPERTIES IMPORTED_LOCATION "/usr/lib/x86_64-linux-gnu/libgivaro.so")
include_directories("/usr/include/givaro")
target_link_libraries(K_Cipher "/usr/lib/x86_64-linux-gnu/libgivaro.so")
target_link_libraries(K_Cipher gmp)