cmake_minimum_required(VERSION 3.15)
project(K_Cipher)

set(CMAKE_CXX_STANDARD 14)

add_executable(K_Cipher main.cpp KCipher.cpp KCipher.h)
#target_link_libraries(Chat /usr/lib/libcrypto++.a)