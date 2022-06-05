cmake_minimum_required(VERSION 3.20)
project(vpnclient C)

set(CMAKE_C_STANDARD 99)
link_libraries(ws2_32)
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(vpnclient client.c)
add_executable(start start.c)
target_link_libraries(vpnclient OpenSSL::Crypto)
