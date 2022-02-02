cmake_minimum_required(VERSION 3.20)
project(vpnclient C)

set(CMAKE_C_STANDARD 99)
link_libraries(ws2_32)

add_executable(vpnclient main.c)
