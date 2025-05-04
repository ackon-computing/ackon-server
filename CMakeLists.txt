cmake_minimum_required(VERSION 3.0.2)
project(ackon-server)

#include_directories(vendor/cargs/include)
#add_subdirectory(vendor/cargs)

set (CMAKE_CXX_FLAGS "-std=c++17 -g -O2")

include_directories(/usr/include/postgresql/)

add_executable(ackon-server main.cpp webserver.cpp sign.cpp)

target_link_libraries(ackon-server stdc++fs)
#target_link_libraries(webmake cargs)
target_link_libraries(ackon-server event)
target_link_libraries(ackon-server crypto)
target_link_libraries(ackon-server ssl)


target_link_libraries(ackon-server pq)
