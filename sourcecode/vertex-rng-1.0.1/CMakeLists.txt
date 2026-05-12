cmake_minimum_required(VERSION 3.10)
project(vertexrng)

set(CMAKE_CXX_STANDARD 14)

add_executable(vertexrng cJSON.c CivetServer.cpp civetweb.c main.cpp)

target_link_libraries (vertexrng pthread dl)
