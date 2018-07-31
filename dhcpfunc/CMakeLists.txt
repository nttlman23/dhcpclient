cmake_minimum_required(VERSION 2.8)
project(dhcp_func)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories("../include")

set(SOURCE_LIB dhcp_func.cpp)

add_library(dhcp_func SHARED ${SOURCE_LIB})

#target_link_libraries(clientmap)

