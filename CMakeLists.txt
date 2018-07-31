cmake_minimum_required(VERSION 2.8)
project(dhcpclient)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g")

include_directories("include/")
add_subdirectory("dhcpfunc/")
set(SOURCE_EXE main.cpp)

add_executable(dhcpclient ${SOURCE_EXE})
link_directories(${main_BINARY_DIR})

target_link_libraries(dhcpclient pthread dhcp_func)
