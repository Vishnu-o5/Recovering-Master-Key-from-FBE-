cmake_minimum_required(VERSION 3.22.1)
project(fbeprobe)

add_library(fbeprobe SHARED
    fbe_probe.cpp)

find_library(log-lib log)

target_link_libraries(fbeprobe ${log-lib})
