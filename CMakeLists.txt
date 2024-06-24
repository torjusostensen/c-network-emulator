cmake_minimum_required(VERSION 3.28)
project(libnet_test C)

set(CMAKE_C_STANDARD 11)

link_directories(
    /usr/lib/x86_64-linux-gnu/libmnl.so
    /usr/lib/x86_64-linux-gnu/libnetfilter_queue.so
)

add_executable(libnet_test nf-queue.c)