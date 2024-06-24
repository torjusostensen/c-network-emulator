cmake_minimum_required(VERSION 3.28)
project(libnet_test C)

set(CMAKE_C_STANDARD 11)

link_directories(
    /usr/lib/x86_64-linux-gnu/libmnl.so
    /usr/lib/x86_64-linux-gnu/libnetfilter_queue.so
)

add_executable(libnet_test nf-queue.c)

# Specify the required libraries
find_library(NETFILTER_QUEUE_LIB netfilter_queue)
if(NETFILTER_QUEUE_LIB)
# Link the target "libnet_test" with the libnetfilter_queue library found
target_link_libraries(libnet_test ${NETFILTER_QUEUE_LIB})
else()
message(FATAL_ERROR "libnetfilter_queue not found")
endif()