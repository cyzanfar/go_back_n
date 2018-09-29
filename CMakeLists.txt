cmake_minimum_required(VERSION 3.12)
project(go_back_n C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(go_back_n
        gbn.c
        gbn.h
        receiver.c
        sender.c)
