cmake_minimum_required(VERSION 3.12)
project(hw1_skeleton C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(hw1_skeleton
        gbn.c
        gbn.h
        receiver.c
        sender.c)
