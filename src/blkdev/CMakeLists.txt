cmake_minimum_required(VERSION 3.7)
project(libutils)

set(CMAKE_CXX_STANDARD 14)

include_directories(blkdev)

set(TEST_BLKDEV_SOURCE_FILES
        blkdev.h
        blkdev_manager.cpp
        physical_dev.cpp
        test_blkdev.cpp
        virtual_dev.cpp)

add_executable(test_blkdev ${TEST_BLKDEV_SOURCE_FILES})

