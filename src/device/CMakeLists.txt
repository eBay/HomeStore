cmake_minimum_required(VERSION 3.7)
project(blkdev)

set(CMAKE_CXX_STANDARD 14)

include_directories(blkdev)
include_directories(..)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../cmake-build-debug/target)

set(TEST_BLKDEV_SOURCE_FILES
        blkdev.h
        blkdev_manager.cpp
        physical_dev.cpp
        test_blkdev.cpp
        chunk_selector.hpp
        virtual_dev.hpp)

add_executable(test_blkdev ${TEST_BLKDEV_SOURCE_FILES})

set(TEST_PHYSDEV_SOURCE_FILES
        physical_dev.cpp
        test_physdev.cpp)

add_executable(test_physdev ${TEST_PHYSDEV_SOURCE_FILES})
target_link_libraries(test_physdev folly glog tcmalloc)