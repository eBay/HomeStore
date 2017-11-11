cmake_minimum_required(VERSION 3.7)
project(blkalloc)

set(CMAKE_CXX_STANDARD 14)

include_directories(../blkalloc)
include_directories(..)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../cmake-build-debug/target)

set(TEST_BLKALLOC_SOURCE_FILES
        blk.h
        blk_allocator.h
        fixed_blk_allocator.cpp
        varsize_blk_allocator.h
        varsize_blk_allocator.cpp
        test_blkalloc.cpp)

add_executable(test_blkalloc ${TEST_BLKALLOC_SOURCE_FILES})
target_link_libraries(test_blkalloc glog)

