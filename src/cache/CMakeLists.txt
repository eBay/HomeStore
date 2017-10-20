cmake_minimum_required(VERSION 3.7)
project(cache)

set(CMAKE_CXX_STANDARD 14)

include_directories(cache)
include_directories(..)

set(TEST_CACHE_SOURCE_FILES
        evictable_mem_alloc.cpp
        evictable_mem_alloc.h
        cache.cpp
        cache.h)

add_executable(test_cache ${TEST_CACHE_SOURCE_FILES})
