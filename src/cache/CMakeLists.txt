cmake_minimum_required(VERSION 3.7)
project(cache)

set(CMAKE_CXX_STANDARD 14)

include_directories(cache)
include_directories(..)

set(TEST_CACHE_SOURCE_FILES
        eviction.hpp
        eviction.cpp
        lru_eviction.hpp
        cache.cpp
        cache.h)

add_executable(test_cache ${TEST_CACHE_SOURCE_FILES})
