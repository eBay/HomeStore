cmake_minimum_required(VERSION 3.7)
project(cache)

set(CMAKE_CXX_STANDARD 14)

#if (CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-DNDEBUG=1)
    add_definitions(-O2)
#endif()

include_directories(blkdev)
include_directories(..)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../cmake-build-debug/target)

set(TEST_CACHE_SOURCE_FILES
        eviction.hpp
        eviction.cpp
        lru_eviction.hpp
        cache.cpp
        cache.h
        test_cache.cpp
        ../omds/memory/mempiece.hpp)

add_executable(test_cache ${TEST_CACHE_SOURCE_FILES})
target_link_libraries(test_cache folly glog farmhash tcmalloc benchmark)
