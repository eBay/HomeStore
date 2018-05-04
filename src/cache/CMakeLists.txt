cmake_minimum_required(VERSION 3.7)
project(cache)

set(CMAKE_CXX_STANDARD 14)
include_directories(device)
include_directories(..)
include_directories(../../deps_prefix/${OS_TYPE}/include)
link_directories(../../deps_prefix/${OS_TYPE}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/)

set(PERF_CACHE_SOURCE_FILES
        eviction.hpp
        lru_eviction.hpp
        cache.cpp
        cache.h
        cache_common.hpp
        perf_cache.cpp
        ../homeds/memory/mempiece.hpp)

add_executable(perf_cache ${PERF_CACHE_SOURCE_FILES})
target_link_libraries(perf_cache folly glog farmhash tcmalloc benchmark pthread)

set(TEST_CACHE_SOURCE_FILES
        eviction.hpp
        lru_eviction.hpp
        cache.cpp
        cache.h
        cache_common.hpp
        test_cache.cpp
        ../homeds/memory/mempiece.hpp)

add_executable(test_cache ${TEST_CACHE_SOURCE_FILES})
target_link_libraries(test_cache folly glog farmhash tcmalloc gtest pthread)