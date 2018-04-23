cmake_minimum_required(VERSION 3.7)
project(blkstore)

set(CMAKE_CXX_STANDARD 14)

include_directories(..)
include_directories(../device)
include_directories(../cache)
include_directories(../../deps_prefix/${OS_TYPE}/include)
include_directories(/usr/local/include/)
#link_directories(../../deps_prefix/${OS_TYPE}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/)
set(TEST_BLKSTORE_SOURCE_FILES
        blkstore.hpp
        test_blkstore.cpp
        ../device/virtual_dev.hpp
        ../device/device_manager.cpp
        ../device/physical_dev.cpp
        ../blkalloc/fixed_blk_allocator.cpp
        ../blkalloc/varsize_blk_allocator.cpp
        ../cache/eviction.hpp
        ../cache/cache.cpp)

add_executable(test_blkstore ${TEST_BLKSTORE_SOURCE_FILES})
target_link_libraries(test_blkstore folly glog farmhash tcmalloc benchmark pthread)
