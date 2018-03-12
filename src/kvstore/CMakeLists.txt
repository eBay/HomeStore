cmake_minimum_required(VERSION 3.7)
project(kvstore)

set(CMAKE_CXX_STANDARD 14)

include_directories(..)
include_directories(../device)
include_directories(../blkstore)
include_directories(../cache)
include_directories(../../deps_prefix/${OS_TYPE}/include)
include_directories(/usr/local/include/)
#link_directories(../../deps_prefix/${OS_TYPE}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/)
set(TEST_KVSTORE_SOURCE_FILES
        ssd_btree.hpp
        test_btree_kvstore.cpp
        ../device/virtual_dev.hpp
        ../device/device_manager.cpp
        ../device/physical_dev.cpp
        ../blkalloc/fixed_blk_allocator.cpp
        ../blkalloc/varsize_blk_allocator.cpp
        ../cache/eviction.cpp
        ../cache/cache.cpp)

add_executable(test_kvstore ${TEST_KVSTORE_SOURCE_FILES})
target_link_libraries(test_kvstore folly glog farmhash tcmalloc gtest pthread)
