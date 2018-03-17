cmake_minimum_required(VERSION 3.7)
project(volume)

set(CMAKE_CXX_STANDARD 14)

include_directories(..)
include_directories(../device)
include_directories(../cache)
include_directories(../../deps_prefix/${OS_TYPE}/include)
include_directories(/usr/local/include/)
include_directories(../blkstore)
link_directories(../../deps_prefix/${OS_TYPE}/lib)

set(TEST_VOLUME_SOURCE_FILES
          volume.cpp
	  vol_test.cpp
        ../device/virtual_dev.hpp
        ../device/device_manager.cpp
        ../device/physical_dev.cpp
        ../blkalloc/fixed_blk_allocator.cpp
#        ../blkalloc/varsize_blk_allocator.cpp
        ../cache/eviction.cpp
        ../cache/cache.cpp)

add_executable(test_volume ${TEST_VOLUME_SOURCE_FILES})
target_link_libraries(test_volume folly glog farmhash tcmalloc benchmark pthread)
