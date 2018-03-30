cmake_minimum_required(VERSION 3.7)
project(blkdev)

set(CMAKE_CXX_STANDARD 14)

include_directories(device)
include_directories(..)
include_directories(../../deps_prefix/${OS_TYPE}/include)
link_directories(../../deps_prefix/${OS_TYPE}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/)

set(TEST_DEVICEMGR_SOURCE_FILES
        device.h
        device_manager.cpp
        physical_dev.cpp
        ../main/homestore.hpp
        test_blkdev.cpp
        device_selector.hpp
        virtual_dev.hpp)

add_executable(test_devmgr ${TEST_DEVICEMGR_SOURCE_FILES})

set(TEST_PHYSDEV_SOURCE_FILES
        physical_dev.cpp
        device_manager.cpp
        device.h
        test_physdev.cpp)

add_executable(test_physdev ${TEST_PHYSDEV_SOURCE_FILES})
target_link_libraries(test_physdev pthread folly glog tcmalloc pthread)

set(TEST_VIRTUALDEV_SOURCE_FILES
        physical_dev.cpp
        virtual_dev.hpp
        device_manager.cpp
        device.h
        ../blkalloc/fixed_blk_allocator.cpp
        ../blkalloc/varsize_blk_allocator.cpp
        test_virtualdev.cpp)

add_executable(test_virtualdev ${TEST_VIRTUALDEV_SOURCE_FILES})
target_link_libraries(test_virtualdev pthread folly glog tcmalloc pthread)