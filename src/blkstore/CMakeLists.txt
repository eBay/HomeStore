cmake_minimum_required(VERSION 3.7)
project(blkstore)

set(CMAKE_CXX_STANDARD 14)

if (CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-DNDEBUG=1)
    add_definitions(-O2)
endif()

include_directories(..)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../cmake-build-debug/target)

set(TEST_BLKSTORE_SOURCE_FILES
        blkstore.hpp)

add_executable(test_blkstore ${TEST_BLKSTORE_SOURCE_FILES})
target_link_libraries(test_blkstore folly glog farmhash tcmalloc benchmark)
