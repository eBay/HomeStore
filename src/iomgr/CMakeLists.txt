cmake_minimum_required(VERSION 3.7)
project(iomgr)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/)

set(TEST_IOMGR_SOURCE_FILES
        endpoint.hpp
        drive_endpoint.cpp
        net_endpoint.cpp
        test_iomgr.cpp)

add_executable(test_iomgr ${TEST_IOMGR_SOURCE_FILES})
target_link_libraries(test_iomgr pthread folly glog tcmalloc pthread)
