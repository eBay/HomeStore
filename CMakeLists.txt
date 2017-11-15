cmake_minimum_required(VERSION 3.7)
project(OmStore)

set(CMAKE_CXX_STANDARD 14)

if (CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-DNDEBUG=1)
endif()

add_subdirectory(src/omds)
add_subdirectory(src/device)
add_subdirectory(src/blkalloc)
add_subdirectory(src/cache)