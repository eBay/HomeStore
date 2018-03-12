cmake_minimum_required(VERSION 3.7)
project(OmStore)

set(CMAKE_CXX_STANDARD 14)

if (CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-DNDEBUG=1)
    add_definitions(-O2)
endif()

set(OS_TYPE unknown)
if(APPLE)
    set(OS_TYPE mac)
elseif(CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(OS_TYPE linux)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/target/${CMAKE_BUILD_TYPE}/${OS_TYPE})
set(LIB_ROOT_DIR ${CMAKE_SOURCE_DIR}/deps_prefix/${OS_TYPE}/lib)
set(INCLUDE_ROOT_DIR ${CMAKE_SOURCE_DIR}/deps_prefix/${OS_TYPE}/include)

#set(CMAKE_VERBOSE_MAKEFILE ON)

include_directories(${INCLUDE_ROOT_DIR})
#link_directories(${LIB_ROOT_DIR})

add_subdirectory(src/omds)
add_subdirectory(src/device)
add_subdirectory(src/blkalloc)
add_subdirectory(src/cache)
add_subdirectory(src/blkstore)
add_subdirectory(src/kvstore)