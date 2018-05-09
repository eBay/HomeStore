cmake_minimum_required(VERSION 3.9)
project(HomeStore)

set(CMAKE_CXX_STANDARD 14)

if (${CMAKE_BUILD_TYPE} STREQUAL Debug)
  if (NOT ${CONAN_SETTINGS_COMPILER} STREQUAL "clang" AND NOT ${CONAN_SETTINGS_COMPILER} STREQUAL "apple-clang")
    include (cmake/debug_flags.cmake)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${REALLY_NO_OPTIMIZATION_FLAGS}")
  endif ()
endif ()

if(EXISTS ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
else()
    message(WARNING "The file conanbuildinfo.cmake doesn't exist, you have to run conan install first")
    return()
endif()

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif ()

add_subdirectory(src)
