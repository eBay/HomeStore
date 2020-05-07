cmake_minimum_required(VERSION 3.9)
project(HomeStore)

set(CMAKE_CXX_STANDARD 17)
enable_testing()

if(EXISTS ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
else ()
  message(WARNING "The file conanbuildinfo.cmake doesn't exist, you have to run conan install first")
endif ()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  if (NOT ${CONAN_SETTINGS_COMPILER} STREQUAL "clang" AND NOT ${CONAN_SETTINGS_COMPILER} STREQUAL "apple-clang")
    include (cmake/debug_flags.cmake)
  endif ()
endif()

set(ASAN_ENABLED_BUILD false)
if ($ENV{ASAN_OPTIONS} MATCHES "detect_leaks=1") 
  message("Running with ASAN leak detection ON")
  set(ASAN_ENABLED_BUILD true)
endif()

if (${MEMORY_SANITIZER_ON})
  message("Running with Memory Sanitizer ON")
  include (cmake/mem_sanitizer.cmake)
endif ()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  if (NOT ${ASAN_ENABLED_BUILD})
    message(AUTHOR_WARNING "********* WARNING: Running with ASAN leak detection OFF for debug build *********")
    message("If not desired, set the env variable as follows and rerun the build")
    message("'ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:disable_coredump=0::unmap_shadow_on_exit=1'")
  endif()

  if (NOT ${MEMORY_SANITIZER_ON})
    message(AUTHOR_WARNING "********* WARNING: Running with Memory Sanitizer OFF for debug build *********")
  endif()
endif()


include(${CONAN_SISL_ROOT}/cmake/settings_gen.cmake)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif ()

add_subdirectory(src)
