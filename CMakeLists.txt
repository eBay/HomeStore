cmake_minimum_required(VERSION 3.9)
project(HomeStore)

option(DEBUG_CMAKE "Debug CMake messages option" OFF)

# Set Global CMake Options
set_property(GLOBAL PROPERTY USE_FOLDERS ON) # turn on folder hierarchies

include (cmake/Flags.cmake)

set(CMAKE_CXX_STANDARD 17)
enable_testing()

if(EXISTS ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
else ()
  message(FATAL_ERROR "The file conanbuildinfo.cmake doesn't exist, you have to run conan install first")
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
  if (NOT ${CONAN_SETTINGS_COMPILER} STREQUAL "clang" AND NOT ${CONAN_SETTINGS_COMPILER} STREQUAL "apple-clang")
    include (cmake/debug_flags.cmake)
  endif ()
endif()

set(ASAN_ENABLED_BUILD false)
if ($ENV{ASAN_OPTIONS} MATCHES "detect_leaks=1") 
  message(STATUS "Running with ASAN leak detection ON")
  set(ASAN_ENABLED_BUILD true)
endif()

if (DEFINED MALLOC_IMPL)
    if (${MALLOC_IMPL} STREQUAL "jemalloc")
        add_flags("-DUSE_JEMALLOC=1")
        # turn off memory sanitizer if using jemalloc otherwise folly will cause double definition errors
        if (DEFINED MEMORY_SANITIZER_ON) 
            unset(MEMORY_SANITIZER_ON CACHE)
        endif()
    elseif (${MALLOC_IMPL} STREQUAL "tcmalloc")
        add_flags("-DUSING_TCMALLOC=1")
    endif()
endif()

if (${MEMORY_SANITIZER_ON})
  message(STATUS "Running with Memory Sanitizer ON")
  include (cmake/mem_sanitizer.cmake)
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
  if (NOT ${ASAN_ENABLED_BUILD})
    message(AUTHOR_WARNING "********* WARNING: Running with ASAN leak detection OFF for debug build *********")
    message(STATUS "If not desired, set the env variable as follows and rerun the build")
    message(STATUS "'ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:disable_coredump=0::unmap_shadow_on_exit=1'")
  endif()

  if (NOT ${MEMORY_SANITIZER_ON})
    message(AUTHOR_WARNING "********* WARNING: Running with Memory Sanitizer OFF for debug build *********")
  endif()
endif()

message(STATUS "Building with Malloc Impl = ${MALLOC_IMPL}")

include(${CONAN_SISL_ROOT}/cmake/settings_gen.cmake)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif ()

if((${CMAKE_C_COMPILER_ID} STREQUAL "GNU") OR (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")) 
    # add linux options
    add_flags("-Dlinux")
    
    # add compiler options
    add_flags("-faligned-new -fconcepts" Languages "CXX")
    
    # add warning options
    add_flags("-Wall -Wextra -Werror")
    add_flags("-Wno-empty-body -Wno-array-bounds -Wno-cast-function-type")
    add_flags("-Wno-unused-parameter -Wno-unused-variable -Wno-maybe-uninitialized -Wno-unused-function")
    
    # add C++ only warning options
    add_flags("-Wno-deprecated-copy" Languages "CXX")
endif()

# add boost options
add_flags("-DBOOST_ALLOW_DEPRECATED_HEADERS")

# add conan information 
add_flags("-DPACKAGE_NAME=\\\"${CONAN_PACKAGE_NAME}\\\"")
add_flags("-DPACKAGE_VERSION=\\\"${CONAN_PACKAGE_VERSION}\\\"")

if(UNIX)
    # enable proper pread/pwrite and large file
    add_flags("-D_POSIX_C_SOURCE=200809L -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE")
endif()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    message(STATUS "Debug build")
    if((${CMAKE_C_COMPILER_ID} STREQUAL "GNU") OR (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")) 
        remove_flag("-O[0-4]")
        add_flags("-O0 -DDEBUG_RCU -D_PRERELEASE=1")
    endif()
else()
    message(STATUS "Release build")
    if((${CMAKE_C_COMPILER_ID} STREQUAL "GNU") OR (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")) 
        remove_flag("-O[0-4]")
        add_flags("-O2 -D_PRERELEASE=1")
    endif()
endif()

add_subdirectory(src)

# build info
string(TOUPPER "${CMAKE_BUILD_TYPE}" UC_CMAKE_BUILD_TYPE)
message(STATUS "Build configuration:       ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler info:           ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} ${CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN}")
message(STATUS "C++ compiler info:         ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} ${CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN}")
message(STATUS "C flags:                   ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${UC_CMAKE_BUILD_TYPE}}")
message(STATUS "C++ flags:                 ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${UC_CMAKE_BUILD_TYPE}}")
message(STATUS "Linker flags (executable): ${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${UC_CMAKE_BUILD_TYPE}}")
message(STATUS "Linker flags (shared):     ${CMAKE_SHARED_LINKER_FLAGS} ${CMAKE_SHARED_LINKER_FLAGS_${UC_CMAKE_BUILD_TYPE}}")
message(STATUS "Linker flags (module):     ${CMAKE_MODULE_LINKER_FLAGS} ${CMAKE_MODULE_LINKER_FLAGS_${UC_CMAKE_BUILD_TYPE}}")
message(STATUS "Linker flags (static):     ${CMAKE_STATIC_LINKER_FLAGS} ${CMAKE_STATIC_LINKER_FLAGS_${UC_CMAKE_BUILD_TYPE}}")
