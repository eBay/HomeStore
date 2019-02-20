set (CPP_FLAGS "-faligned-new -Dlinux")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body -Wno-array-bounds")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS} -DRCU_SIGNAL")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message("Debug build")
    add_compile_options(-D_DEBUG=1 -O0 -DDEBUG_RCU -D_PRERELEASE)
else()
    message("Release build")
    add_compile_options(-DNDEBUG=1 -O3 -D_PRERELEASE)
endif()

find_package(Boost 1.64 REQUIRED)
find_package (Threads REQUIRED)
find_library(LIB_AIO aio)
find_library(LIB_DOUBLE_CONVERSION double-conversion)
find_library(LIB_ISAL isal)

set(COMMON_LIB_DEPS
      ${CONAN_LIBS}
      ${LIB_DOUBLE_CONVERSION}
      ${LIB_AIO}
      ${LIB_ISAL}
    )

include_directories (BEFORE .)

add_subdirectory(blkalloc)
add_subdirectory(blkstore)
add_subdirectory(cache)
add_subdirectory(device)
add_subdirectory(endpoint)
add_subdirectory(homeds)
add_subdirectory(volume)
add_subdirectory(error)
add_subdirectory(main)
add_subdirectory(threadpool)
add_subdirectory(mapping)

set(HOMESTORE_OBJECTS
        $<TARGET_OBJECTS:hs_main>
        $<TARGET_OBJECTS:hs_device>
        $<TARGET_OBJECTS:hs_endpoint>
        $<TARGET_OBJECTS:hs_blkalloc>
        $<TARGET_OBJECTS:hs_error>
        )
add_library(homestore STATIC ${HOMESTORE_OBJECTS})
target_link_libraries(homestore ${COMMON_LIB_DEPS})

add_library(homeblks STATIC
                 ${HOMESTORE_OBJECTS}
                 $<TARGET_OBJECTS:hs_volume>)
target_link_libraries(homeblks ${COMMON_LIB_DEPS})
