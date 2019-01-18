set (CPP_FLAGS "-faligned-new -Dlinux")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body -Wno-array-bounds")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS} -DRCU_SIGNAL")

find_package(Boost 1.64 REQUIRED)
find_package (Threads REQUIRED)

find_library(LIB_AIO aio)
find_library(LIB_DOUBLE_CONVERSION double-conversion)
set(COMMON_LIB_DEPS
      ${CONAN_LIBS}
      ${LIB_DOUBLE_CONVERSION}
      ${LIB_AIO}
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

if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
    message("Debug build")
    add_compile_options(-D_DEBUG=1 -O0 -DDEBUG_RCU -D_PRERELEASE=1)
else()
    message("Release build")
    add_compile_options(-DNDEBUG=1 -O3)
endif()

add_library(homestore
                  $<TARGET_OBJECTS:hs_main>
                  $<TARGET_OBJECTS:hs_volume>
                  $<TARGET_OBJECTS:hs_device>
                  $<TARGET_OBJECTS:hs_endpoint>
                  $<TARGET_OBJECTS:hs_blkalloc>
                  $<TARGET_OBJECTS:hs_error>
                )
target_link_libraries(homestore
                         ${COMMON_LIB_DEPS})
