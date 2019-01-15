set (CPP_FLAGS "-faligned-new -Dlinux")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body -Wno-array-bounds")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS}") 

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
add_subdirectory(metrics)
add_subdirectory(main)
add_subdirectory(threadpool)

add_library(homestore
                  $<TARGET_OBJECTS:hs_main>
                  $<TARGET_OBJECTS:hs_volume>
                  $<TARGET_OBJECTS:hs_device>
                  $<TARGET_OBJECTS:hs_endpoint>
                  $<TARGET_OBJECTS:hs_blkalloc>
                  $<TARGET_OBJECTS:hs_error>
                  $<TARGET_OBJECTS:hs_metrics>
                )
target_link_libraries(homestore
                         ${COMMON_LIB_DEPS})
