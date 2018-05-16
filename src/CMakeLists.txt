set (CPP_FLAGS "-faligned-new -Dlinux")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body -Wno-array-bounds")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS}") 

find_package(Boost 1.64 REQUIRED)
find_package (Threads REQUIRED)

find_library(LIB_AIO aio)
find_library(LIB_DOUBLE_CONVERSION double-conversion)

include_directories (BEFORE .)

add_subdirectory(blkalloc)
add_subdirectory(cache)
add_subdirectory(device)
add_subdirectory(endpoint)
add_subdirectory(volume)

add_library(homestore
                  $<TARGET_OBJECTS:hs_volume>
                  $<TARGET_OBJECTS:hs_device>
                  $<TARGET_OBJECTS:hs_endpoint>
                  $<TARGET_OBJECTS:hs_cache>
                  $<TARGET_OBJECTS:hs_blkalloc>
                )
target_link_libraries(homestore
                         ${CONAN_LIBS}
                         ${LIB_DOUBLE_CONVERSION}
                         ${LIB_AIO})


add_executable(test_volume volume/vol_test.cpp)
target_link_libraries(test_volume homestore)
