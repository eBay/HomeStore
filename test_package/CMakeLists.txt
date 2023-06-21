project(PackageTest CXX)
cmake_minimum_required(VERSION 3.9)

set(CMAKE_CXX_STANDARD 17)
include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)

find_package (Threads REQUIRED)
find_package (homestore REQUIRED)

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif ()

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

add_executable(hs_volume hs_volume.cpp)
target_link_libraries(hs_volume
                      homestore::homestore
                      ${spdk_LIBRARY_LIST}
                      ${dpdk_LIBRARY_LIST}
                    )
