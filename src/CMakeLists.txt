cmake_minimum_required(VERSION 3.13)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)

find_package(Threads)
find_library(LIB_AIO aio REQUIRED)
find_package(isa-l REQUIRED)
find_package(iomgr REQUIRED)
find_package(farmhash REQUIRED)
find_package(GTest REQUIRED)

set (COMMON_DEPS
        iomgr::iomgr
        farmhash::farmhash
        isa-l::isa-l
        sisl::sisl
    )

set(COMMON_TEST_DEPS
        ${COMMON_DEPS}
        ${spdk_LIBRARY_LIST}
        ${dpdk_LIBRARY_LIST}
        GTest::gmock
    )

include_directories (BEFORE lib/)
include_directories (BEFORE include/)
include_directories (BEFORE ${CMAKE_CURRENT_BINARY_DIR}/lib)

add_subdirectory(lib/blkalloc)
add_subdirectory(lib/device)
add_subdirectory(lib/checkpoint)
add_subdirectory(lib/common)
add_subdirectory(lib/logstore)
add_subdirectory(lib/meta)
add_subdirectory(lib/index)

add_subdirectory(tests)
set(HOMESTORE_OBJECTS
    $<TARGET_OBJECTS:hs_common> 
    $<TARGET_OBJECTS:hs_device> 
    $<TARGET_OBJECTS:hs_blkalloc> 
    $<TARGET_OBJECTS:hs_logdev> 
    $<TARGET_OBJECTS:hs_metablk>
    $<TARGET_OBJECTS:hs_checkpoint>
    $<TARGET_OBJECTS:hs_index>
    lib/homestore.cpp
    #$<TARGET_OBJECTS:hs_cp>
    #$<TARGET_OBJECTS:indx_mgr>
)
#target_link_libraries(homestore_objs ${COMMON_DEPS})

add_library(homestore STATIC 
    ${HOMESTORE_OBJECTS} 
)
target_link_libraries(homestore ${COMMON_DEPS})
