cmake_minimum_required(VERSION 3.13)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)

find_package(Threads)
find_library(LIB_AIO aio QUIET REQUIRED)
find_package(isa-l QUIET)
find_package(iomgr QUIET REQUIRED)
find_package(farmhash QUIET REQUIRED)
find_package(GTest QUIET REQUIRED)
find_package(NuraftMesg QUIET REQUIRED)

list(APPEND COMMON_DEPS
    iomgr::iomgr
    farmhash::farmhash
    nuraft_mesg::proto
    nuraft::nuraft
    sisl::sisl
)
if (${isa-l_FOUND})
    list(APPEND COMMON_DEPS isa-l::isa-l)
else ()
    add_flags("-DNO_ISAL")
endif()

list(APPEND COMMON_TEST_DEPS
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
add_subdirectory(lib/blkdata_svc/)
add_subdirectory(lib/replication/)

add_subdirectory(tests)
set(HOMESTORE_OBJECTS
    $<TARGET_OBJECTS:hs_common> 
    $<TARGET_OBJECTS:hs_device> 
    $<TARGET_OBJECTS:hs_blkalloc> 
    $<TARGET_OBJECTS:hs_logdev> 
    $<TARGET_OBJECTS:hs_metablk>
    $<TARGET_OBJECTS:hs_checkpoint>
    $<TARGET_OBJECTS:hs_index>
    $<TARGET_OBJECTS:hs_datasvc>
    $<TARGET_OBJECTS:hs_replication>
    lib/homestore.cpp
    lib/crc.cpp
    lib/logging.cpp
    #$<TARGET_OBJECTS:hs_cp>
    #$<TARGET_OBJECTS:indx_mgr>
)
#target_link_libraries(homestore_objs ${COMMON_DEPS})

add_library(homestore STATIC 
    ${HOMESTORE_OBJECTS} 
)
target_link_libraries(homestore ${COMMON_DEPS})
