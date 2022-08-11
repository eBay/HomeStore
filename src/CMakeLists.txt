cmake_minimum_required(VERSION 3.11)

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

include_directories (BEFORE .)
include_directories (BEFORE ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(engine)
add_subdirectory(homeblks)
add_subdirectory(homelogstore)
add_subdirectory(test_scripts)

add_library(homestore)
target_sources(homestore PRIVATE
      $<TARGET_OBJECTS:hs_engine>
      $<TARGET_OBJECTS:hs_common>
      $<TARGET_OBJECTS:hs_device>
      $<TARGET_OBJECTS:hs_blkalloc>
      $<TARGET_OBJECTS:hs_logdev>
      $<TARGET_OBJECTS:hs_metablk>
      $<TARGET_OBJECTS:indx_mgr>
    )

add_library(homeblks)
target_sources(homeblks PRIVATE
      $<TARGET_OBJECTS:hs_engine>
      $<TARGET_OBJECTS:hs_common>
      $<TARGET_OBJECTS:hs_device>
      $<TARGET_OBJECTS:hs_blkalloc>
      $<TARGET_OBJECTS:hs_logdev>
      $<TARGET_OBJECTS:hs_metablk>
      $<TARGET_OBJECTS:indx_mgr>
      $<TARGET_OBJECTS:hs_homeblks>
      $<TARGET_OBJECTS:hs_volume>
    )
