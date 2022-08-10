include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ..)

set(BLKALLOC_SOURCE
        blk_allocator.cpp
        fixed_blk_allocator.cpp
        varsize_blk_allocator.cpp
        blk_cache_queue.cpp
        blkalloc_cp.cpp
       )
add_library(hs_blkalloc OBJECT ${BLKALLOC_SOURCE})
target_link_libraries(hs_blkalloc ${COMMON_DEPS})
add_dependencies(hs_blkalloc hs_common)

can_build_nonio_tests(build_nonio_tests)
if (${build_nonio_tests})
    set(TEST_BLKALLOC_SOURCE_FILES test_blkalloc.cpp)
    link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

    # Ignoring sign-compare only for this test file because it uses folly concurrent_skip_list which violates this check.
    set_source_files_properties(test_blkalloc.cpp PROPERTIES COMPILE_OPTIONS "-Wno-sign-compare" )
    add_executable(test_blkalloc ${TEST_BLKALLOC_SOURCE_FILES} $<TARGET_OBJECTS:hs_blkalloc>)
    target_link_libraries(test_blkalloc homestore ${COMMON_TEST_DEPS} )
    add_test(NAME BlkAlloc COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_blkalloc)

    set(TEST_BLK_CACHE_QUEUE_SOURCE_FILES test_blk_cache_queue.cpp)
    add_executable(test_blk_cache_queue ${TEST_BLK_CACHE_QUEUE_SOURCE_FILES} blk_cache_queue.cpp)
    target_link_libraries(test_blk_cache_queue homestore ${COMMON_TEST_DEPS} )
    add_test(NAME BlkCacheQueue COMMAND test_blk_cache_queue)
endif()
