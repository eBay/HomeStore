cmake_minimum_required(VERSION 3.13)

include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ../include/)
include_directories (BEFORE ../lib/)
include_directories (BEFORE .)

can_build_nonio_tests(build_nonio_tests)
if (${build_nonio_tests})
    link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

    # Ignoring sign-compare only for this test file because it uses folly concurrent_skip_list which violates this check.
    set_source_files_properties(test_blkalloc.cpp PROPERTIES COMPILE_OPTIONS "-Wno-sign-compare" )
    add_executable(test_blkalloc)
    target_sources(test_blkalloc PRIVATE test_blkalloc.cpp $<TARGET_OBJECTS:hs_blkalloc>)
    target_link_libraries(test_blkalloc homestore ${COMMON_TEST_DEPS} )
    add_test(NAME BlkAlloc COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_blkalloc)

    add_executable(test_blk_cache_queue)
    target_sources(test_blk_cache_queue PRIVATE test_blk_cache_queue.cpp ../lib/blkalloc/blk_cache_queue.cpp)
    target_link_libraries(test_blk_cache_queue homestore ${COMMON_TEST_DEPS} )
    add_test(NAME BlkCacheQueue COMMAND test_blk_cache_queue)

    set(TEST_VDEV_SOURCES test_vdev.cpp)
    add_executable(test_virtual_device ${TEST_VDEV_SOURCES})
    target_link_libraries(test_virtual_device homestore ${COMMON_TEST_DEPS} GTest::gmock)
    add_test(NAME VirtualDev COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_virtual_device)

    set(TEST_BTREENODE_SOURCE_FILES test_btree_node.cpp)
    add_executable(test_btree_node ${TEST_BTREENODE_SOURCE_FILES})
    target_link_libraries(test_btree_node ${COMMON_TEST_DEPS} GTest::gtest)
    add_test(NAME BtreeNode COMMAND test_btree_node)

    set(TEST_MEMBTREE_SOURCE_FILES test_mem_btree.cpp)
    add_executable(test_mem_btree ${TEST_MEMBTREE_SOURCE_FILES})
    target_link_libraries(test_mem_btree ${COMMON_TEST_DEPS} GTest::gtest)
    add_test(NAME MemBtree COMMAND test_mem_btree)

    add_executable(test_blk_read_tracker)
    target_sources(test_blk_read_tracker PRIVATE test_blk_read_tracker.cpp ../lib/blkdata_svc/blk_read_tracker.cpp ../lib/blkalloc/blk.cpp)
    target_link_libraries(test_blk_read_tracker ${COMMON_TEST_DEPS} GTest::gtest)
    add_test(NAME BlkReadTracker COMMAND test_blk_read_tracker)


endif()

can_build_io_tests(io_tests)
if (${io_tests})

    add_executable(test_data_service)
    target_sources(test_data_service PRIVATE test_data_service.cpp) 
    target_link_libraries(test_data_service homestore ${COMMON_TEST_DEPS} GTest::gmock)

    add_executable(test_log_store)
    target_sources(test_log_store PRIVATE test_log_store.cpp)
    target_link_libraries(test_log_store hs_logdev homestore ${COMMON_TEST_DEPS} )

    set(TEST_METABLK_SOURCE_FILES test_meta_blk_mgr.cpp)
    add_executable(test_meta_blk_mgr ${TEST_METABLK_SOURCE_FILES})
    target_link_libraries(test_meta_blk_mgr homestore ${COMMON_TEST_DEPS} GTest::gmock)

    add_executable(test_cp_mgr)
    target_sources(test_cp_mgr PRIVATE test_cp_mgr.cpp)
    target_link_libraries(test_cp_mgr homestore ${COMMON_TEST_DEPS} GTest::gtest)
    add_test(NAME CPMgr COMMAND test_cp_mgr)

    can_build_epoll_io_tests(epoll_tests)
    if(${epoll_tests})
        add_test(NAME LogStore-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_log_store)
        add_test(NAME MetaBlkMgr-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_meta_blk_mgr)
        add_test(NAME DataSerice-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_data_service)
    endif()

    can_build_spdk_io_tests(spdk_tests)
    if(${spdk_tests})
        add_test(NAME LogStore-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_log_store -- --spdk true)
        add_test(NAME MetaBlkMgr-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_meta_blk_mgr -- --spdk "true")
        add_test(NAME DataSerice-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_data_service -- --spdk "true")
        if(${epoll_tests})
        SET_TESTS_PROPERTIES(MetaBlkMgr-Spdk PROPERTIES DEPENDS LogStore-Spdk)
        SET_TESTS_PROPERTIES(DataSerice-Spdk PROPERTIES DEPENDS MetaBlkMgr-Spdk)
        endif()
    endif()
endif()

is_non_coverage_build(non_coverage_build)
if (${non_coverage_build})
    find_package(benchmark REQUIRED)
    add_executable(log_store_benchmark)
    target_sources(log_store_benchmark PRIVATE log_store_benchmark.cpp)
    target_link_libraries(log_store_benchmark hs_logdev homestore ${COMMON_TEST_DEPS} benchmark::benchmark)
    #add_test(NAME LogStoreBench COMMAND test_log_benchmark)
endif()
