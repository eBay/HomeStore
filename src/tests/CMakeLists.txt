cmake_minimum_required(VERSION 3.13)

include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ../include/)
include_directories (BEFORE ../lib/)
include_directories (BEFORE ../tests/)
include_directories (BEFORE .)
add_subdirectory(test_scripts)

can_build_nonio_tests(build_nonio_tests)
if (${build_nonio_tests})
    link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

    # Ignoring sign-compare only for this test file because it uses folly concurrent_skip_list which violates this check.
    set_source_files_properties(test_blkalloc.cpp PROPERTIES COMPILE_OPTIONS "-Wno-sign-compare" )

    add_executable(test_raft_repl_dev)
    target_sources(test_raft_repl_dev PRIVATE test_raft_repl_dev.cpp)
    target_link_libraries(test_raft_repl_dev homestore ${COMMON_TEST_DEPS} GTest::gmock)
    add_test(NAME RaftReplDev-Epoll COMMAND ${CMAKE_BINARY_DIR}/bin/test_raft_repl_dev)

endif()


is_non_coverage_build(non_coverage_build)
if (${non_coverage_build})
    find_package(benchmark REQUIRED)
    add_executable(log_store_benchmark)
    target_sources(log_store_benchmark PRIVATE log_store_benchmark.cpp)
    target_link_libraries(log_store_benchmark hs_logdev homestore ${COMMON_TEST_DEPS} benchmark::benchmark)

    add_executable(index_btree_benchmark)
    target_sources(index_btree_benchmark PRIVATE index_btree_benchmark.cpp)
    target_link_libraries(index_btree_benchmark homestore ${COMMON_TEST_DEPS} benchmark::benchmark)
endif()
