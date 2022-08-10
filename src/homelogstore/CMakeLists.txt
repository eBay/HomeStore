include(${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
set(LOGDEV_SOURCE_FILES
    log_dev.cpp
    log_group.cpp
    log_stream.cpp
    log_store.cpp
    log_store_family.cpp
    log_store_mgr.cpp
    )
add_library(hs_logdev OBJECT ${LOGDEV_SOURCE_FILES})
target_link_libraries(hs_logdev
    ${COMMON_DEPS}
  )

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

can_build_io_tests(io_tests)
if (${io_tests})
    set(TEST_LOGSTORE_SOURCES tests/test_log_store.cpp)
    add_executable(test_log_store ${TEST_LOGSTORE_SOURCES})
    target_link_libraries(test_log_store hs_logdev homeblks ${COMMON_TEST_DEPS} )

    can_build_epoll_io_tests(epoll_tests)
    if(${epoll_tests})
        add_test(NAME TestLogStore-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_log_store)
    endif()

    can_build_spdk_io_tests(spdk_tests)
    if(${spdk_tests})
        add_test(NAME TestLogStore-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_log_store -- --spdk true)
        if(${epoll_tests})
            SET_TESTS_PROPERTIES(TestLogStore-Spdk PROPERTIES DEPENDS TestVolError-Epoll)
        endif()
    endif()
endif()

find_package(benchmark REQUIRED)

is_non_coverage_build(non_coverage_build)
if (${non_coverage_build})
    set(TEST_LOGSTORE_BENCHMARK_SOURCES tests/log_store_benchmark.cpp)
    add_executable(log_store_benchmark ${TEST_LOGSTORE_BENCHMARK_SOURCES})
    target_link_libraries(log_store_benchmark hs_logdev homeblks ${COMMON_TEST_DEPS} benchmark::benchmark )
    #add_test(NAME TestLogBench COMMAND test_log_benchmark)
endif()
