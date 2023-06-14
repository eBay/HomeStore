cmake_minimum_required(VERSION 3.11)

include(${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

add_library(hs_logdev OBJECT)
target_sources(hs_logdev PRIVATE
      log_dev.cpp
      log_group.cpp
      log_stream.cpp
      log_store.cpp
      log_store_family.cpp
      log_store_mgr.cpp
    )
target_link_libraries(hs_logdev ${COMMON_DEPS})
add_dependencies(hs_logdev hs_common)

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

can_build_io_tests(io_tests)
if (${io_tests})
    add_executable(test_log_store)
    target_sources(test_log_store PRIVATE tests/test_log_store.cpp)
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
    add_executable(log_store_benchmark)
    target_sources(log_store_benchmark PRIVATE tests/log_store_benchmark.cpp)
    target_link_libraries(log_store_benchmark hs_logdev homeblks ${COMMON_TEST_DEPS} benchmark::benchmark )
    #add_test(NAME TestLogBench COMMAND test_log_benchmark)
endif()
