include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ..)

is_non_coverage_build(non_coverage_build)
if (${non_coverage_build})
    # Coverage doesn't like binaries that don't run...
    set(PERF_CACHE_SOURCE_FILES perf_cache.cpp)
    add_executable(perf_cache ${PERF_CACHE_SOURCE_FILES})
    target_link_libraries(perf_cache homestore ${CONAN_LIBS})
endif ()

can_build_nonio_tests(non_io_tests)
if (${non_io_tests})
    set(TEST_CACHE_SOURCE_FILES test_cache.cpp)
    add_executable(test_cache ${TEST_CACHE_SOURCE_FILES})
    target_link_libraries(test_cache homestore iberty ${CONAN_LIBS})
    add_test(NAME TestCache COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_cache)
endif()
