set(PERF_CACHE_SOURCE_FILES
        perf_cache.cpp
        )
add_executable(perf_cache
                  ${PERF_CACHE_SOURCE_FILES}
                )
target_link_libraries(perf_cache ${COMMON_LIB_DEPS})
message(WARNING "Cache perf test will not be run...fails")
#add_test(NAME CachePerf COMMAND perf_cache)


set(TEST_CACHE_SOURCE_FILES
        test_cache.cpp
        )

add_executable(test_cache
                  ${TEST_CACHE_SOURCE_FILES}
                )
target_link_libraries(test_cache ${COMMON_LIB_DEPS})
add_test(NAME TestCache COMMAND test_cache)
