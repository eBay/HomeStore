# Coverage doesn't like binaries that don't run...
if (NOT "${CONAN_TEST_TARGET}" STREQUAL "coverage")
    if (NOT "${CONAN_TEST_TARGET}" STREQUAL "off")
        set(PERF_CACHE_SOURCE_FILES
              perf_cache.cpp
              )
        add_executable(perf_cache
                        ${PERF_CACHE_SOURCE_FILES}
                      )
        target_link_libraries(perf_cache homestore ${CONAN_LIBS})
        message(WARNING "Cache perf test will not be run...fails")
        #add_test(NAME CachePerf COMMAND perf_cache)
    endif ()
endif ()

include_directories (BEFORE ..)

if (NOT "${CONAN_TEST_TARGET}" STREQUAL "off")
    set(TEST_CACHE_SOURCE_FILES
        test_cache.cpp
        )

    add_executable(test_cache
                  ${TEST_CACHE_SOURCE_FILES}
                )
    target_link_libraries(test_cache homestore iberty ${CONAN_LIBS})
    add_test(NAME TestCache COMMAND test_cache)
endif()
