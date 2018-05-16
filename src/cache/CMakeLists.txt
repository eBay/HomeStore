
set(CACHE_SOURCE
        cache.cpp
        )
add_library(hs_cache STATIC ${CACHE_SOURCE})

#set(PERF_CACHE_SOURCE_FILES
#        perf_cache.cpp
#        )
#add_executable(perf_cache ${PERF_CACHE_SOURCE_FILES})
#target_link_libraries(perf_cache hs_cache ${CONAN_LIBS})
#
#set(TEST_CACHE_SOURCE_FILES
#        test_cache.cpp
#        )
#
#add_executable(test_cache ${TEST_CACHE_SOURCE_FILES})
#target_link_libraries(test_cache hs_cache ${CONAN_LIBS}k)
