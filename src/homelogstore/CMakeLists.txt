include_directories (BEFORE ../engine)
set(LOGDEV_SOURCE_FILES
        log_dev.cpp
        log_group.cpp
        log_stream.cpp
        log_store.cpp
    )
add_library(hs_logdev OBJECT ${LOGDEV_SOURCE_FILES})

set(TEST_LOGSTORE_SOURCES tests/test_log_store.cpp)
add_executable(test_log_store ${TEST_LOGSTORE_SOURCES})
target_link_libraries(test_log_store hs_logdev homeblks)

set(TEST_LOGSTORE_BENCHMARK_SOURCES tests/log_store_benchmark.cpp)
add_executable(log_store_benchmark ${TEST_LOGSTORE_BENCHMARK_SOURCES})
target_link_libraries(log_store_benchmark hs_logdev homeblks)

add_test(NAME TestLogStore COMMAND test_log_store)
add_test(NAME TestVDev COMMAND test_virtual_device)
SET_TESTS_PROPERTIES(TestVDev PROPERTIES DEPENDS TestLogStore)
