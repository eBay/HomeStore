set(LOGDEV_SOURCE_FILES
        log_dev.cpp
        log_group.cpp
        log_store.cpp
    )
add_library(hs_logdev OBJECT ${LOGDEV_SOURCE_FILES})

#set(TEST_LOGDEV_SOURCES tests/test_log_dev.cpp)
#add_executable(test_log_dev ${TEST_LOGDEV_SOURCES})
#target_link_libraries(test_log_dev hs_logdev sisl homeblks ${CONAN_LIBS})

set(TEST_LOGSTORE_SOURCES tests/test_log_store.cpp)
add_executable(test_log_store ${TEST_LOGSTORE_SOURCES})
target_link_libraries(test_log_store hs_logdev sisl homeblks ${CONAN_LIBS})
add_test(NAME TestLogStore COMMAND test_log_store)