if(${CMAKE_BUILD_TYPE STREQUAL} STREQUAL "Debug")
    set(TEST_THREAD_POOL_SOURCE_FILES
        test_thread_pool.cpp
        )
    add_executable(test_threadpool
                   ${TEST_THREAD_POOL_SOURCE_FILES}
                   )
    target_link_libraries(test_threadpool)
    add_test(NAME ThreadPool COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_threadpool)
else()
    message(WARNING "Threadpool test disabled in Release build! Fails to build.")
endif()
