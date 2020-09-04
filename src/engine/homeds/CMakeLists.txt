message(WARNING "BTree test disabled due to interface change.")
# XXX: Out of date with BTree interface
#set(TEST_BTREE_SOURCE_FILES
#        tests/test_btree.cpp
#        )
#add_executable(test_btree
#                  ${TEST_BTREE_SOURCE_FILES}
#                )
#target_link_libraries(test_btree ${COMMON_LIB_DEPS})
#add_test(NAME BTree COMMAND test_btree)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message(STATUS "Debug build")
    add_compile_options(-D_DEBUG=1 -O0 -DDEBUG_RCU -D_PRERELEASE=1)
else()
    message(STATUS "Release build")
    add_compile_options(-DNDEBUG=1 -O3)
endif()

include_directories(BEFORE ..)

if (NOT "${CONAN_TEST_TARGET}" STREQUAL "off")
    set(TEST_BTREE_CRUD_SOURCE_FILES tests/test_btree_crud.cpp)
    add_executable(test_btree_crud ${TEST_BTREE_CRUD_SOURCE_FILES})
    target_link_libraries(test_btree_crud homestore ${CONAN_LIBS})

    set(TEST_HASH_SOURCE_FILES tests/test_hashset.cpp)
    add_executable(test_hash ${TEST_HASH_SOURCE_FILES})
    target_link_libraries(test_hash ${CONAN_LIBS} iberty)

    set(TEST_AVECTOR_SOURCE_FILES tests/test_avector.cpp)
    add_executable(test_avector ${TEST_AVECTOR_SOURCE_FILES})
    target_link_libraries(test_avector ${CONAN_LIBS})

    set(TEST_LOAD_FILES 
            tests/loadgen_tests/test_load.cpp
            loadgen/iomgr_executor.cpp
            )
    add_executable(test_load ${TEST_LOAD_FILES})
    target_link_libraries(test_load homeblks ${CONAN_LIBS})

    set(TEST_IOMGR_EXEC_FILES 
        tests/test_iomgr_executor.cpp
        loadgen/iomgr_executor.cpp
        )
    add_executable(test_iomgr_exec ${TEST_IOMGR_EXEC_FILES})
    target_link_libraries(test_iomgr_exec homestore ${CONAN_LIBS})

    if(CMAKE_BUILD_TYPE STREQUAL Debug)
        set(TEST_THREAD_POOL_SOURCE_FILES
            tests/test_thread_pool.cpp
            )
    add_executable(test_threadpool
        ${TEST_THREAD_POOL_SOURCE_FILES}
        )
    target_link_libraries(test_threadpool ${CONAN_LIBS})
    endif()

    add_test(NAME BTreeCRUD COMMAND test_btree_crud)
    add_test(NAME Hash COMMAND test_hash)
    add_test(NAME Avector COMMAND test_avector)
    add_test(NAME TestLoadCache COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Cache*)
    add_test(NAME TestLoadVDev COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*VDevTest_RW* && ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*VDevTest_PRW*)
    if(CMAKE_BUILD_TYPE STREQUAL Debug)
      add_test(NAME ThreadPool COMMAND test_threadpool)
    endif()
    SET_TESTS_PROPERTIES(TestLoadVDev PROPERTIES DEPENDS TestLoadCache)

#add_test(NAME TestVolLoadgen COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Volume* --num_vols=20)
#SET_TESTS_PROPERTIES(TestVolLoadgen PROPERTIES DEPENDS TestLoadVDev)

#add_test(NAME TestLoadMap COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Map*)
#SET_TESTS_PROPERTIES(TestLoadMap PROPERTIES DEPENDS TestVolLoadgen)
endif()
