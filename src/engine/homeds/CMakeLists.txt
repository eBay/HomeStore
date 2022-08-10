include(${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
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

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    message(STATUS "Debug build")
    if((${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU") OR (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")) 
        remove_flag("-O[0-4]")
        add_flags("-O0")
    endif()
else()
    message(STATUS "Release build")
    if((${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU") OR (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")) 
        remove_flag("-O[0-4]")
        add_flags("-O3")
    endif()
endif()

find_package(benchmark REQUIRED)
include_directories(BEFORE ..)
link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

can_build_nonio_tests(non_io_tests)
if (${non_io_tests})
    set(TEST_BTREE_CRUD_SOURCE_FILES tests/test_btree_crud.cpp)
    add_executable(test_btree_crud ${TEST_BTREE_CRUD_SOURCE_FILES})
    target_link_libraries(test_btree_crud homestore ${COMMON_TEST_DEPS})

    set(TEST_HASH_SOURCE_FILES tests/test_hashset.cpp)
    add_executable(test_hash ${TEST_HASH_SOURCE_FILES})
    target_link_libraries(test_hash ${COMMON_TEST_DEPS} benchmark::benchmark iberty)

    set(TEST_AVECTOR_SOURCE_FILES tests/test_avector.cpp)
    add_executable(test_avector ${TEST_AVECTOR_SOURCE_FILES})
    target_link_libraries(test_avector ${COMMON_TEST_DEPS})

    set(TEST_LOAD_FILES 
            tests/loadgen_tests/test_load.cpp
            loadgen/iomgr_executor.cpp
            )
    add_executable(test_load ${TEST_LOAD_FILES})
    target_compile_options(test_load PRIVATE -Wno-deprecated)
    target_link_libraries(test_load homeblks ${COMMON_TEST_DEPS})

    set(TEST_IOMGR_EXEC_FILES 
        tests/test_iomgr_executor.cpp
        loadgen/iomgr_executor.cpp
        )
    add_executable(test_iomgr_exec ${TEST_IOMGR_EXEC_FILES})
    target_link_libraries(test_iomgr_exec homestore ${COMMON_TEST_DEPS})

    if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(TEST_THREAD_POOL_SOURCE_FILES tests/test_thread_pool.cpp)
        add_executable(test_threadpool ${TEST_THREAD_POOL_SOURCE_FILES})
        target_link_libraries(test_threadpool ${COMMON_TEST_DEPS})
    endif()
    add_test(NAME BTreeCRUD COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_btree_crud)
    add_test(NAME Hash COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_hash)
    add_test(NAME Avector COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_avector)
    # TODO: NEED TO BE FIXED SOON. Disabling this temporarily till we make api changes and fix this one
    add_test(NAME TestLoad COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*SimpleKVMemTest*)
    add_test(NAME TestLoadCache COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Cache*)
    add_test(NAME TestLoadVDev_RW COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*VDevTest_RW*)
    add_test(NAME TestLoadVDev_PRW COMMAND  ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*VDevTest_PRW*)
    add_test(NAME TestLoadMap COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Map*)
    set_tests_properties(TestLoadCache PROPERTIES RESOURCE_LOCK "TestLoad")
    set_tests_properties(TestLoadVDev_RW PROPERTIES RESOURCE_LOCK "TestLoadCache;TestLoad")
    set_tests_properties(TestLoadVDev_PRW PROPERTIES RESOURCE_LOCK "TestLoadVDev_RW;TestLoad;TestLoadCache")
    set_tests_properties(TestLoadMap PROPERTIES RESOURCE_LOCK "TestLoadVdev_PRW;TestLoad;TestLoadCache;TestLoadVDev;TestLoadVDev_RW")
    if(CMAKE_BUILD_TYPE STREQUAL Debug)
        add_test(NAME ThreadPool COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_threadpool)
    endif()

    #add_test(NAME TestVolLoadgen COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Volume* --num_vols=20)
    #SET_TESTS_PROPERTIES(TestVolLoadgen PROPERTIES DEPENDS TestLoadVDev)

    #add_test(NAME TestLoadMap COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Map*)
    #SET_TESTS_PROPERTIES(TestLoadMap PROPERTIES DEPENDS TestVolLoadgen)
endif()
