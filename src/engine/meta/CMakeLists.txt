include(${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ../)

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

set(METABLK_SOURCE_FILES meta_blks_mgr.cpp)
add_library(hs_metablk OBJECT ${METABLK_SOURCE_FILES})
target_link_libraries(hs_metablk ${COMMON_DEPS})

can_build_io_tests(io_tests)
if (${io_tests})
    set(TEST_METABLK_SOURCE_FILES test_meta_blk_mgr.cpp)
    add_executable(test_meta_blk_mgr ${TEST_METABLK_SOURCE_FILES})
    target_link_libraries(test_meta_blk_mgr homeblks ${COMMON_TEST_DEPS})

    can_build_epoll_io_tests(epoll_tests)
    if(${epoll_tests})
        add_test(NAME TestMetaBlkMgr-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_meta_blk_mgr)
    endif()

    can_build_spdk_io_tests(spdk_tests)
    if(${spdk_tests})
        add_test(NAME TestMetaBlkMgr-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_meta_blk_mgr -- --spdk "true")
        if(${epoll_tests})
            SET_TESTS_PROPERTIES(TestMetaBlkMgr-Spdk PROPERTIES DEPENDS TestLogStore-Spdk)
            SET_TESTS_PROPERTIES(TestMetaBlkMgr-Spdk PROPERTIES DEPENDS TestVolError-Epoll)
        endif()
    endif()
endif()
