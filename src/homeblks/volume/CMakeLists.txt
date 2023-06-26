include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

add_flags("-Wno-stringop-truncation")
set(VOLUME_SOURCE_FILES
    volume.cpp
    mapping.cpp
    )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})
target_link_libraries(hs_volume ${COMMON_DEPS})

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

# Coverage doesn't like binaries that don't run...
is_non_coverage_build(non_coverage_build)
if (${non_coverage_build})
    set(BTREE_CHECKER_SOURCE_FILES tool/btree_checker.cpp)
    add_executable(check_btree ${BTREE_CHECKER_SOURCE_FILES})
    target_link_libraries(check_btree homeblks ${COMMON_TEST_DEPS})

    #set(PERF_TEST_VOLUME_SOURCE_FILES tests/vol_perf_gtest.cpp)
    #add_executable(perf_test_volume ${PERF_TEST_VOLUME_SOURCE_FILES})
    #target_link_libraries(perf_test_volume homeblks ${CONAN_LIBS})
endif()

can_build_io_tests(build_io_tests)
if (${build_io_tests})
    #set(TEST_MAP_SOURCE_FILES tests/map_gtest.cpp)
    #add_executable(test_mapping ${TEST_MAP_SOURCE_FILES})
    #target_link_libraries(test_mapping homeblks)

    #set(TEST_MERGE_SOURCE_FILES tests/vol_merge.cpp)
    #add_executable(test_merge ${TEST_MERGE_SOURCE_FILES})

    set(TEST_VOLUME_SOURCE_FILES tests/vol_gtest.cpp tests/mod_test_vdev.cpp tests/mod_test_meta.cpp)
    add_executable(test_volume ${TEST_VOLUME_SOURCE_FILES})
    target_link_libraries(test_volume homeblks ${COMMON_TEST_DEPS})

    set(HS_SVC_TOOL_SOURCE_FILES tool/hs_svc_tool.cpp)
    add_executable(hs_svc_tool ${HS_SVC_TOOL_SOURCE_FILES})
    target_link_libraries(hs_svc_tool homeblks ${COMMON_TEST_DEPS})

    # disable the test for now
    #add_test(NAME TestHttpSanity COMMAND ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=http_sanity_test --dirpath=${CMAKE_BINARY_DIR}/bin/)
    
    can_build_epoll_io_tests(is_epoll)
    if (${is_epoll})
        add_test(NAME TestHSSvcTool-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=hs_svc_tool --dirpath=${CMAKE_BINARY_DIR}/bin/ --emulate_hdd=1 --)
        add_test(NAME TestVol-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_volume --emulate_hdd_cnt=1)
        #SET_TESTS_PROPERTIES(TestVol-Epoll PROPERTIES DEPENDS TestHttpSanity)
        
        #add_test(NAME TestMapBtreeFix COMMAND test_volume --gtest_filter=*btree_fix_rerun_io* --max_num_writes=1000 --max_volume=10)
        #SET_TESTS_PROPERTIES(TestMapBtreeFix PROPERTIES DEPENDS TestVol)

        if (${PRERELEASE_ON})
            add_test(NAME TestHSForceReinit-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=force_reinit --dirpath=${CMAKE_BINARY_DIR}/bin/ --emulate_hdd=1 --)
            SET_TESTS_PROPERTIES(TestHSForceReinit-Epoll PROPERTIES DEPENDS TestVol-Epoll)
        endif()


        add_test(NAME TestVolCopy-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=copy_vol --dirpath=${CMAKE_BINARY_DIR}/bin/ --emulate_hdd=1 --)
        if (${PRERELEASE_ON})
            SET_TESTS_PROPERTIES(TestVolCopy-Epoll PROPERTIES DEPENDS TestHSForceReinit-Epoll)
        else()
            SET_TESTS_PROPERTIES(TestVolCopy-Epoll PROPERTIES DEPENDS TestVol-Epoll)
        endif()

        add_test(NAME TestVolBtreePagintion-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=btree_node_pagination --dirpath=${CMAKE_BINARY_DIR}/bin/ --emulate_hdd=1 --)
        SET_TESTS_PROPERTIES(TestVolBtreePagintion-Epoll PROPERTIES DEPENDS TestVolCopy-Epoll)

        add_test(NAME TestVolRecovery-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/ --emulate_hdd=1 --)
        SET_TESTS_PROPERTIES(TestVolRecovery-Epoll PROPERTIES DEPENDS TestVolBtreePagintion-Epoll)
            
        add_test(NAME TestVolRecoveryCrash-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery_crash --dirpath=${CMAKE_BINARY_DIR}/bin/ --emulate_hdd=1 --)
        SET_TESTS_PROPERTIES(TestVolRecoveryCrash-Epoll PROPERTIES DEPENDS TestVolRecovery-Epoll)
        add_test(NAME TestVolError-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_volume --flip=2 --verify_type=2 --emulate_hdd_cnt=1)
        SET_TESTS_PROPERTIES(TestVolError-Epoll PROPERTIES DEPENDS TestVolRecoveryCrash-Epoll)
        add_test(NAME TestVolUnmap-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_volume --unmap_enable=1 --verify_type=2 --emulate_hdd_cnt=1)
        SET_TESTS_PROPERTIES(TestVolUnmap-Epoll PROPERTIES DEPENDS TestVolError-Epoll)
    endif()

    can_build_spdk_io_tests(is_spdk)
    if (${is_spdk})
        add_test(NAME TestHSSvcTool-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=hs_svc_tool --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        add_test(NAME TestVol-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_volume --spdk true)
        if (${is_epoll})
            SET_TESTS_PROPERTIES(TestHSSvcTool-Spdk PROPERTIES DEPENDS TestMetaBlkMgr-Spdk)
            # TestVol-Spdk depends on the last binary run in epoll mode because epoll tests and test_volume rely on binding to 5000 port.
            SET_TESTS_PROPERTIES(TestVol-Spdk PROPERTIES DEPENDS TestVolUnmap-Epoll)
        endif()

        #add_test(NAME TestMapBtreeFix COMMAND test_volume --gtest_filter=*btree_fix_rerun_io* --max_num_writes=1000 --max_volume=10)
        #SET_TESTS_PROPERTIES(TestMapBtreeFix PROPERTIES DEPENDS TestVol)

        if (${PRERELEASE_ON})
            add_test(NAME TestHSForceReinit-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=force_reinit --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
            SET_TESTS_PROPERTIES(TestHSForceReinit-Spdk PROPERTIES DEPENDS TestVol-Spdk)
        endif()

        add_test(NAME TestVolCopy-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=copy_vol --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        if (${PRERELEASE_ON})
            SET_TESTS_PROPERTIES(TestVolCopy-Spdk PROPERTIES DEPENDS TestHSForceReinit-Spdk)
        else()
            SET_TESTS_PROPERTIES(TestVolCopy-Spdk PROPERTIES DEPENDS TestVol-Spdk)
        endif()

        add_test(NAME TestVolRecovery-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        SET_TESTS_PROPERTIES(TestVolRecovery-Spdk PROPERTIES DEPENDS TestVolCopy-Spdk)

        add_test(NAME TestVolRecoveryCrash-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery_crash --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        SET_TESTS_PROPERTIES(TestVolRecoveryCrash-Spdk PROPERTIES DEPENDS TestVolRecovery-Spdk)
        add_test(NAME TestVolError-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_volume --spdk --flip=2 --verify_type=2)
        SET_TESTS_PROPERTIES(TestVolError-Spdk PROPERTIES DEPENDS TestVolRecoveryCrash-Spdk)
        add_test(NAME TestVolUnmap-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_volume --spdk --unmap_enable=1 --verify_type=2)
        SET_TESTS_PROPERTIES(TestVolUnmap-Spdk PROPERTIES DEPENDS TestVolError-Spdk)
    endif()
endif ()
