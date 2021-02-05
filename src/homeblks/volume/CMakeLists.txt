include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

set(VOLUME_SOURCE_FILES
    volume.cpp
    mapping.cpp
    )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

# Coverage doesn't like binaries that don't run...
is_non_coverage_build(non_coverage_build)
if (${non_coverage_build})
    set(BTREE_CHECKER_SOURCE_FILES tool/btree_checker.cpp)
    add_executable(check_btree ${BTREE_CHECKER_SOURCE_FILES})
    target_link_libraries(check_btree homeblks ${CONAN_LIBS})

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
    target_link_libraries(test_volume homeblks ${CONAN_LIBS})

    set(HS_SVC_TOOL_SOURCE_FILES tool/hs_svc_tool.cpp)
    add_executable(hs_svc_tool ${HS_SVC_TOOL_SOURCE_FILES})
    target_link_libraries(hs_svc_tool homeblks ${CONAN_LIBS})
    
    can_build_epoll_io_tests(is_epoll)
    if (${is_epoll})
        add_test(NAME TestHSSvcTool-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=hs_svc_tool --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
        add_test(NAME TestVol-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/test_volume)
        
        #add_test(NAME TestMapBtreeFix COMMAND test_volume --gtest_filter=*btree_fix_rerun_io* --max_num_writes=1000 --max_volume=10)
        #SET_TESTS_PROPERTIES(TestMapBtreeFix PROPERTIES DEPENDS TestVol)

        add_test(NAME TestHSForceReinit-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=force_reinit --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
        SET_TESTS_PROPERTIES(TestHSForceReinit-Epoll PROPERTIES DEPENDS TestVol-Epoll)

        add_test(NAME TestVolRecovery-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
        SET_TESTS_PROPERTIES(TestVolRecovery-Epoll PROPERTIES DEPENDS TestHSForceReinit-Epoll)
    
        add_test(NAME TestVolRecoveryCrash-Epoll COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace,base:debug" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery_crash --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
        SET_TESTS_PROPERTIES(TestVolRecoveryCrash-Epoll PROPERTIES DEPENDS TestVolRecovery-Epoll)
    endif()

    can_build_spdk_io_tests(is_spdk)
    if (${is_spdk})
        add_test(NAME TestHSSvcTool-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=hs_svc_tool --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        add_test(NAME TestVol-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/test_volume --spdk true)
        if (${is_epoll})
            SET_TESTS_PROPERTIES(TestHSSvcTool-Spdk PROPERTIES DEPENDS TestHSSvcTool-Epoll)
            SET_TESTS_PROPERTIES(TestVol-Spdk PROPERTIES DEPENDS TestVol-Epoll)
        endif()

        #add_test(NAME TestMapBtreeFix COMMAND test_volume --gtest_filter=*btree_fix_rerun_io* --max_num_writes=1000 --max_volume=10)
        #SET_TESTS_PROPERTIES(TestMapBtreeFix PROPERTIES DEPENDS TestVol)

        add_test(NAME TestHSForceReinit-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=force_reinit --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        SET_TESTS_PROPERTIES(TestHSForceReinit-Spdk PROPERTIES DEPENDS TestVol-Spdk)

        add_test(NAME TestVolRecovery-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        SET_TESTS_PROPERTIES(TestVolRecovery-Spdk PROPERTIES DEPENDS TestHSForceReinit-Spdk)
    
        add_test(NAME TestVolRecoveryCrash-Spdk COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace,base:debug" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery_crash --dirpath=${CMAKE_BINARY_DIR}/bin/ -- --spdk true)
        SET_TESTS_PROPERTIES(TestVolRecoveryCrash-Spdk PROPERTIES DEPENDS TestVolRecovery-Spdk)
    endif()
endif ()
