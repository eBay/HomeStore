set(VOLUME_SOURCE_FILES
    volume.cpp
    mapping.cpp
    )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

#set(TEST_MERGE_SOURCE_FILES
#       vol_merge.cpp
#      )
     
if (NOT "${CONAN_TEST_TARGET}" STREQUAL "coverage")
    set(BTREE_CHECKER_SOURCE_FILES
        btree_checker.cpp
        )
    add_executable(check_btree
                   ${BTREE_CHECKER_SOURCE_FILES}
                   )
    target_link_libraries(check_btree homeblks ${CONAN_LIBS})

    set(TEST_MAP_SOURCE_FILES
        map_gtest.cpp
        )
    #add_executable(test_mapping
    #                ${TEST_MAP_SOURCE_FILES}
    #                )
    #target_link_libraries(test_mapping homeblks)
endif ()

if ("${CONAN_TEST_TARGET}" STREQUAL "full")
    set(TEST_VOLUME_SOURCE_FILES
        vol_gtest.cpp
        )
    add_executable(test_volume ${TEST_VOLUME_SOURCE_FILES})
    target_link_libraries(test_volume homeblks ${CONAN_LIBS})

    set(PERF_TEST_VOLUME_SOURCE_FILES
        vol_perf_gtest.cpp
        )
    add_executable(perf_test_volume ${PERF_TEST_VOLUME_SOURCE_FILES})
    target_link_libraries(perf_test_volume homeblks ${CONAN_LIBS})

    set(HS_SVC_TOOL_SOURCE_FILES
       hs_svc_tool.cpp
       )
    add_executable(hs_svc_tool ${HS_SVC_TOOL_SOURCE_FILES})
    target_link_libraries(hs_svc_tool homeblks ${CONAN_LIBS})

#add_executable(test_merge
#                  ${TEST_MERGE_SOURCE_FILES}
#              )

# Coverage doesn't like binaries that don't run...
    add_test(NAME TestHSSvcTool COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=hs_svc_tool --dirpath=${CMAKE_BINARY_DIR}/bin/ --)

    add_test(NAME TestVol COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/test_volume)
#add_test(NAME TestMapBtreeFix COMMAND test_volume --gtest_filter=*btree_fix_rerun_io* --max_num_writes=1000 --max_volume=10)
#SET_TESTS_PROPERTIES(TestMapBtreeFix PROPERTIES DEPENDS TestVol)
    
    add_test(NAME TestHSForceReinit COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=force_reinit --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
    SET_TESTS_PROPERTIES(TestHSForceReinit PROPERTIES DEPENDS TestVol)

    add_test(NAME TestVolRecovery COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
    SET_TESTS_PROPERTIES(TestVolRecovery PROPERTIES DEPENDS TestHSForceReinit)
     
    add_test(NAME TestVolRecoveryCrash COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh --retry_log_mods "volume:trace,indx_mgr:trace,base:debug" ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery_crash --dirpath=${CMAKE_BINARY_DIR}/bin/ --)
    SET_TESTS_PROPERTIES(TestVolRecoveryCrash PROPERTIES DEPENDS TestVolRecovery)
endif ()
