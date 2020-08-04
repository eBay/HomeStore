set(VOLUME_SOURCE_FILES
       volume.cpp
       mapping.cpp
      )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

#set(TEST_MERGE_SOURCE_FILES
#       vol_merge.cpp
#      )
set(TEST_VOLUME_SOURCE_FILES
       vol_gtest.cpp
      )
set(PERF_TEST_VOLUME_SOURCE_FILES
       vol_perf_gtest.cpp
      )
set(BTREE_CHECKER_SOURCE_FILES
       btree_checker.cpp
      )
set(TEST_MAP_SOURCE_FILES
      map_gtest.cpp
     )
     
#add_executable(test_merge
#                  ${TEST_MERGE_SOURCE_FILES}
#              )
add_executable(test_volume
                  ${TEST_VOLUME_SOURCE_FILES}
                )


# Coverage doesn't like binaries that don't run...
if (NOT ${CONAN_BUILD_COVERAGE})
    add_executable(perf_test_volume
                      ${PERF_TEST_VOLUME_SOURCE_FILES}
                    )
    add_executable(check_btree
                      ${BTREE_CHECKER_SOURCE_FILES}
                    )
    #add_executable(test_mapping
    #                ${TEST_MAP_SOURCE_FILES}
    #                )
    target_link_libraries(check_btree homeblks ${CONAN_LIBS})
    target_link_libraries(perf_test_volume homeblks ${CONAN_LIBS})
    #target_link_libraries(test_mapping homeblks)
endif ()

target_link_libraries(test_volume homeblks ${CONAN_LIBS})

add_test(NAME TestVol COMMAND test_volume)

#add_test(NAME TestMapBtreeFix COMMAND test_volume --gtest_filter=*btree_fix_rerun_io* --max_num_writes=1000 --max_volume=10)
#SET_TESTS_PROPERTIES(TestMapBtreeFix PROPERTIES DEPENDS TestVol)

add_test(NAME TestVolRecovery COMMAND ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/)
SET_TESTS_PROPERTIES(TestVolRecovery PROPERTIES DEPENDS TestVol)
#add_test(NAME TestVolRecoveryCrash COMMAND ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery_crash --dirpath=${CMAKE_BINARY_DIR}/bin/)
#SET_TESTS_PROPERTIES(TestVolRecoveryCrash PROPERTIES DEPENDS TestVolRecovery)
