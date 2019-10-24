set(VOLUME_SOURCE_FILES
       volume.cpp
       home_blks.cpp
       blk_read_tracker.cpp
      )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

set(TEST_MERGE_SOURCE_FILES
       vol_merge.cpp
      )
set(TEST_VOLUME_SOURCE_FILES
       vol_gtest.cpp
      )
set(PERF_TEST_VOLUME_SOURCE_FILES
       vol_perf_gtest.cpp
      )
set(BTREE_CHECKER_SOURCE_FILES
       btree_checker.cpp
      )

add_executable(test_merge
                  ${TEST_MERGE_SOURCE_FILES}
              )
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
    target_link_libraries(check_btree homeblks ${COMMON_LIB_DEPS})
    target_link_libraries(perf_test_volume homeblks ${COMMON_LIB_DEPS})
    TARGET_LINK_LIBRARIES(perf_test_volume ${Boost_LIBRARIES})
    TARGET_LINK_LIBRARIES(check_btree ${Boost_LIBRARIES})
endif ()

target_link_libraries(test_merge homeblks ${COMMON_LIB_DEPS})

target_link_libraries(test_volume homeblks ${COMMON_LIB_DEPS})

FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)
TARGET_LINK_LIBRARIES(test_volume ${Boost_LIBRARIES})

add_test(NAME TestVol COMMAND test_volume)
add_test(NAME TestVolRecovery COMMAND ${CMAKE_BINARY_DIR}/bin/scripts/vol_test.py --test_suits=recovery --dirpath=${CMAKE_BINARY_DIR}/bin/)
SET_TESTS_PROPERTIES(TestVolRecovery PROPERTIES DEPENDS TestVol)

#add_test(NAME PerfTestVol COMMAND perf_test_volume)
#add_test(NAME RecoveryVol COMMAND python vol_test.py)
#add_test(NAME CheckBtree COMMAND check_btree)


