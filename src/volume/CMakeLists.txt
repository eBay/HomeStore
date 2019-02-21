set(VOLUME_SOURCE_FILES
       volume.cpp
       home_blks.cpp
      )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

set(TEST_VOLUME_SOURCE_FILES
       vol_gtest.cpp
      )
set(PERF_TEST_VOLUME_SOURCE_FILES
       vol_perf_gtest.cpp
      )

add_executable(test_volume
                  ${TEST_VOLUME_SOURCE_FILES}
                )
add_executable(perf_test_volume
                  ${PERF_TEST_VOLUME_SOURCE_FILES}
                )
target_link_libraries(test_volume homeblks ${COMMON_LIB_DEPS})
target_link_libraries(perf_test_volume homeblks ${COMMON_LIB_DEPS})

FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)
TARGET_LINK_LIBRARIES(test_volume ${Boost_LIBRARIES})
TARGET_LINK_LIBRARIES(perf_test_volume ${Boost_LIBRARIES})

file(COPY vol_test.py DESTINATION ${CMAKE_BINARY_DIR}/bin)
add_test(NAME TestVol COMMAND test_volume)
#add_test(NAME PerfTestVol COMMAND perf_test_volume)
#add_test(NAME RecoveryVol COMMAND python vol_test.py)


