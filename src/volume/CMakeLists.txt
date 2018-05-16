set(VOLUME_SOURCE_FILES
       volume.cpp
      )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

set(TEST_VOLUME_SOURCE_FILES
       vol_test.cpp
      )
add_executable(test_volume
                  ${TEST_VOLUME_SOURCE_FILES}
                )
target_link_libraries(test_volume homestore ${COMMON_LIB_DEPS})
