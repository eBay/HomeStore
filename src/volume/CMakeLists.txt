set(VOLUME_SOURCE_FILES
       volume.cpp
       home_blks.cpp
      )
add_library(hs_volume OBJECT ${VOLUME_SOURCE_FILES})

set(TEST_VOLUME_SOURCE_FILES
       vol_gtest.cpp
      )
add_executable(test_volume
                  ${TEST_VOLUME_SOURCE_FILES}
                )
target_link_libraries(test_volume homestore ${COMMON_LIB_DEPS})

FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)
TARGET_LINK_LIBRARIES(test_volume ${Boost_LIBRARIES})


add_subdirectory(test)

file(COPY vol_test.py DESTINATION ${CMAKE_BINARY_DIR}/bin)
add_test(NAME TestVol COMMAND test_volume)

