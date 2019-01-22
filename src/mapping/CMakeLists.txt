set(MAPPING_SOURCE_FILES
       map_gtest.cpp
      )
add_library(hs_mapping OBJECT ${MAPPING_SOURCE_FILES})

set(TEST_MAPPING_SOURCE_FILES
       map_gtest.cpp
      )
add_executable(test_mapping
                  ${TEST_MAPPING_SOURCE_FILES}
                )
target_link_libraries(test_mapping homestore ${COMMON_LIB_DEPS})

FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)
TARGET_LINK_LIBRARIES(test_mapping ${Boost_LIBRARIES})

#add_test(NAME TestVol COMMAND test_volume)


