
set(TEST_MAP_SOURCE_FILES
       map_gtest.cpp
      )
add_executable(test_mapping
                  ${TEST_MAP_SOURCE_FILES}
                )
target_link_libraries(test_mapping homeblks ${COMMON_LIB_DEPS})

FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)
TARGET_LINK_LIBRARIES(test_mapping ${Boost_LIBRARIES})
#add_test(NAME MappingTest COMMAND test_mapping)