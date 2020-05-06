# Coverage doesn't like binaries that don't run...
if (NOT ${CONAN_BUILD_COVERAGE})
    set(TEST_MAP_SOURCE_FILES
           map_gtest.cpp
          )
    add_executable(test_mapping
                      ${TEST_MAP_SOURCE_FILES}
                    )
    target_link_libraries(test_mapping ${CONAN_LIBS} homeblks)
    #add_test(NAME MappingTest COMMAND test_mapping)
endif ()
