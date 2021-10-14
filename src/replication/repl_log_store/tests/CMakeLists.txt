
file(GLOB UNIT_TEST_SRC *.cpp unit_test_main.cpp)


MESSAGE( STATUS "UNIT_TEST_SRC = " ${UNIT_TEST_SRC} )
MESSAGE( STATUS "CMAKE_RUNTIME_OUTPUT_DIRECTORY = " ${CMAKE_RUNTIME_OUTPUT_DIRECTORY} )

include_directories(${CMAKE_HOME_DIRECTORY}/src)

add_executable(unit_test unit_test_main.cpp 
    ${UNIT_TEST_SRC} 
    $<TARGET_OBJECTS:logstore> 
)

 

target_include_directories(unit_test   BEFORE PUBLIC ${CMAKE_HOME_DIRECTORY}/src/tests)
target_link_libraries (unit_test   
    ${CONAN_LIBS}
    ${CONAN_LIBS_GTEST} )

add_test(NAME unit_test_basic COMMAND unit_test --test_type basic --cleanup WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
add_test(NAME unit_test_compact COMMAND unit_test --test_type compact WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
add_test(NAME unit_test_pack COMMAND unit_test --test_type pack WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

set_tests_properties(unit_test_basic unit_test_compact unit_test_pack PROPERTIES TIMEOUT 100 RUN_SERIAL TRUE)
