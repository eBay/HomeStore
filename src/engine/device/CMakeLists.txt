include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ..)

add_library(hs_device OBJECT)
target_sources(hs_device PRIVATE
      physical_dev.cpp
      device_manager.cpp
      virtual_dev.cpp
      journal_vdev.cpp
    )
target_link_libraries(hs_device ${COMMON_DEPS})

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})
can_build_nonio_tests(non_io_tests)
if (${non_io_tests})
    set(TEST_VDEV_SOURCES tests/test_vdev.cpp)
    add_executable(test_virtual_device ${TEST_VDEV_SOURCES})
    target_link_libraries(test_virtual_device hs_device homestore ${COMMON_TEST_DEPS} GTest::gmock)
    add_test(NAME TestVDev COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_virtual_device)
endif()
