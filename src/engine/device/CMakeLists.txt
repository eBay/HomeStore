include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ..)
set(DEVICE_SOURCE
    blkbuffer.cpp
    physical_dev.cpp
    device_manager.cpp
    )
add_library(hs_device OBJECT ${DEVICE_SOURCE})

can_build_nonio_tests(non_io_tests)
if (${non_io_tests})
    set(TEST_VDEV_SOURCES tests/test_vdev.cpp)
    add_executable(test_virtual_device ${TEST_VDEV_SOURCES})
    target_link_libraries(test_virtual_device hs_device homeblks ${CONAN_LIBS})
    add_test(NAME TestVDev COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_virtual_device)
endif()
