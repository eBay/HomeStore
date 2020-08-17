include_directories (BEFORE ..)
set(DEVICE_SOURCE
        physical_dev.cpp
        device_manager.cpp
       )
add_library(hs_device OBJECT ${DEVICE_SOURCE})

set(TEST_VDEV_SOURCES tests/test_vdev.cpp)
add_executable(test_virtual_device ${TEST_VDEV_SOURCES})
target_link_libraries(test_virtual_device hs_device homeblks ${CONAN_LIBS})
if (NOT "${CONAN_TEST_TARGET}" STREQUAL "off")
    add_test(NAME TestVDev COMMAND test_virtual_device)
endif()

message(WARNING "PhysicalDevice test disabled due to interface change.")
# XXX: Currently out of date with DeviceManager interface
#set(TEST_PHYSDEV_SOURCE_FILES
#        test_physdev.cpp)
#add_executable(test_physdev
#                  ${TEST_PHYSDEV_SOURCE_FILES}
#                  $<TARGET_OBJECTS:hs_device>
#                  $<TARGET_OBJECTS:hs_endpoint>
#                )
#target_link_libraries(test_physdev ${COMMON_LIB_DEPS})
#add_test(NAME PhysicalDev COMMAND test_physdev)

message(WARNING "VirtualDevice test disabled due to interface change.")
# XXX: Currently out of data with VirtualDev interface
#set(TEST_VIRTUALDEV_SOURCE_FILES
#        test_virtualdev.cpp)
#add_executable(test_virtualdev
#                  ${TEST_VIRTUALDEV_SOURCE_FILES}
#                  $<TARGET_OBJECTS:hs_device>
#                  $<TARGET_OBJECTS:hs_endpoint>
#                )
#target_link_libraries(test_virtualdev ${COMMON_LIB_DEPS})
#add_test(NAME VirtualDev COMMAND test_virtualdev)
