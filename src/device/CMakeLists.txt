set(DEVICE_SOURCE
        physical_dev.cpp
        device_manager.cpp
       )
add_library(hs_device OBJECT ${DEVICE_SOURCE})

set(TEST_DEVICEMGR_SOURCE_FILES
        test_blkdev.cpp
        )
add_executable(test_devmgr
                  ${TEST_DEVICEMGR_SOURCE_FILES}
                  $<TARGET_OBJECTS:hs_device>
                  $<TARGET_OBJECTS:hs_endpoint>
                )
target_link_libraries(test_devmgr ${COMMON_LIB_DEPS} ${CONAN_LIBS_FOLLY})

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
