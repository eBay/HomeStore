set(DEVICE_SOURCE
        physical_dev.cpp
        device_manager.cpp
       )
add_library(hs_device STATIC ${DEVICE_SOURCE})

#set(TEST_DEVICEMGR_SOURCE_FILES
#        test_blkdev.cpp
#        )
#add_executable(test_devmgr ${TEST_DEVICEMGR_SOURCE_FILES})
#target_link_libraries(test_devmgr hs_device ${CONAN_LIBS})
#
#set(TEST_PHYSDEV_SOURCE_FILES
#        test_physdev.cpp)
#add_executable(test_physdev ${TEST_PHYSDEV_SOURCE_FILES})
#target_link_libraries(test_physdev hs_device ${CONAN_LIBS})
#
#set(TEST_VIRTUALDEV_SOURCE_FILES
#        test_virtualdev.cpp)
#add_executable(test_virtualdev ${TEST_VIRTUALDEV_SOURCE_FILES})
#target_link_libraries(test_virtualdev hs_device ${CONAN_LIBS})
