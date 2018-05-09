set (CPP_FLAGS "-fPIC -faligned-new")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS}") 

find_package(Boost 1.64 REQUIRED)
find_package (Threads REQUIRED)

include_directories (BEFORE .)

set(TEST_VOLUME_SOURCE_FILES
        blkalloc/varsize_blk_allocator.cpp

        cache/cache.cpp
	cache/eviction.hpp

        device/device_manager.cpp
        device/physical_dev.cpp
        device/virtual_dev.hpp

        iomgr/drive_endpoint.cpp
        iomgr/iomgr.cpp
	iomgr/iomgr.hpp

        volume/vol_test.cpp
        volume/volume.cpp)


add_executable(test_volume ${TEST_VOLUME_SOURCE_FILES})
target_link_libraries(test_volume
                      ${CONAN_LIBS} 
                      double-conversion
                      aio
                      ${CMAKE_DL_LIBS}
                      ${CMAKE_THREAD_LIBS_INIT})
