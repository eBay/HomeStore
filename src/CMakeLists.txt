set (CPP_FLAGS "-fPIC -faligned-new")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body -Wno-array-bounds")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS}") 

find_package(Boost 1.64 REQUIRED)
find_package (Threads REQUIRED)

include_directories (BEFORE .)

set(HOMESTORE_SRC
        blkalloc/varsize_blk_allocator.cpp

        cache/cache.cpp
	cache/eviction.hpp

        device/device_manager.cpp
        device/physical_dev.cpp
        device/virtual_dev.hpp

        iomgr/drive_endpoint.cpp
        iomgr/iomgr.cpp
	iomgr/iomgr.hpp

        volume/volume.cpp)

add_library(homestore ${HOMESTORE_SRC})
target_link_libraries(homestore
                      ${CONAN_LIBS} 
                      aio
                      double-conversion
                      ${CMAKE_DL_LIBS}
                      ${CMAKE_THREAD_LIBS_INIT})

add_executable(test_volume volume/vol_test.cpp)
target_link_libraries(test_volume homestore)
