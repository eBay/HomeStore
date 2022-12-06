include(${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)
include_directories (BEFORE ../../include/)
include_directories (BEFORE ..)
include_directories (BEFORE .)

link_directories(${spdk_LIB_DIRS} ${dpdk_LIB_DIRS})

set(METABLK_SOURCE_FILES meta_blk_service.cpp)
add_library(hs_metablk OBJECT ${METABLK_SOURCE_FILES})
target_link_libraries(hs_metablk ${COMMON_DEPS})
