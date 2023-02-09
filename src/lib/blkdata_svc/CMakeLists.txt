include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_datasvc OBJECT)
target_sources(hs_datasvc PRIVATE
    blkdata_service.cpp
    blk_read_tracker.cpp
    )
target_link_libraries(hs_datasvc ${COMMON_DEPS})
