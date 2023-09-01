include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_device OBJECT)
target_sources(hs_device PRIVATE
      physical_dev.cpp
      device_manager.cpp
      virtual_dev.cpp
      journal_vdev.cpp
      chunk.cpp
      round_robin_chunk_selector.cpp
    )
target_link_libraries(hs_device hs_common ${COMMON_DEPS})
