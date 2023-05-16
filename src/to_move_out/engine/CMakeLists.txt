cmake_minimum_required(VERSION 3.11)

add_subdirectory(blkalloc)
add_subdirectory(blkstore)
add_subdirectory(cache)
add_subdirectory(device)
add_subdirectory(homeds)
add_subdirectory(common)
add_subdirectory(meta)
add_subdirectory(index)

include_directories (BEFORE .)
include_directories (BEFORE ${CMAKE_CURRENT_BINARY_DIR})

add_library(hs_engine OBJECT)
target_sources(hs_engine PRIVATE
      $<TARGET_OBJECTS:hs_common>
      $<TARGET_OBJECTS:hs_device>
      $<TARGET_OBJECTS:hs_blkstore>
      $<TARGET_OBJECTS:hs_blkalloc>
      $<TARGET_OBJECTS:hs_metablk>
      $<TARGET_OBJECTS:indx_mgr>
      homestore_base.cpp
    )
target_link_libraries(hs_engine ${COMMON_DEPS})
