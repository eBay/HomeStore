include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_new_device OBJECT)
target_sources(hs_new_device PRIVATE
      physical_dev.cpp
      new_device.cpp
      virtual_dev.cpp
      chunk.cpp
    )
target_link_libraries(hs_new_device hs_common ${COMMON_DEPS})
