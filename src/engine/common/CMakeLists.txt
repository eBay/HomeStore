cmake_minimum_required(VERSION 3.11)

include_directories (BEFORE ..)

find_package(FlatBuffers REQUIRED)

add_library(hs_common OBJECT)
target_sources(hs_common PRIVATE
      error.cpp
      homestore_status_mgr.cpp
      homestore_utils.cpp
    )
target_link_libraries(hs_common ${COMMON_DEPS})

set(FLATBUFFERS_FLATC_EXECUTABLE ${flatbuffers_LIB_DIRS}/../bin/flatc)
settings_gen_cpp(${FLATBUFFERS_FLATC_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_common homestore_config.fbs)
