include_directories (BEFORE ..)

find_package(FlatBuffers REQUIRED)

set(COMMON_SOURCE_FILES
    error.cpp
    homestore_status_mgr.cpp
    homestore_utils.cpp
    )
add_library(hs_common OBJECT ${COMMON_SOURCE_FILES})
target_link_libraries(hs_common ${COMMON_DEPS})

settings_gen_cpp($<TARGET_FILE:flatbuffers::flatc> ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_common homestore_config.fbs)
