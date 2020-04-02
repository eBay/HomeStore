include_directories (BEFORE ..)

set(COMMON_SOURCE_FILES
     error.cpp
)
add_library(hs_common OBJECT ${COMMON_SOURCE_FILES})
settings_gen_cpp(${CONAN_BIN_DIRS_FLATBUFFERS} ${CMAKE_CURRENT_SOURCE_DIR}/generated/ hs_common homestore_config.fbs)
