include_directories (BEFORE ..)
add_subdirectory(volume)

set(HOMEBLKS_SOURCE_FILES
       home_blks.cpp
      )
add_library(hs_homeblks OBJECT ${HOMEBLKS_SOURCE_FILES})
settings_gen_cpp(${CONAN_BIN_DIRS_FLATBUFFERS} ${CMAKE_CURRENT_SOURCE_DIR}/generated/ hs_homeblks homeblks_config.fbs)
