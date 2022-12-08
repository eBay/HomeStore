cmake_minimum_required(VERSION 3.13)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_checkpoint OBJECT)
target_sources(hs_checkpoint PRIVATE
        cp_mgr.cpp
      )
target_link_libraries(hs_checkpoint ${COMMON_DEPS})