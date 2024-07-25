cmake_minimum_required(VERSION 3.13)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_logdev OBJECT)
target_sources(hs_logdev PRIVATE
      log_dev.cpp
      log_group.cpp
      log_stream.cpp
      log_store.cpp
      log_store_service.cpp
    )
target_link_libraries(hs_logdev ${COMMON_DEPS})
