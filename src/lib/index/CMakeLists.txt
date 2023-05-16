cmake_minimum_required(VERSION 3.11)

include_directories (BEFORE ../)

set(INDEX_SOURCE_FILES
    index_service.cpp
    wb_cache.cpp
    )
add_library(hs_index OBJECT ${INDEX_SOURCE_FILES})
target_link_libraries(hs_index ${COMMON_DEPS})
