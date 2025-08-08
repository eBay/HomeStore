cmake_minimum_required(VERSION 3.11)

include_directories (BEFORE ../)

add_subdirectory(cow_btree)
add_subdirectory(mem_btree)

set(INDEX_SOURCE_FILES
    index_service.cpp
    btree_base.cpp
    index_cp.cpp
    )
add_library(hs_index OBJECT ${INDEX_SOURCE_FILES})
target_link_libraries(hs_index ${COMMON_DEPS})
#add_dependencies(hs_index hs_cow_btree hs_mem_btree)
