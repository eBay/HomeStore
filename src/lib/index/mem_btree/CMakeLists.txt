cmake_minimum_required(VERSION 3.11)

include_directories (BEFORE ../)

add_library(hs_mem_btree OBJECT)
target_sources(hs_mem_btree PRIVATE
    mem_btree_store.cpp
    )
target_link_libraries(hs_mem_btree hs_common ${COMMON_DEPS})
#add_library(hs_cow_btree OBJECT ${COW_BTREE_SOURCE_FILES})
