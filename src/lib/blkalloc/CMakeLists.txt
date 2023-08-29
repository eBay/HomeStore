cmake_minimum_required(VERSION 3.13)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_blkalloc OBJECT)
target_sources(hs_blkalloc PRIVATE
        blk.cpp
        blk_allocator.cpp
        fixed_blk_allocator.cpp
        varsize_blk_allocator.cpp
        blk_cache_queue.cpp
        append_blk_allocator.cpp
        #blkalloc_cp.cpp
      )
target_link_libraries(hs_blkalloc ${COMMON_DEPS})
add_dependencies(hs_blkalloc hs_common)
