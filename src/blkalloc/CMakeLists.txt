set(BLKALLOC_SOURCE
  #dynamic_blk_allocator.cpp
        fixed_blk_allocator.cpp
        varsize_blk_allocator.cpp
       )
add_library(hs_blkalloc OBJECT ${BLKALLOC_SOURCE})

#set(TEST_BLKALLOC_SOURCE_FILES
#        test_blkalloc.cpp
#        )
#add_executable(test_blkalloc ${TEST_BLKALLOC_SOURCE_FILES})
#target_link_libraries(test_blkalloc hs_blkalloc ${CONAN_LIBS}k)

