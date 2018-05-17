set(BLKALLOC_SOURCE
  #dynamic_blk_allocator.cpp
        fixed_blk_allocator.cpp
        varsize_blk_allocator.cpp
       )
add_library(hs_blkalloc OBJECT ${BLKALLOC_SOURCE})

if(CMAKE_BUILD_TYPE STREQUAL Debug)
  set(TEST_BLKALLOC_SOURCE_FILES
          test_blkalloc.cpp
          )
  add_executable(test_blkalloc
                    ${TEST_BLKALLOC_SOURCE_FILES}
                    $<TARGET_OBJECTS:hs_blkalloc>
                  )
  target_link_libraries(test_blkalloc ${COMMON_LIB_DEPS})
  add_test(NAME BlkAlloc COMMAND test_blkalloc)
else()
  message(WARNING "BlkAlloc test disabled in Release build! Fails to build.")
endif()
