cmake_minimum_required(VERSION 3.11)

include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

add_library(hs_blkstore OBJECT ${BLKSTORE_SOURCE})
target_sources(hs_blkstore PRIVATE blkbuffer.cpp)
target_link_libraries(hs_blkstore ${COMMON_DEPS})

message(INFO "BlkStore test disabled due to interface change.")
# XXX: Out of date with BlkStore interface
#set(TEST_BLKSTORE_SOURCE_FILES
#        test_blkstore.cpp
#        )
#add_executable(test_store
#                  ${TEST_BLKSTORE_SOURCE_FILES}
#                )
#target_link_libraries(test_store ${COMMON_LIB_DEPS})
#add_test(NAME BlkStore COMMAND test_store)
