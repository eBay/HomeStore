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
