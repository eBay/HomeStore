message(WARNING "KvStore test disabled due to interface change.")
# XXX: Out of date with DeviceManager interface
#set(TEST_BTREEKV_SOURCE_FILES
#        test_btree_kvstore.cpp
#        )
#add_executable(test_kvstore
#                  ${TEST_BTREEKV_SOURCE_FILES}
#                )
#target_link_libraries(test_kvstore ${COMMON_LIB_DEPS})
