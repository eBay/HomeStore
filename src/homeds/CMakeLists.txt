message(WARNING "BTree test disabled due to interface change.")
# XXX: Out of date with BTree interface
#set(TEST_BTREE_SOURCE_FILES
#        tests/test_btree.cpp
#        )
#add_executable(test_btree
#                  ${TEST_BTREE_SOURCE_FILES}
#                )
#target_link_libraries(test_btree ${COMMON_LIB_DEPS})

set(TEST_BTREE_CRUD_SOURCE_FILES
        tests/test_btree_crud.cpp
        )
add_executable(test_btree_crud
                  ${TEST_BTREE_CRUD_SOURCE_FILES}
                )
target_link_libraries(test_btree_crud ${COMMON_LIB_DEPS})

set(TEST_HASH_SOURCE_FILES
        tests/test_hashset.cpp
        )
add_executable(test_hash
                  ${TEST_HASH_SOURCE_FILES}
                )
target_link_libraries(test_hash ${COMMON_LIB_DEPS})

set(TEST_COMPOSITE_SOURCE_FILES
        tests/test_composite_allocator.cpp
        )
add_executable(test_composite_allocator
                  ${TEST_COMPOSITE_SOURCE_FILES}
                )
target_link_libraries(test_composite_allocator ${COMMON_LIB_DEPS})

set(TEST_OBJALLOCATOR_SOURCE_FILES
        tests/test_obj_allocator.cpp
        )
add_executable(test_obj_allocator
                  ${TEST_OBJALLOCATOR_SOURCE_FILES}
                )
target_link_libraries(test_obj_allocator ${COMMON_LIB_DEPS})

set(TEST_BITWORD_SOURCE_FILES
        tests/test_bitword.cpp
        )
add_executable(test_bitword
                  ${TEST_BITWORD_SOURCE_FILES}
                )
target_link_libraries(test_bitword ${COMMON_LIB_DEPS})

set(TEST_BITSET_SOURCE_FILES
        tests/test_bitset.cpp
        )
add_executable(test_bitset
                  ${TEST_BITSET_SOURCE_FILES}
                )
target_link_libraries(test_bitset ${COMMON_LIB_DEPS})

set(TEST_AVECTOR_SOURCE_FILES
        tests/test_avector.cpp
        )
add_executable(test_avector
                  ${TEST_AVECTOR_SOURCE_FILES}
                )
target_link_libraries(test_avector ${COMMON_LIB_DEPS} folly)
