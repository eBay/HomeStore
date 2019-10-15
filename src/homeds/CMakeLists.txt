message(WARNING "BTree test disabled due to interface change.")
# XXX: Out of date with BTree interface
#set(TEST_BTREE_SOURCE_FILES
#        tests/test_btree.cpp
#        )
#add_executable(test_btree
#                  ${TEST_BTREE_SOURCE_FILES}
#                )
#target_link_libraries(test_btree ${COMMON_LIB_DEPS})
#add_test(NAME BTree COMMAND test_btree)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message("Debug build")
    add_compile_options(-D_DEBUG=1 -O0 -DDEBUG_RCU -D_PRERELEASE=1)
else()
    message("Release build")
    add_compile_options(-DNDEBUG=1 -O3)
endif()

set(TEST_BTREE_CRUD_SOURCE_FILES tests/test_btree_crud.cpp)
add_executable(test_btree_crud ${TEST_BTREE_CRUD_SOURCE_FILES})
target_link_libraries(test_btree_crud  homestore ${COMMON_LIB_DEPS})
add_test(NAME BTreeCRUD COMMAND test_btree_crud)

set(TEST_HASH_SOURCE_FILES tests/test_hashset.cpp)
add_executable(test_hash ${TEST_HASH_SOURCE_FILES})
target_link_libraries(test_hash ${COMMON_LIB_DEPS} iberty)
add_test(NAME Hash COMMAND test_hash)

set(TEST_COMPOSITE_SOURCE_FILES tests/test_composite_allocator.cpp)
add_executable(test_composite_allocator ${TEST_COMPOSITE_SOURCE_FILES})
target_link_libraries(test_composite_allocator ${COMMON_LIB_DEPS} iberty)

set(TEST_OBJALLOCATOR_SOURCE_FILES tests/test_obj_allocator.cpp)
add_executable(test_obj_allocator ${TEST_OBJALLOCATOR_SOURCE_FILES})
target_link_libraries(test_obj_allocator ${COMMON_LIB_DEPS})
add_test(NAME ObjAlloc COMMAND test_obj_allocator)

set(TEST_BITWORD_SOURCE_FILES tests/test_bitword.cpp)
add_executable(test_bitword ${TEST_BITWORD_SOURCE_FILES})
target_link_libraries(test_bitword ${COMMON_LIB_DEPS})
add_test(NAME Bitword COMMAND test_bitword)

set(TEST_BITSET_SOURCE_FILES tests/test_bitset.cpp)
add_executable(test_bitset ${TEST_BITSET_SOURCE_FILES})
target_link_libraries(test_bitset ${COMMON_LIB_DEPS})
add_test(NAME Bitset COMMAND test_bitset)

set(TEST_AVECTOR_SOURCE_FILES tests/test_avector.cpp)
add_executable(test_avector ${TEST_AVECTOR_SOURCE_FILES})
target_link_libraries(test_avector ${COMMON_LIB_DEPS} folly)
add_test(NAME Avector COMMAND test_avector)

set(OBJ_ALLOCATOR_BENCHMARK_FILES tests/obj_allocator_benchmark.cpp)
add_executable(obj_allocator_benchmark ${OBJ_ALLOCATOR_BENCHMARK_FILES})
target_link_libraries(obj_allocator_benchmark ${COMMON_LIB_DEPS})
add_test(NAME ObjAllocatorBenchmark COMMAND obj_allocator_benchmark)

set(TEST_LOAD_FILES 
        tests/loadgen_tests/test_load.cpp
        loadgen/iomgr_executor.cpp
        )
#add_executable(test_load ${TEST_LOAD_FILES})
#target_link_libraries(test_load homestore homeblks ${COMMON_LIB_DEPS})
#add_test(NAME TestLoad COMMAND test_load)

#add_test(NAME TestVolLoadgen COMMAND ${CMAKE_BINARY_DIR}/bin/test_load --gtest_filter=*Volume*)
#SET_TESTS_PROPERTIES(TestVolLoadgen PROPERTIES DEPENDS TestLoad)

#FIND_PACKAGE(Boost COMPONENTS program_options REQUIRED)
#TARGET_LINK_LIBRARIES(test_load ${Boost_LIBRARIES})

set(TEST_IOMGR_EXEC_FILES 
    tests/test_iomgr_executor.cpp
    loadgen/iomgr_executor.cpp
    )
#add_executable(test_iomgr_exec ${TEST_IOMGR_EXEC_FILES})
#target_link_libraries(test_iomgr_exec homestore ${COMMON_LIB_DEPS})
