cmake_minimum_required(VERSION 3.7)
project(omds)

set(CMAKE_CXX_STANDARD 14)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../../target/${CMAKE_BUILD_TYPE}/${OS_TYPE})
#set(LIB_ROOT_DIR ${CMAKE_SOURCE_DIR}/deps_prefix/${OS_TYPE}/lib)
#set(INCLUDE_ROOT_DIR ${CMAKE_SOURCE_DIR}/deps_prefix/${OS_TYPE}/include)

include(${CMAKE_SOURCE_DIR}/CMakeScripts/utils.cmake)
include_directories(..)
#include_directories(${INCLUDE_ROOT_DIR})
#link_directories(${LIB_ROOT_DIR})

set(BTREE_SOURCE_FILES
        array/flexarray.hpp
        bitmap/Bitword.hpp
        btree/abstract_node.hpp
        btree/btree.hpp
        btree/btree_internal.h
        btree/mem_btree.hpp
        btree/simple_node.hpp
        btree/varlen_node.hpp
        hash/intrusive_hashset.hpp
        memory/generic_freelist_allocator.hpp
        memory/chunk_allocator.hpp
        memory/sys_allocator.hpp
        memory/composite_allocator.hpp
        memory/mem_allocator.hpp
        memory/tagged_ptr.hpp
        utility/atomic_counter.hpp
        thread/lock.hpp)
set(TEST_BTREE_SOURCE_FILES
        ${BTREE_SOURCE_FILES}
        tests/test_btree.cpp)
add_executable(test_btree ${TEST_BTREE_SOURCE_FILES})

set(TEST_BTREE_CRUD_SOURCE_FILES
        ${BTREE_SOURCE_FILES}
        tests/test_btree_crud.cpp)
add_executable(test_btree_crud ${TEST_BTREE_CRUD_SOURCE_FILES})
#AddStaticLibraries(test_btree_crud ${LIB_ROOT_DIR}
#                                    gtest)
target_link_libraries(test_btree_crud gtest)

set(TEST_HASH_SOURCE_FILES
        hash/intrusive_hashset.hpp
        tests/test_hashset.cpp)
add_executable(test_hash ${TEST_HASH_SOURCE_FILES})
target_link_libraries(test_hash folly tcmalloc farmhash benchmark)

set(TEST_COMPOSITE_SOURCE_FILES
        memory/mem_allocator.hpp
        memory/chunk_allocator.hpp
        memory/sys_allocator.hpp
        memory/composite_allocator.hpp
        memory/generic_freelist_allocator.hpp
        memory/freelist_allocator.hpp
        tests/test_composite_allocator.cpp)
add_executable(test_composite_allocator ${TEST_COMPOSITE_SOURCE_FILES})
target_link_libraries(test_composite_allocator folly glog tcmalloc benchmark)

set(TEST_OBJALLOCATOR_SOURCE_FILES
        memory/obj_allocator.hpp
        memory/freelist_allocator.hpp
        tests/test_obj_allocator.cpp)
add_executable(test_obj_allocator ${TEST_OBJALLOCATOR_SOURCE_FILES})
target_link_libraries(test_obj_allocator folly glog tcmalloc)

set(TEST_BITWORD_SOURCE_FILES
        bitmap/Bitword.hpp
        tests/test_bitword.cpp)
add_executable(test_bitword ${TEST_BITWORD_SOURCE_FILES})

set(TEST_BITSET_SOURCE_FILES
        bitmap/bitset.hpp
        utility/useful_defs.hpp
        tests/test_bitset.cpp)
add_executable(test_bitset ${TEST_BITSET_SOURCE_FILES})

set(TEST_AVECTOR_SOURCE_FILES
        array/avector.hpp
        tests/test_avector.cpp)
add_executable(test_avector ${TEST_AVECTOR_SOURCE_FILES})