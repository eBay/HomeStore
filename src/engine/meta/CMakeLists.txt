include_directories (BEFORE ../)

set(METABLK_SOURCE_FILES
    meta_blks_mgr.cpp
      )
add_library(hs_metablk OBJECT ${METABLK_SOURCE_FILES})

if (NOT "${CONAN_TEST_TARGET}" STREQUAL "off")
    set(TEST_METABLK_SOURCE_FILES
      test_meta_blk_mgr.cpp
      )

    add_executable(test_meta_blk_mgr
                  ${TEST_METABLK_SOURCE_FILES}
                )

    target_link_libraries(test_meta_blk_mgr homeblks ${CONAN_LIBS})
    add_test(NAME TestMetaBlkMgr COMMAND ${CMAKE_SOURCE_DIR}/test_wrap.sh ${CMAKE_BINARY_DIR}/bin/test_meta_blk_mgr)
endif()
