include_directories (BEFORE ../)

set(METABLK_SOURCE_FILES
    meta_blks_mgr.cpp
      )
add_library(hs_metablk OBJECT ${METABLK_SOURCE_FILES})

set(TEST_METABLK_SOURCE_FILES
     test_meta_blk_mgr.cpp
    )

add_executable(test_meta_blk_mgr
                ${TEST_METABLK_SOURCE_FILES}
              )

target_link_libraries(test_meta_blk_mgr homeblks ${CONAN_LIBS})
if (NOT "${CONAN_TEST_TARGET}" STREQUAL "off")
    add_test(NAME TestMetaBlkMgr COMMAND test_meta_blk_mgr)
endif()
