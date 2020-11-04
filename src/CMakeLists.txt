include (CTest)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads)
find_library(LIB_AIO aio)
find_library(LIB_ISAL isal)

set(COMMON_LIB_DEPS
    ${CONAN_LIBS}
    ${LIB_AIO}
    #${LIB_DOUBLE_CONVERSION}
    #${LIB_ISAL}
    )

include_directories (BEFORE .)
include_directories (BEFORE ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(engine)
add_subdirectory(homeblks)
add_subdirectory(homelogstore)
add_subdirectory(test_scripts)

set(HOMESTORE_OBJECTS
    $<TARGET_OBJECTS:hs_engine>
    $<TARGET_OBJECTS:hs_common>
    $<TARGET_OBJECTS:hs_device>
    $<TARGET_OBJECTS:hs_blkalloc>
    $<TARGET_OBJECTS:hs_logdev>
    $<TARGET_OBJECTS:hs_metablk>
    $<TARGET_OBJECTS:indx_mgr>
    )
add_library(homestore STATIC ${HOMESTORE_OBJECTS})
#target_link_libraries(homestore ${COMMON_LIB_DEPS})

add_library(homeblks STATIC
            ${HOMESTORE_OBJECTS}
            $<TARGET_OBJECTS:hs_homeblks>
            $<TARGET_OBJECTS:hs_volume>)
#target_link_libraries(homeblks ${COMMON_LIB_DEPS})
