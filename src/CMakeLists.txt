set (CPP_FLAGS "-faligned-new -Dlinux")
set (CPP_WARNINGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable -Wno-empty-body -Wno-array-bounds -Wno-cast-function-type -Wno-maybe-uninitialized -Wno-deprecated-copy -Wno-attributes")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CPP_FLAGS} ${CPP_WARNINGS} -DBOOST_ALLOW_DEPRECATED_HEADERS -DRCU_SIGNAL")

if ("$ENV{HOMESTORE_BUILD_TAG}" STREQUAL "")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPACKAGE_VERSION=\\\"${CONAN_PACKAGE_VERSION}\\\"")
else()
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DPACKAGE_VERSION=\\\"${CONAN_PACKAGE_VERSION}-$ENV{HOMESTORE_BUILD_TAG}\\\"")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message("Debug build")
    add_compile_options(-D_DEBUG=1 -O0 -DDEBUG_RCU -D_PRERELEASE=1)
else()
    message("Release build")
    add_compile_options(-DNDEBUG=1 -O2 -D_PRERELEASE=1)
endif()


include (CTest)
find_package (Threads REQUIRED)
find_library(LIB_AIO aio)
find_library(LIB_DOUBLE_CONVERSION double-conversion)
find_library(LIB_ISAL isal)

set(COMMON_LIB_DEPS
      ${CONAN_LIBS}
      ${LIB_DOUBLE_CONVERSION}
      ${LIB_AIO}
      ${LIB_ISAL}
    )

include_directories (BEFORE .)

#add_subdirectory(blkalloc)
#add_subdirectory(blkstore)
#add_subdirectory(cache)
#add_subdirectory(device)
#add_subdirectory(endpoint)
#add_subdirectory(journal)
#add_subdirectory(homeds)
#add_subdirectory(homeblks)
#add_subdirectory(error)
#add_subdirectory(common)
#add_subdirectory(threadpool)

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
        )
add_library(homestore STATIC ${HOMESTORE_OBJECTS})
target_link_libraries(homestore ${COMMON_LIB_DEPS})

add_library(homeblks STATIC
                 ${HOMESTORE_OBJECTS}
                 $<TARGET_OBJECTS:hs_homeblks>
                 $<TARGET_OBJECTS:hs_volume>)
target_link_libraries(homeblks ${COMMON_LIB_DEPS})
