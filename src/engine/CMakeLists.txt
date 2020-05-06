
add_subdirectory(blkalloc)
add_subdirectory(blkstore)
add_subdirectory(cache)
add_subdirectory(device)
add_subdirectory(homeds)
add_subdirectory(common)
add_subdirectory(meta)

include_directories (BEFORE .)
include_directories (BEFORE ..)
#include_directories (BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/engine)

set(HOMESTORE_OBJECTS
        $<TARGET_OBJECTS:hs_common>
        $<TARGET_OBJECTS:hs_device>
        $<TARGET_OBJECTS:hs_blkalloc>
        $<TARGET_OBJECTS:hs_metablk>
        )

add_library(hs_engine OBJECT ${HOMESTORE_OBJECTS})
#target_include_directories(hs_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/engine)
