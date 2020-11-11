include_directories (BEFORE ../)

set(INDXMGR_SOURCE_FILES
    blk_read_tracker.cpp
    indx_mgr.cpp
    snap_mgr.cpp
    )
add_library(indx_mgr OBJECT ${INDXMGR_SOURCE_FILES})

