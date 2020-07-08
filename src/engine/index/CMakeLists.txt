include_directories (BEFORE ../)

set(INDXMGR_SOURCE_FILES
    indx_mgr.cpp
    snap_mgr.cpp
   )
add_library(indx_mgr OBJECT ${INDXMGR_SOURCE_FILES})

