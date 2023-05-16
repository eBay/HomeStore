file (GLOB LIBRARY_SOURCES *.cc)

if (APPLE)
    set(OPEN_MEMSTREAM open_memstream.c)
    message(STATUS "APPLE: Use custom ${OPEN_MEMSTREAM}")
endif ()

add_library(logstore OBJECT ${LIBRARY_SOURCES} ${OPEN_MEMSTREAM})
