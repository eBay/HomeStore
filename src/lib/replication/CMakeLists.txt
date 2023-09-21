include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

include_directories (BEFORE ..)
include_directories (BEFORE .)

add_library(hs_replication OBJECT)
target_sources(hs_replication PRIVATE
    service/repl_service_impl.cpp
    repl_dev/solo_repl_dev.cpp
    )
target_link_libraries(hs_replication ${COMMON_DEPS})
