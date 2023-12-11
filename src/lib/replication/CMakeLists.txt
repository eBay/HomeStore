include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

include_directories (BEFORE ..)
include_directories (BEFORE .)

list(APPEND SCHEMA_FLAGS "--scoped-enums" "--gen-name-strings" "--cpp-std=c++17" "--cpp-static-reflection" "--reflect-names")

flatbuffers_generate_headers(
    TARGET hs_replication_fb 
    SCHEMAS push_data_rpc.fbs
    FLAGS ${SCHEMA_FLAGS}
)

add_library(hs_replication OBJECT)
target_sources(hs_replication PRIVATE
    service/generic_repl_svc.cpp
    service/raft_repl_service.cpp
    repl_dev/solo_repl_dev.cpp
    repl_dev/common.cpp
    repl_dev/raft_repl_dev.cpp
    repl_dev/raft_state_machine.cpp
    log_store/repl_log_store.cpp
    log_store/home_raft_log_store.cpp
    )
target_link_libraries(hs_replication PRIVATE ${COMMON_DEPS} hs_common hs_replication_fb)

#set(FLATBUFFERS_FLATC_EXECUTABLE ${flatbuffers_LIB_DIRS}/../bin/flatc)
#flatbuffer_gen_cpp(${FLATBUFFERS_FLATC_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_replication rpc/push_data_rpc.fbs rpc/fetch_data_rpc.fbs)

