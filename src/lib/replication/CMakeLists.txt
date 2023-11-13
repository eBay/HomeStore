include (${CMAKE_SOURCE_DIR}/cmake/test_mode.cmake)

include_directories (BEFORE ..)
include_directories (BEFORE .)

flatbuffers_generate_headers(
    TARGET hs_replication_fb 
    SCHEMAS rpc/push_data_rpc.fbs
    FLAGS "--cpp"
)
#build_flatbuffers(
#    rpc/push_data_rpc.fbs
#    ""
#    hs_replication_fb
#    ""
#    "${CMAKE_CURRENT_BINARY_DIR}/generated/"
#    ""
#    ""
#    )
#target_link_libraries(hs_replication_fb ${COMMON_DEPS})

add_library(hs_replication OBJECT)
target_sources(hs_replication PRIVATE
    service/generic_repl_svc.cpp
    repl_dev/solo_repl_dev.cpp
    repl_dev/common.cpp
    )
target_link_libraries(hs_replication PRIVATE ${COMMON_DEPS} hs_replication_fb)

#set(FLATBUFFERS_FLATC_EXECUTABLE ${flatbuffers_LIB_DIRS}/../bin/flatc)
#flatbuffer_gen_cpp(${FLATBUFFERS_FLATC_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_replication rpc/push_data_rpc.fbs rpc/fetch_data_rpc.fbs)

