cmake_minimum_required (VERSION 3.11)

add_library(service OBJECT)
target_sources(service PRIVATE
            repl_service.cpp
            home_repl_backend.cpp
        )
target_link_libraries(service
            nuraft::nuraft
            sisl::sisl
            homestore::homestore
            nuraft_mesg::nuraft_mesg
        )
target_compile_features(service PUBLIC cxx_std_17)

include ("${sisl_INCLUDE_DIRS}/../cmake/settings_gen.cmake")
settings_gen_cpp($<TARGET_FILE:flatbuffers::flatc> ${CMAKE_CURRENT_BINARY_DIR} service ../repl_config.fbs)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
