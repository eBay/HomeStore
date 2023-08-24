cmake_minimum_required (VERSION 3.11)

add_library(log_store OBJECT)
target_sources(log_store PRIVATE
            home_raft_log_store.cpp
        )
target_link_libraries(log_store
            homestore::homestore
            nuraft::nuraft
            sisl::sisl
        )
target_compile_features(log_store PUBLIC cxx_std_17)
