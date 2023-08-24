cmake_minimum_required (VERSION 3.11)

add_library(storage_engine OBJECT)
target_sources(storage_engine PRIVATE
            home_storage_engine.cpp
        )
target_link_libraries(storage_engine
            homestore::homestore
            sisl::sisl
        )
target_compile_features(storage_engine PUBLIC cxx_std_17)
