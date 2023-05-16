include_directories (BEFORE ..)

add_subdirectory(volume)

find_package(flatbuffers REQUIRED)

add_library(hs_homeblks OBJECT)
target_sources(hs_homeblks PRIVATE
      home_blks.cpp
      homeblks_http_server.cpp
    )
target_link_libraries(hs_homeblks ${COMMON_DEPS})

settings_gen_cpp($<TARGET_FILE:flatbuffers::flatc> ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_homeblks homeblks_config.fbs)
