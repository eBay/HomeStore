include_directories (BEFORE ..)

add_subdirectory(volume)

find_package(FlatBuffers REQUIRED)

set(HOMEBLKS_SOURCE_FILES
    home_blks.cpp
    homeblks_http_server.cpp
    )
add_library(hs_homeblks OBJECT ${HOMEBLKS_SOURCE_FILES})
target_link_libraries(hs_homeblks ${COMMON_DEPS})

settings_gen_cpp($<TARGET_FILE:flatbuffers::flatc> ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_homeblks homeblks_config.fbs)
