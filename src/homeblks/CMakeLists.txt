include_directories (BEFORE ..)

add_subdirectory(volume)

find_package(FlatBuffers REQUIRED)

add_library(hs_homeblks OBJECT)
target_sources(hs_homeblks PRIVATE
      home_blks.cpp
      homeblks_http_server.cpp
    )
target_link_libraries(hs_homeblks ${COMMON_DEPS})

set(FLATBUFFERS_FLATC_EXECUTABLE ${flatbuffers_LIB_DIRS}/../bin/flatc)
settings_gen_cpp(${FLATBUFFERS_FLATC_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/generated/ hs_homeblks homeblks_config.fbs)
