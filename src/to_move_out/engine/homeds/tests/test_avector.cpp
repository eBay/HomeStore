//
// Created by Kadayam, Hari on 30/11/17.
//

#include <iostream>
#include <sisl/options/options.h>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include "homeds/array/sparse_vector.hpp"
#include <sisl/utility/thread_buffer.hpp>

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
RCU_REGISTER_INIT

void func(const homeds::sparse_vector< int >& cvec) {
    LOGINFO("vec.at(1) = {}", cvec.at(1));
    try {
        LOGINFO("vec.at(7) = {}", cvec.at(7));
    } catch (std::out_of_range& e) { LOGINFO("vec.at(7) caught: {}", e.what()); }
    LOGINFO("vec[6] = {} Vector size = {}", cvec[6], cvec.size());
}

SISL_OPTIONS_ENABLE(logging)
int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging)
    sisl::logging::SetLogger("test_avector");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    homeds::sparse_vector< int > vec;
    vec.reserve(10);

    vec.push_back(1);
    vec.push_back(2);
    LOGINFO("Vector size = {}", vec.size());
    vec[5] = 6;
    vec.at(6) = 7;
    LOGINFO("vec[5] = {} vec.at(6) = {} Vector size = {}", vec[5], vec.at(6), vec.size());
    func(vec);
}
