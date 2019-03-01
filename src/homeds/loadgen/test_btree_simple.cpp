//
// Created by Kadayam, Hari on 2/22/19.
//

#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>
#include <utility/obj_life_counter.hpp>

#include "blkstore/blkstore.hpp"
#include <metrics/metrics.hpp>
#include "key_spec.hpp"
#include "keyset.hpp"
#include "loadgen_common.hpp"
#include "device/virtual_dev.hpp"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc)
THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

void keygen_test() {
    KeySet< SimpleNumberKey, KeyPattern::SEQUENTIAL > seq_ks;
    seq_ks.generate_keys(100);

    for (auto i = 0u; i < 200; i++) {
        std::cout << "Batch of 4\n";
        std::cout << "-----------------\n";
        auto keys = seq_ks.get_keys(KeyPattern::SEQUENTIAL, 4);
        for (auto &k : keys) {
            std::cout << k->to_string() << "\n";
        }
    }
}

SDS_OPTIONS_ENABLE(logging)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger("test_btree_simple");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    keygen_test();
    //setup_devices(2);
    //testing::InitGoogleTest(&argc, argv);
    //return RUN_ALL_TESTS();
}