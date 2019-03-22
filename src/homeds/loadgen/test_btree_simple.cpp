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
#include "spec/key_spec.hpp"
#include "spec/value_spec.hpp"
#include "spec/store_spec.hpp"
#include "loadgen.hpp"
#include "keyset.hpp"
#include "loadgen_common.hpp"
#include "device/virtual_dev.hpp"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc, iomgr)
THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define simple_mem_btree_store_t MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 8192 >

void simple_insert_test() {
    KVGenerator<SimpleNumberKey, FixedBytesValue<64>, simple_mem_btree_store_t > kvg;

    // Step 1: First create a store and register to kv generator
    kvg.register_store(std::make_shared<simple_mem_btree_store_t>());

    // Step 2: Create a keyset of specific pattern and register to the kv generator
    auto seq_keyset = std::make_shared<KeySet<SimpleNumberKey>>(KeyPattern::SEQUENTIAL);
    kvg.register_keyset(seq_keyset);

    // Start the test.
    kvg.preload(seq_keyset, ValuePattern::RANDOM_BYTES, 500);

    // Insert new 100 documents
    for (auto i = 0u; i < 100; i++) {
        kvg.insert_new(seq_keyset, ValuePattern::RANDOM_BYTES);
    }

#if 0
    // Insert first 100 documents again and check for failure
    for (auto i = 0u; i < 100; i++) {
        kvg.insert_existing(seq_keyset, ValuePattern::RANDOM_BYTES, false /* expected_success */);
    }
#endif

    // Get first 100 documents again and check for failure
    for (auto i = 0u; i < 100; i++) {
        kvg.get(seq_keyset, KeyPattern::SEQUENTIAL);
    }

    // Try reading nonexisting document
    for (auto i = 0u; i < 100; i++) {
        kvg.get_non_existing(seq_keyset, false /* expected_success */);
    }

    kvg.wait_for_test();
}

SDS_OPTIONS_ENABLE(logging)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger("test_btree_simple");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    simple_insert_test();
    //setup_devices(2);
    //testing::InitGoogleTest(&argc, argv);
    //return RUN_ALL_TESTS();
}