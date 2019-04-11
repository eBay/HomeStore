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

#include <metrics/metrics.hpp>
#include "loadgen.hpp"
#include "keyset.hpp"
#include "loadgen_common.hpp"
#include "spec/btree/btree_key_spec.hpp"
#include "spec/btree/btree_value_spec.hpp"
#include "spec/btree/btree_store_spec.hpp"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc, iomgr)
THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define simple_mem_btree_store_t MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 8192 >

void simple_insert_test() {
    KVGenerator<SimpleNumberKey, FixedBytesValue<64>, simple_mem_btree_store_t > kvg;

    // First create a store and register to kv generator
    kvg.register_store(std::make_shared<simple_mem_btree_store_t>());

    // Start the test by preloading some entries randomly.
    kvg.preload(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, 500u);

    kvg.run_parallel([&]() {
        // Insert new 100 documents
        for (auto i = 0u; i < 100; i++) {
            kvg.insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES);
        }
    });

    kvg.run_parallel([&]() {
        // update existing first 100 documents
        for (auto i = 0u; i < 100; i++) {
            kvg.update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES,false);
        }
    });

//    kvg.reset_pattern(KeyPattern::SEQUENTIAL,0);
    kvg.run_parallel([&](){
        
        // Get first 100 documents again and check for failure
        for (auto i = 0u; i < 100; i++) {
            kvg.get(KeyPattern::SEQUENTIAL, false /* exclusive_access */);
        }

        // Try reading nonexisting document
        for (auto i = 0u; i < 100; i++) {
            kvg.get_non_existing(false /* expected_success */);
        }
    });

//    kvg.reset_pattern(KeyPattern::SEQUENTIAL,0);
//    kvg.run_parallel([&]() {
//        // update existing first 100 documents
//        for (auto i = 0u; i < 100; i++) {
//            kvg.remove(KeyPattern::SEQUENTIAL, true);
//        }
//    });

    kvg.run_parallel([&]() {
        // Get first 100 documents again and check for failure
        for (auto i = 0u; i < 100; i++) {
            kvg.get(KeyPattern::SEQUENTIAL, false /* exclusive_access */);
        }
    });

    kvg.run_parallel([&](){
        // Do range query on different pattern
        for (auto i = 0u; i < 1000; i++) {
            kvg.range_query(KeyPattern::SEQUENTIAL, 28, true /* exclusive_access */, true, true);
        }
    });
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