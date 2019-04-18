//#include <gtest/gtest.h>
//#include <iostream>
//#include <thread>
//#include <sds_logging/logging.h>
//#include <sds_options/options.h>
//
//#include "btree_loadgen.hpp"
//#include "btree_simple/btree_key_spec.hpp"
//#include "btree_simple/btree_value_spec.hpp"
//#include "btree_simple/btree_store_spec.hpp"
//
//SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc, iomgr)
//SDS_OPTION_GROUP(test_mem_btree, (num_keys, "", "num_keys", "number of keys",
//        ::cxxopts::value<uint64_t>()->default_value("10000"), "number"))
//SDS_OPTIONS_ENABLE(logging, test_mem_btree)
//
//#define simple_mem_btree_store_t homeds::loadgen::MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 8192 >
//#define SimpleMemBtreeKVGen KVGenerator<SimpleNumberKey, FixedBytesValue<64>, simple_mem_btree_store_t >
//
//typedef testing::Types<SimpleMemBtreeKVGen/*,SSDBtree-define more types here*/> KVGenTypes;
//TYPED_TEST_CASE(BtreeTestLoadGen, KVGenTypes);
//
//TYPED_TEST(BtreeTestLoadGen, BtreeTest) {
//    this->execute();
//}
//
//int main(int argc, char *argv[]) {
//    SDS_OPTIONS_LOAD(argc, argv, logging, test_mem_btree)
//    sds_logging::SetLogger("test_mem_btree");
//    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
//
//    testing::InitGoogleTest(&argc, argv);
//
//    N = SDS_OPTIONS["num_keys"].as<uint64_t>();
//
//    return RUN_ALL_TESTS();
//}
//

#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>
#include <utility/obj_life_counter.hpp>

#include <metrics/metrics.hpp>
#include "homeds/loadgen/loadgen.hpp"
#include "homeds/loadgen/keyset.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "btree_simple/btree_key_spec.hpp"
#include "btree_simple/btree_value_spec.hpp"
#include "btree_simple/btree_store_spec.hpp"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc, iomgr)
THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define simple_mem_btree_store_t MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 8192 >
#define KVG KVGenerator<SimpleNumberKey, FixedBytesValue<64>, simple_mem_btree_store_t >

static uint64_t N=0;//total number of keys

static uint64_t get_io_count(int percent){
    return percent*N/100;
}

struct BtreeTestLoadGen : public ::testing::Test {
    KVG kvg;

    void do_checkpoint() {
        kvg.run_parallel([&]() {
            int batch = 50;
            for (auto i = 0u; i < get_io_count(100); i += batch) {
                kvg.range_query(KeyPattern::SEQUENTIAL,
                                batch, true /* exclusive_access */, true, true);
            }
        });
    }

    void do_inserts() {
        // preload random 50%
        kvg.preload(KeyPattern::UNI_RANDOM,
                    ValuePattern::RANDOM_BYTES, get_io_count(50));

        //insert sequential 50%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(50); i++) {
                kvg.insert_new(KeyPattern::SEQUENTIAL,
                               ValuePattern::RANDOM_BYTES);
            }
        });
    }

    void do_updates() {
        //update sequential 10%, from start
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.update(KeyPattern::SEQUENTIAL,
                           ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        //update random 50%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(50); i++) {
                kvg.update(KeyPattern::UNI_RANDOM,
                           ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        do_checkpoint();

        //update sequential 10%, trailing
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, get_io_count(90));
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.update(KeyPattern::SEQUENTIAL,
                           ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        do_checkpoint();
    }

    void do_removes() {
        //remove sequential 10% from start
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        //remove random 30%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(30); i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, true, true);
            }
        });

        //remove trailing 10%
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, get_io_count(90));
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(10); i++) {
                kvg.remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        do_checkpoint();

        //remove all documents
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(50); i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, true, true);
            }
        });
    }

    void do_negative_tests() {
        //remove from empty set, 5% random
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(5); i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, false, false);
            }
        });

        //update  empty set, 5% random
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_io_count(5); i++) {
                kvg.update(KeyPattern::UNI_RANDOM,
                           ValuePattern::RANDOM_BYTES, false, false);
            }
        });
    }

    void execute(){
        //basic serialized tests
        do_inserts();
        do_updates();
        do_removes();
        do_negative_tests();

        //TODO - add parallel tests
    }
};

TEST_F(BtreeTestLoadGen, SimpleMemBtreeTest) {
    this->execute();
}


SDS_OPTION_GROUP(test_mem_btree,(num_keys,"", "num_keys", "number of keys",
        ::cxxopts::value<uint64_t>()->default_value("10000"), "number"))
SDS_OPTIONS_ENABLE(logging, test_mem_btree)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging,test_mem_btree)
    sds_logging::SetLogger("test_mem_btree");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    testing::InitGoogleTest(&argc, argv);

    N = SDS_OPTIONS["num_keys"].as<uint64_t>();

    return RUN_ALL_TESTS();
}

