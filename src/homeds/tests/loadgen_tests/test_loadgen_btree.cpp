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

static uint64_t NIO=0,NC=0,NR=0,NU=0,ND=0,NK=0,CURR_NC=0,CURR_NR=0,CURR_NU=0,CURR_ND=0;

static uint64_t get_io_count(int percent){
    return percent*NIO/100;
}

struct BtreeTestLoadGen : public ::testing::Test {
    KVG kvg;
    std::atomic<uint64_t> stored_keys=0, outstanding_create=0, outstanding_remove=0, outstanding_others=0;
    int WARM_UP_KEYS=1000;
    int CHECKPOINT_RANGE_BATCH_SIZE=50;
    std::mutex m_cv_mtx;
    
    uint64_t get_warmup_key_count(int percent){
        return percent*WARM_UP_KEYS/100;
    }

    uint64_t get_existing_key_count(int percent){
        return percent*kvg.get_keys_count()/100;
    }
    
    void do_checkpoint() {
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_existing_key_count(100); i += CHECKPOINT_RANGE_BATCH_SIZE) {
                kvg.range_query(KeyPattern::SEQUENTIAL,
                        CHECKPOINT_RANGE_BATCH_SIZE, true /* exclusive_access */, true, true);
            }
        });
    }
    
    void do_inserts() {
        // preload random 50%
        kvg.preload(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, get_warmup_key_count(50));
        
        //insert sequential 50%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < get_warmup_key_count(50); i++) {
                kvg.insert_new(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES);
            }
        });
    }
    
    void do_updates() {
        auto tenPer = get_existing_key_count(10);
        auto thirtyPer = get_existing_key_count(30);
        
        //update sequential 10%, from start
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg.update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
            }
        });

        //update sequential 10%, trailing
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg.update(KeyPattern::SEQUENTIAL, ValuePattern::RANDOM_BYTES, true, true);
            }
        });
        
        //update random 30%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < thirtyPer; i++) {
                kvg.update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true);
            }
        });
    }

    void do_removes() {
        auto tenPer = get_existing_key_count(10);
        auto thirtyPer = get_existing_key_count(30);
        
        //remove sequential 10% from start
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, 0);
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg.remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });

        //remove trailing 10%
        kvg.reset_pattern(KeyPattern::SEQUENTIAL, get_existing_key_count(90));
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < tenPer; i++) {
                kvg.remove(KeyPattern::SEQUENTIAL, true, true);
            }
        });
        
        //remove random 30%
        kvg.run_parallel([&]() {
            for (auto i = 0u; i < thirtyPer; i++) {
                kvg.remove(KeyPattern::UNI_RANDOM, true, true);
            }
        });

        do_checkpoint();
        kvg.remove_all_keys();
    }

    void do_negative_tests() {
        //remove from empty set
        kvg.run_parallel([&]() {
            kvg.remove(KeyPattern::UNI_RANDOM, false, false, nullptr, false);
            kvg.update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, false, false, false);
        });
    }

    void warmup(){
        //basic serialized tests
        do_inserts();
        do_updates();
        do_removes();
        do_negative_tests();
    }
    
    void insert_success_cb() {
        std::unique_lock<std::mutex> lk(mutex);
        stored_keys++;
        outstanding_create--;
    }
    void remove_success_cb() {
        std::unique_lock<std::mutex> lk(mutex);
        stored_keys--;
        outstanding_others--;
    }
    void read_update_success_cb() {
        std::unique_lock<std::mutex> lk(mutex);
        outstanding_others--;
    }
    
    void regression(){
        kvg.run_parallel([&]() {
            while(CURR_NC<NC || CURR_NR<NR || CURR_NU<NU || CURR_ND<ND){
                std::unique_lock<std::mutex> lk(mutex);
                //allow create only if stored keys + issued creates are less than max number of keys
                while (CURR_NC<NC && stored_keys+outstanding_create<NK) {
                    CURR_NC++;
                    outstanding_create++;
                    kvg.insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES,
                                   std::bind(&BtreeTestLoadGen::insert_success_cb, this));
                }
                if(CURR_NR<NR && stored_keys-outstanding_others>0 ) {
                    CURR_NR++;
                    outstanding_others++;
                    kvg.get(KeyPattern::UNI_RANDOM, true, true,true,
                            std::bind(&BtreeTestLoadGen::remove_success_cb, this));
                }
                if (CURR_NU<NU && stored_keys-outstanding_others>0) {
                    CURR_NU++;
                    outstanding_others++;
                    kvg.update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true,true,
                               std::bind(&BtreeTestLoadGen::remove_success_cb, this));
                }
                //allow remove only if there are any stored keys on which other operations are not being worked on
                if (CURR_ND<ND && stored_keys-outstanding_others>0) {
                    CURR_ND++;
                    outstanding_others++;
                    kvg.remove(KeyPattern::UNI_RANDOM, true, true, 
                            std::bind(&BtreeTestLoadGen::remove_success_cb, this));
                }
            }
        });
        
        do_checkpoint();
        kvg.remove_all_keys();
    }
};

TEST_F(BtreeTestLoadGen, SimpleMemBtreeTest) {
    this->warmup();
    this->regression();
}

SDS_OPTION_GROUP(test_mem_btree,
                 (num_io, "", "num_io", "num of io", ::cxxopts::value<uint64_t>()->default_value("10000"), "number"),
                 (num_keys, "", "num_keys", "num of keys", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
                 (percent_create, "", "percent_create", "percentage of io that are creates", ::cxxopts::value<uint64_t>()->default_value("80"), "number"),
                 (percent_read, "", "percent_read", "percentage of io that are reads", ::cxxopts::value<uint64_t>()->default_value("10"), "number"),
                 (percent_update, "", "percent_update", "percentage of io that are updates", ::cxxopts::value<uint64_t>()->default_value("50"), "number"),
                 (percent_delete, "", "percent_delete", "percentage of io that are deletes", ::cxxopts::value<uint64_t>()->default_value("30"), "number"))
                 /* Percent above are not cummulative to 100. They can happen in any order*/
SDS_OPTIONS_ENABLE(logging, test_mem_btree)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging,test_mem_btree)
    sds_logging::SetLogger("test_mem_btree");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    testing::InitGoogleTest(&argc, argv);

    NIO = SDS_OPTIONS["num_io"].as<uint64_t>();
    NK = SDS_OPTIONS["num_keys"].as<uint64_t>();
    NC = get_io_count(SDS_OPTIONS["percent_create"].as<uint64_t>());
    NR = get_io_count(SDS_OPTIONS["percent_read"].as<uint64_t>());
    NU = get_io_count(SDS_OPTIONS["percent_update"].as<uint64_t>());
    ND = get_io_count(SDS_OPTIONS["percent_delete"].as<uint64_t>());
    
    assert(ND<=NC);
    return RUN_ALL_TESTS();
}

