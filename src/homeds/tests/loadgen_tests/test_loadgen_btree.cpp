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

static uint64_t NIO=0,NK=0;//total ios and total keys
static int PC=0,PR=0,PU=0,PD=0;//total % for op 
static uint64_t PRINT_INTERVAL=0;
static uint64_t WARM_UP_KEYS=0;


struct BtreeTestLoadGen : public ::testing::Test {
    KVG kvg;
    std::atomic<uint64_t> stored_keys=0, outstanding_create=0, outstanding_others=0;
    int CHECKPOINT_RANGE_BATCH_SIZE=50;
    std::condition_variable m_cv;
    std::mutex m_cv_mtx;
    uint64_t C_NC=0,C_NR=0,C_NU=0,C_ND=0,C_IO;//current op issued counter
    
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
    
    uint64_t get_issued_ios(){
        return C_NC+C_NR+C_NU+C_ND;
    }
    
    void try_create(){
        if((stored_keys+outstanding_create)>=NK)return ;//cant accomodate more 
        kvg.insert_new(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES,
                       std::bind(&BtreeTestLoadGen::insert_success_cb, this));
        C_NC++;
        outstanding_create++;
        try_print();
    }
    
    void try_read(){
        if(stored_keys-outstanding_others==0)return ;//cannot accomodate more 
        kvg.get(KeyPattern::UNI_RANDOM, true, true,true,
                std::bind(&BtreeTestLoadGen::read_update_success_cb, this));
        C_NR++;
        outstanding_others++;
        try_print();
    }
    
    void try_update(){
        if(stored_keys-outstanding_others==0)return ;//cannot accomodate more 
        kvg.update(KeyPattern::UNI_RANDOM, ValuePattern::RANDOM_BYTES, true, true,true,
                   std::bind(&BtreeTestLoadGen::read_update_success_cb, this));
        C_NU++;
        outstanding_others++;
        try_print();
    }
    
    void try_delete(){
        if(stored_keys-outstanding_others==0)return ;//cannot accomodate more 
        kvg.remove(KeyPattern::UNI_RANDOM, true, true,
                   std::bind(&BtreeTestLoadGen::remove_success_cb, this));
        C_ND++;
        outstanding_others++;
        try_print();
    }

    void try_print(){
        if (get_issued_ios() % PRINT_INTERVAL == 0) {
            LOGDEBUG(
                    "stored_keys:{}, outstanding_create:{}, outstanding_others:{}, creates:{}, reads:{}, updates:{}, deletes:{}, total_io:{}",
                    stored_keys, outstanding_create, outstanding_others, C_NC, C_NR, C_NU, C_ND, get_issued_ios());
        }
    }
    
    void regression(){
        kvg.run_parallel([&]() {
            while(true){
                std::unique_lock<std::mutex> lk(mutex);
                auto op = select_io();

                if(op==1)
                    try_create();
                else if(op==2)
                    try_read();
                else if(op==3)
                    try_update();
                else if(op==4)
                    try_delete();
                else
                    assert(0);

                if (get_issued_ios() > NIO)
                    break;
            }
        });
        
        do_checkpoint();
        kvg.remove_all_keys();
    }
    
    uint8_t select_io(){
        int ran = rand() % 100;
        if(ran<PC)return 1;
        else if(ran<PR)return 2;
        else if(ran<PU)return 3;
        else if(ran<PD)return 4;
        else assert(0);
    }
    
};

TEST_F(BtreeTestLoadGen, SimpleMemBtreeTest) {
    this->warmup();
    LOGDEBUG("Warm up completed");
    this->regression();
}

SDS_OPTION_GROUP(test_mem_btree,
        (num_io, "", "num_io", "num of io", ::cxxopts::value<uint64_t>()->default_value("10000"), "number"),
        (num_keys, "", "num_keys", "num of keys", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
        (per_create, "", "per_create", "percentage of io that are creates", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
        (per_read, "", "per_read", "percentage of io that are reads", ::cxxopts::value<uint64_t>()->default_value("20"), "number"),
        (per_update, "", "per_update", "percentage of io that are updates", ::cxxopts::value<uint64_t>()->default_value("30"), "number"),
        (per_delete, "", "per_delete", "percentage of io that are deletes", ::cxxopts::value<uint64_t>()->default_value("40"), "number"),
        (print_interval, "", "print_interval", "print interval for each op", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
        (warm_up_keys, "", "warm_up_keys", "num of warm up keys", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"))
SDS_OPTIONS_ENABLE(logging, test_mem_btree)

int main(int argc, char *argv[]) {
    SDS_OPTIONS_LOAD(argc, argv, logging,test_mem_btree)
    sds_logging::SetLogger("test_mem_btree");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    testing::InitGoogleTest(&argc, argv);

    NIO = SDS_OPTIONS["num_io"].as<uint64_t>();
    NK = SDS_OPTIONS["num_keys"].as<uint64_t>();
    PC = SDS_OPTIONS["per_create"].as<uint64_t>();
    PR = SDS_OPTIONS["per_read"].as<uint64_t>();
    PU = SDS_OPTIONS["per_update"].as<uint64_t>();
    PD = SDS_OPTIONS["per_delete"].as<uint64_t>();
    PRINT_INTERVAL = SDS_OPTIONS["print_interval"].as<uint64_t>();
    WARM_UP_KEYS = SDS_OPTIONS["warm_up_keys"].as<uint64_t>();
    
    if(PC+PR+PU+PD!=100){
        LOGERROR("CRUD percent should total to 100");
        return 1;
    }
    PR+=PC;
    PU+=PR;
    PD=100;
    srand(time(0));
    
    return RUN_ALL_TESTS();
}

