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

#include "keyspecs/simple_key_spec.hpp"
#include "valuespecs/fixedbyte_value_spec.hpp"
#include "storespecs/membtree_store_spec.hpp"

#include "btree_loadgen.hpp"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc, iomgr)
THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define G_SimpleKV_Mem BtreeLoadGen<SimpleNumberKey, FixedBytesValue<64>, MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 8192 >>

static uint64_t NIO=0,NK=0;//total ios and total keys
static int PC=0,PR=0,PU=0,PD=0;//total % for op 
static uint64_t PRINT_INTERVAL=0;
static uint64_t WARM_UP_KEYS=0;

struct BtreeTest : public testing::Test{
};

TEST_F(BtreeTest, SimpleKVMemTest) {
    G_SimpleKV_Mem loadgen;
    loadgen.setParam(PC,PR,PU,PD,NIO,NK,PRINT_INTERVAL,WARM_UP_KEYS);
    loadgen.warmup();
    loadgen.regression();
}

SDS_OPTION_GROUP(test_mem_btree,
        (num_io, "", "num_io", "num of io", ::cxxopts::value<uint64_t>()->default_value("10000"), "number"),
        (num_keys, "", "num_keys", "num of keys", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
        (per_create, "", "per_create", "percentage of io that are creates", ::cxxopts::value<uint64_t>()->default_value("40"), "number"),
        (per_read, "", "per_read", "percentage of io that are reads", ::cxxopts::value<uint64_t>()->default_value("10"), "number"),
        (per_update, "", "per_update", "percentage of io that are updates", ::cxxopts::value<uint64_t>()->default_value("30"), "number"),
        (per_delete, "", "per_delete", "percentage of io that are deletes", ::cxxopts::value<uint64_t>()->default_value("20"), "number"),
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

