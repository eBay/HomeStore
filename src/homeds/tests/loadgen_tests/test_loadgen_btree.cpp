#include <gtest/gtest.h>
#include <iostream>
#include <thread>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <utility/thread_buffer.hpp>
#include <utility/obj_life_counter.hpp>
#include <metrics/metrics.hpp>

#include "btree_simple/btree_key_spec.hpp"
#include "btree_simple/btree_value_spec.hpp"
#include "btree_simple/btree_store_spec.hpp"
#include "btree_loadgen.hpp"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc, iomgr)
THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define simple_mem_btree_store_t MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 8192 >
#define SimpleMemBtreeKVGen KVGenerator<SimpleNumberKey, FixedBytesValue<64>, simple_mem_btree_store_t >

typedef testing::Types<SimpleMemBtreeKVGen/*,SSDBtree-define more types here*/> KVGenTypes;
TYPED_TEST_CASE(BtreeTestLoadGen, KVGenTypes);

TYPED_TEST(BtreeTestLoadGen, BtreeTest) {
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
