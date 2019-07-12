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

#include "mapping/mapping.hpp"
#include "keyspecs/map_key_spec.hpp"
#include "storespecs/map_store_spec.hpp"
#include "valuespecs/map_value_spec.hpp"
#include "storespecs/ssdbtree_store_spec.hpp"
#include "keyspecs/var_key_spec.hpp"
#include "valuespecs/var_value_spec.hpp"

#include "btree_loadgen.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"

#include "disk_initializer.hpp"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define G_SimpleKV_Mem BtreeLoadGen<SimpleNumberKey, FixedBytesValue<64>, MemBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 4096 >, IOMgrExecutor>

#define G_SimpleKV_SSD BtreeLoadGen<SimpleNumberKey, FixedBytesValue<64>, SSDBtreeStoreSpec<SimpleNumberKey, FixedBytesValue<64>, 4096 >, IOMgrExecutor>

#define G_VarKV_SSD BtreeLoadGen<VarBytesKey, VarBytesValue<64>, SSDBtreeStoreSpec<VarBytesKey, VarBytesValue<64>, 4096 >, IOMgrExecutor>

#define G_MapKV_SSD BtreeLoadGen<MapKey, MapValue, MapStoreSpec<MapKey, MapValue, 4096 >, IOMgrExecutor>

static uint64_t NIO=0,NK=0,NRT=0;//total ios and total keys
static int PC=0,PR=0,PU=0,PD=0,PRU=0,PRQ=0;//total % for op 
static uint64_t PRINT_INTERVAL=0;
static uint64_t WARM_UP_KEYS=0;
static uint8_t NT=0;//num of threads
Clock::time_point startTime;
Clock::time_point print_startTime;

struct BtreeTest : public testing::Test{
    std::unique_ptr<G_SimpleKV_Mem> loadgen;
    
    void execute(){
        loadgen = std::make_unique<G_SimpleKV_Mem>(NT);
        loadgen->initParam(PC,PR,PU,PD,PRU,PRQ,NIO,NRT,NK,PRINT_INTERVAL,WARM_UP_KEYS,startTime,print_startTime);
        LOGINFO("WarmUp Started");
        loadgen->warmup();
        LOGINFO("Regression Started");
        loadgen->regression(true,false,false);
    }
};

TEST_F(BtreeTest, SimpleKVMemTest) {
    this->execute();
}

// TODO: combine the SimpleKVMem/SimpleKVSSD/VarKVSSD in one class
struct SSDBtreeTest : public testing::Test{
    std::unique_ptr<G_SimpleKV_SSD> loadgen; 
    DiskInitializer<IOMgrExecutor> di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete=false;

    void join(){
        std::unique_lock<std::mutex> lk(m_mtx);
        m_cv.wait(lk,[this]{return is_complete;});
    }
    
    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(PC,PR,PU,PD,PRU,PRQ,NIO,NRT,NK,PRINT_INTERVAL,WARM_UP_KEYS,startTime,print_startTime);//internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(false,false,false);
        is_complete=true;
        m_cv.notify_one();
    }
    
    void execute(){
        loadgen = std::make_unique<G_SimpleKV_SSD>(NT);//starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&SSDBtreeTest::init_done_cb, this, std::placeholders::_1,std::placeholders::_2));
        join();//sync wait for test to finish
    }
};

TEST_F(SSDBtreeTest, SimpleKVSSDTest) {
    this->execute();
}


struct SSDBtreeVarKVTest : public testing::Test{
    std::unique_ptr<G_VarKV_SSD> loadgen; 
    DiskInitializer<IOMgrExecutor> di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete=false;

    void join(){
        std::unique_lock<std::mutex> lk(m_mtx);
        m_cv.wait(lk,[this]{return is_complete;});
    }
    
    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(PC,PR,PU,PD,PRU,PRQ,NIO,NRT,NK,PRINT_INTERVAL,WARM_UP_KEYS,startTime,print_startTime);//internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(false,false,false);
        is_complete=true;
        m_cv.notify_one();
    }
    
    void execute(){
        loadgen = std::make_unique<G_VarKV_SSD>(NT);//starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&SSDBtreeVarKVTest::init_done_cb, this, std::placeholders::_1,std::placeholders::_2));
        join();//sync wait for test to finish
    }
};



TEST_F(SSDBtreeVarKVTest, VarKVSSDTest) {
    this->execute();
}

struct MapTest : public testing::Test{
    std::unique_ptr<G_MapKV_SSD> loadgen; 
    DiskInitializer<IOMgrExecutor> di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete=false;

    void join(){
        std::unique_lock<std::mutex> lk(m_mtx);
        m_cv.wait(lk,[this]{return is_complete;});

    }
    
    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(PC,PR,PU,PD,PRU,PRQ,NIO,NRT,NK,PRINT_INTERVAL,WARM_UP_KEYS,startTime,print_startTime);//internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(false,true,true);
        is_complete=true;
        m_cv.notify_one();
    }
    
    void execute(){
        loadgen = std::make_unique<G_MapKV_SSD>(NT);//starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&MapTest::init_done_cb, this, std::placeholders::_1,std::placeholders::_2));
        join();//sync wait for test to finish
    }
};

TEST_F(MapTest, MapSSDTest) {
        this->execute();
}


SDS_OPTION_GROUP(test_load,
        (num_io, "", "num_io", "num of io", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
        (run_time, "", "run_time", "time to run in seconds", ::cxxopts::value<uint64_t>()->default_value("300"), "number"),
        (num_keys, "", "num_keys", "num of keys", ::cxxopts::value<uint64_t>()->default_value("300"), "number"),
        (per_create, "", "per_create", "percentage of io that are creates", ::cxxopts::value<uint64_t>()->default_value("40"), "number"),
        (per_read, "", "per_read", "percentage of io that are reads", ::cxxopts::value<uint64_t>()->default_value("5"), "number"),
        (per_update, "", "per_update", "percentage of io that are updates", ::cxxopts::value<uint64_t>()->default_value("5"), "number"),
        (per_delete, "", "per_delete", "percentage of io that are deletes", ::cxxopts::value<uint64_t>()->default_value("15"), "number"),
        (per_range_update, "", "per_range_update", "percentage of io that are range update", ::cxxopts::value<uint64_t>()->default_value("15"), "number"),
        (per_range_query, "", "per_range_query", "percentage of io that are range query", ::cxxopts::value<uint64_t>()->default_value("20"), "number"),
        (print_interval, "", "print_interval", "print interval in seconds", ::cxxopts::value<uint64_t>()->default_value("10"), "number"),
        (warm_up_keys, "", "warm_up_keys", "num of warm up keys", ::cxxopts::value<uint64_t>()->default_value("1000"), "number"),
        (num_threads, "", "num_threads", "num of threads", ::cxxopts::value<uint8_t>()->default_value("8"), "number"))
SDS_OPTIONS_ENABLE(logging, test_load, test_volume)

int main(int argc, char *argv[]) {
    testing::InitGoogleTest(&argc, argv);
    
    ::testing::GTEST_FLAG(filter) = "*MapSSD*";
    SDS_OPTIONS_LOAD(argc, argv, logging,test_load)
    sds_logging::SetLogger("test_load");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    NIO = SDS_OPTIONS["num_io"].as<uint64_t>();
    NK = SDS_OPTIONS["num_keys"].as<uint64_t>();
    PC = SDS_OPTIONS["per_create"].as<uint64_t>();
    PR = SDS_OPTIONS["per_read"].as<uint64_t>();
    PU = SDS_OPTIONS["per_update"].as<uint64_t>();
    PD = SDS_OPTIONS["per_delete"].as<uint64_t>();
    NRT = SDS_OPTIONS["run_time"].as<uint64_t>();
    
    PRU = SDS_OPTIONS["per_range_update"].as<uint64_t>();
    PRQ = SDS_OPTIONS["per_range_query"].as<uint64_t>();
    PRINT_INTERVAL = SDS_OPTIONS["print_interval"].as<uint64_t>();
    WARM_UP_KEYS = SDS_OPTIONS["warm_up_keys"].as<uint64_t>();
    NT = SDS_OPTIONS["num_threads"].as<uint8_t>();
    
    if(PC+PR+PU+PD+PRU+PRQ!=100){
        LOGERROR("percent should total to 100");
        return 1;
    }
    PR+=PC;
    PU+=PR;
    PD+=PU;
    PRU+=PD;
    PRQ=100;
    srand(time(0));

    startTime = Clock::now();
    print_startTime = Clock::now();
    return RUN_ALL_TESTS();
}

