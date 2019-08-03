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

#include "keyspecs/cache_key_spec.hpp"
#include "valuespecs/cache_value_spec.hpp"
#include "storespecs/cache_store_spec.hpp"

#include "loadgen_crud_suite.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"

#include "disk_initializer.hpp"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define G_SimpleKV_Mem                                                                                                 \
    BtreeLoadGen< SimpleNumberKey, FixedBytesValue< 64 >,                                                              \
                  MemBtreeStoreSpec< SimpleNumberKey, FixedBytesValue< 64 >, 4096 >, IOMgrExecutor >

#define G_SimpleKV_SSD                                                                                                 \
    BtreeLoadGen< SimpleNumberKey, FixedBytesValue< 64 >,                                                              \
                  SSDBtreeStoreSpec< SimpleNumberKey, FixedBytesValue< 64 >, 4096 >, IOMgrExecutor >

#define G_VarKV_SSD                                                                                                    \
    BtreeLoadGen< VarBytesKey, VarBytesValue< 64 >, SSDBtreeStoreSpec< VarBytesKey, VarBytesValue< 64 >, 4096 >,       \
                  IOMgrExecutor >

#define G_MapKV_SSD BtreeLoadGen< MapKey, MapValue, MapStoreSpec< MapKey, MapValue, 4096 >, IOMgrExecutor >

#define G_CacheKV BtreeLoadGen< CacheKey, CacheValue, CacheStoreSpec< CacheKey, CacheValue, 4096 >, IOMgrExecutor >

static Param parameters;

struct BtreeTest : public testing::Test {
    std::unique_ptr< G_SimpleKV_Mem > loadgen;

    void execute() {
        loadgen = std::make_unique< G_SimpleKV_Mem >(parameters.NT);
        loadgen->initParam(parameters);
        LOGINFO("WarmUp Started");
        loadgen->warmup(true, true, false, false);
        LOGINFO("Regression Started");
        loadgen->regression(true, true, false, false);
    }
};

TEST_F(BtreeTest, SimpleKVMemTest) { this->execute(); }

// TODO: combine the SimpleKVMem/SimpleKVSSD/VarKVSSD in one class
struct SSDBtreeTest : public testing::Test {
    std::unique_ptr< G_SimpleKV_SSD > loadgen;
    DiskInitializer< IOMgrExecutor >  di;
    std::mutex                        m_mtx;
    std::condition_variable           m_cv;
    bool                              is_complete = false;

    void join() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        is_complete = true;
        m_cv.notify_one();
    }

    void execute() {
        loadgen = std::make_unique< G_SimpleKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&SSDBtreeTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(SSDBtreeTest, SimpleKVSSDTest) { this->execute(); }

struct SSDBtreeVarKVTest : public testing::Test {
    std::unique_ptr< G_VarKV_SSD >   loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex                       m_mtx;
    std::condition_variable          m_cv;
    bool                             is_complete = false;

    void join() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        is_complete = true;
        m_cv.notify_one();
    }

    void execute() {
        loadgen = std::make_unique< G_VarKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&SSDBtreeVarKVTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(SSDBtreeVarKVTest, VarKVSSDTest) { this->execute(); }

struct MapTest : public testing::Test {
    std::unique_ptr< G_MapKV_SSD >   loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex                       m_mtx;
    std::condition_variable          m_cv;
    bool                             is_complete = false;

    void join() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(true, false, true, true);
        is_complete = true;
        m_cv.notify_one();
    }

    void execute() {
        loadgen = std::make_unique< G_MapKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&MapTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(MapTest, MapSSDTest) { this->execute(); }

struct CacheTest : public testing::Test {
    std::unique_ptr< G_CacheKV > loadgen;

    void execute() {
        loadgen = std::make_unique< G_CacheKV >(parameters.NT);
        loadgen->initParam(parameters);
        LOGINFO("WarmUp Started");
        loadgen->warmup(false, true, false, false);
        LOGINFO("Regression Started");
        loadgen->regression(false, true, false, false);
    }
};

TEST_F(CacheTest, CacheMemTest) { this->execute(); }

SDS_OPTION_GROUP(
    test_load, (num_io, "", "num_io", "num of io", ::cxxopts::value< uint64_t >()->default_value("1000"), "number"),
    (run_time, "", "run_time", "time to run in seconds", ::cxxopts::value< uint64_t >()->default_value("300"),
     "number"),
    (num_keys, "", "num_keys", "num of keys", ::cxxopts::value< uint64_t >()->default_value("300"), "number"),
    (per_create, "", "per_create", "percentage of io that are creates",
     ::cxxopts::value< uint64_t >()->default_value("40"), "number"),
    (per_read, "", "per_read", "percentage of io that are reads", ::cxxopts::value< uint64_t >()->default_value("5"),
     "number"),
    (per_update, "", "per_update", "percentage of io that are updates",
     ::cxxopts::value< uint64_t >()->default_value("5"), "number"),
    (per_delete, "", "per_delete", "percentage of io that are deletes",
     ::cxxopts::value< uint64_t >()->default_value("15"), "number"),
    (per_range_update, "", "per_range_update", "percentage of io that are range update",
     ::cxxopts::value< uint64_t >()->default_value("15"), "number"),
    (per_range_query, "", "per_range_query", "percentage of io that are range query",
     ::cxxopts::value< uint64_t >()->default_value("20"), "number"),
    (print_interval, "", "print_interval", "print interval in seconds",
     ::cxxopts::value< uint64_t >()->default_value("10"), "number"),
    (warm_up_keys, "", "warm_up_keys", "num of warm up keys", ::cxxopts::value< uint64_t >()->default_value("200"),
     "number"),
    (num_threads, "", "num_threads", "num of threads", ::cxxopts::value< uint8_t >()->default_value("8"), "number"),
    (workload_shift_time, "", "workload_shift_time", "time in sec to shift workload",
     ::cxxopts::value< uint64_t >()->default_value("3600"), "number"))
SDS_OPTIONS_ENABLE(logging, test_load, test_volume)

int main(int argc, char* argv[]) {
    testing::InitGoogleTest(&argc, argv);

    ::testing::GTEST_FLAG(filter) = "*Map*:*Cache*";
    SDS_OPTIONS_LOAD(argc, argv, logging, test_load)
    sds_logging::SetLogger("test_load");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    parameters.NIO = SDS_OPTIONS["num_io"].as< uint64_t >();
    parameters.NK = SDS_OPTIONS["num_keys"].as< uint64_t >();
    parameters.PC = SDS_OPTIONS["per_create"].as< uint64_t >();
    parameters.PR = SDS_OPTIONS["per_read"].as< uint64_t >();
    parameters.PU = SDS_OPTIONS["per_update"].as< uint64_t >();
    parameters.PD = SDS_OPTIONS["per_delete"].as< uint64_t >();
    parameters.NRT = SDS_OPTIONS["run_time"].as< uint64_t >();
    parameters.WST = SDS_OPTIONS["workload_shift_time"].as< uint64_t >();

    parameters.PRU = SDS_OPTIONS["per_range_update"].as< uint64_t >();
    parameters.PRQ = SDS_OPTIONS["per_range_query"].as< uint64_t >();
    parameters.PRINT_INTERVAL = SDS_OPTIONS["print_interval"].as< uint64_t >();
    parameters.WARM_UP_KEYS = SDS_OPTIONS["warm_up_keys"].as< uint64_t >();
    parameters.NT = SDS_OPTIONS["num_threads"].as< uint8_t >();

    if (parameters.PC + parameters.PR + parameters.PU + parameters.PD + parameters.PRU + parameters.PRQ != 100) {
        LOGERROR("percent should total to 100");
        return 1;
    }
    parameters.PR += parameters.PC;
    parameters.PU += parameters.PR;
    parameters.PD += parameters.PU;
    parameters.PRU += parameters.PD;
    parameters.PRQ = 100;
    srand(time(0));

    assert(parameters.WARM_UP_KEYS <=
           parameters.NK); // this is required as we set MAX_KEYS in key spec as per value of NK
           
    return RUN_ALL_TESTS();
}
