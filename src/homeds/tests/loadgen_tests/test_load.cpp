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

#include "storespecs/volume_store_spec.hpp"
#include "keyspecs/vol_key_spec.hpp"
#include "valuespecs/vol_value_spec.hpp"

#include "storespecs/file_store_spec.hpp"
#include "valuespecs/blk_value_spec.hpp"

#include "disk_initializer.hpp"
#include <linux/fs.h>
#include <sys/ioctl.h>

#ifndef DEBUG
extern bool same_value_gen;
#endif
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

THREAD_BUFFER_INIT;

using namespace homeds::loadgen;

#define G_SimpleKV_Mem                                                                                                 \
    BtreeLoadGen< SimpleNumberKey, FixedBytesValue< 64 >,                                                              \
                  MemBtreeStoreSpec< SimpleNumberKey, FixedBytesValue< 64 >, 512 >, IOMgrExecutor >

#define G_SimpleKV_SSD                                                                                                 \
    BtreeLoadGen< SimpleNumberKey, FixedBytesValue< 64 >,                                                              \
                  SSDBtreeStoreSpec< SimpleNumberKey, FixedBytesValue< 64 >, 4096 >, IOMgrExecutor >

#define G_VarKV_SSD                                                                                                    \
    BtreeLoadGen< VarBytesKey, VarBytesValue< 64 >, SSDBtreeStoreSpec< VarBytesKey, VarBytesValue< 64 >, 4096 >,       \
                  IOMgrExecutor >

#define G_MapKV_SSD BtreeLoadGen< MapKey, MapValue, MapStoreSpec< MapKey, MapValue, 4096 >, IOMgrExecutor >

#define G_CacheKV BtreeLoadGen< CacheKey, CacheValue, CacheStoreSpec< CacheKey, CacheValue, 4096 >, IOMgrExecutor >

#define G_Volume_Test BtreeLoadGen<VolumeKey, VolumeValue, VolumeStoreSpec<VolumeKey, VolumeValue>, IOMgrExecutor>

#define G_FileKV BtreeLoadGen< MapKey, BlkValue, FileStoreSpec, IOMgrExecutor >

static Param parameters;
bool loadgen_verify_mode = false;

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
    DiskInitializer< IOMgrExecutor > di;
    std::unique_ptr< G_MapKV_SSD >   loadgen;
    std::mutex                       m_mtx;
    std::condition_variable          m_cv;
    bool                             is_complete = false;

    void join() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        loadgen->specific_tests(SPECIFIC_TEST::MAP);
        LOGINFO("Regression Started");
        loadgen->regression(true, false, true, true);
        is_complete = true;
        m_cv.notify_one();
    }

    void execute() {
        loadgen = std::make_unique< G_MapKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&MapTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2), 512);
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(MapTest, MapSSDTest) { this->execute(); }

struct FileTest : public testing::Test {
    std::unique_ptr< G_FileKV >      loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex                       m_mtx;
    std::condition_variable          m_cv;
    bool                             is_complete = false;

    void join() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(std::error_condition err, const homeds::out_params& params1) {
        loadgen->specific_tests(SPECIFIC_TEST::MAP);
        LOGINFO("Regression Started");
        size_t size = 0;
        for (uint32_t i = 0; i < parameters.file_names.size(); ++i) {
            auto fd = open(parameters.file_names[i].c_str(), O_RDWR);
            struct stat buf;
            uint64_t devsize = 0;
            if (fstat(fd, &buf) >= 0) {
                devsize = buf.st_size;
            } else {
                ioctl(fd, BLKGETSIZE64, &devsize);
            }
            assert(devsize > 0);
            devsize = devsize - (devsize % MAX_SEGMENT_SIZE);
            size += devsize;
        }
        parameters.NK = size / BLK_SIZE;
        loadgen->initParam(parameters); // internally inits mapping
        loadgen->regression(true, false, true, true);
        is_complete = true;
        m_cv.notify_one();
    }

    void execute() {
        loadgen = std::make_unique< G_FileKV >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&FileTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(FileTest, FileTest) { this->execute(); }

struct CacheTest : public testing::Test {
    std::unique_ptr< G_CacheKV > loadgen;

    void execute() {
        loadgen = std::make_unique< G_CacheKV >(parameters.NT);
        loadgen->initParam(parameters);
        LOGINFO("Regression Started");
        loadgen->regression(false, false, false, false);
    }
};

class VolumeLoadTest : public testing::Test {
private:
    std::unique_ptr<G_Volume_Test>  m_loadgen; 
    VolumeManager<IOMgrExecutor>*   m_vol_mgr = nullptr;
    std::mutex                      m_mtx;
    std::condition_variable         m_cv;
    bool                            m_is_complete = false;

private:
    void init_done_cb(std::error_condition err) {
        // internally call VolumeStoreSpec::init_store
        // Need to set NK so that we can generate lba no larger than max vol size;
        parameters.NK = m_vol_mgr->max_vol_blks();
        m_loadgen->initParam(parameters);
        LOGINFO("Starting I/O ...");
        m_loadgen->regression(true, false, false, false);
        LOGINFO("I/O Completed . "); 
        m_is_complete = true;
        m_cv.notify_one();
    }
    
    void join() {
        std::unique_lock<std::mutex>    lk(m_mtx);
        m_cv.wait(lk, [this] {return m_is_complete;});
    }

public:
    void execute() {
        // start iomgr
        // volume store handles verification by itself;
        m_loadgen = std::make_unique<G_Volume_Test>(parameters.NT, false);

        m_vol_mgr = VolumeManager<IOMgrExecutor>::instance();

        // start vol manager which creates a bunch of volumes;
        m_vol_mgr->start(parameters.enable_write_log, m_loadgen->get_executor(), 
                std::bind(&VolumeLoadTest::init_done_cb, this, std::placeholders::_1));

        // wait for loadgen to finish
        join();
        
        m_vol_mgr->stop();

        VolumeManager<IOMgrExecutor>::del_instance();
    }
};

TEST_F(VolumeLoadTest, VolumeTest) {
    this->execute();
}

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
    (enable_write_log, "", "enable_write_log", "enable write log persistence", ::cxxopts::value< uint8_t >()->default_value("0"), "number"),
    (workload_shift_time, "", "workload_shift_time", "time in sec to shift workload",
     ::cxxopts::value< uint64_t >()->default_value("3600"), "number"),
    (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service", cxxopts::value<int32_t>()->default_value("5001"), "port"),
    (files, "", "input-files", "Do IO on a set of files", cxxopts::value< std::vector< std::string > >(),"path,[path,...]"))

SDS_OPTIONS_ENABLE(logging, test_load)

// TODO: VolumeTest couldn't be started after MapSSDTest. Seems because of the http server can't be started because of bing to the same port 5001
int main(int argc, char* argv[]) {
    ::testing::GTEST_FLAG(filter) = "*Map*:*Cache*";
    testing::InitGoogleTest(&argc, argv);

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
    parameters.enable_write_log = SDS_OPTIONS["enable_write_log"].as< uint8_t >();

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
#ifndef DEBUG
    same_value_gen = true;
#endif

    if (SDS_OPTIONS.count("input-files")) {
        for (auto const& path : SDS_OPTIONS["input-files"].as< std::vector< std::string > >()) {
            parameters.file_names.push_back(path);
        }
        /* We don't support more then one file */
        assert(parameters.file_names.size() == 1);
    }
    assert(parameters.WARM_UP_KEYS <=
           parameters.NK); // this is required as we set MAX_KEYS in key spec as per value of NK
           
    return RUN_ALL_TESTS();
}
