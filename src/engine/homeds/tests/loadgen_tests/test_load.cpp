#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

#ifdef __linux__
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#endif

#include <metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/obj_life_counter.hpp>
#include <sisl/utility/thread_buffer.hpp>

#include <gtest/gtest.h>

#include "disk_initializer.hpp"
#include "homeblks/volume/mapping.hpp"
#include "homeds/loadgen/iomgr_executor.hpp"
#include "homeds/loadgen/loadgen.hpp"
#include "homeds/loadgen/keyset.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "loadgen_crud_suite.hpp"
#include "keyspecs/cache_key_spec.hpp"
#include "keyspecs/logstore_key_spec.hpp"
#include "keyspecs/map_key_spec.hpp"
#include "keyspecs/simple_key_spec.hpp"
#include "keyspecs/var_key_spec.hpp"
#include "keyspecs/vdev_key_spec.hpp"
#include "keyspecs/vol_key_spec.hpp"
#include "storespecs/cache_store_spec.hpp"
#include "storespecs/file_store_spec.hpp"
#include "storespecs/log_store_spec.hpp"
#include "storespecs/map_store_spec.hpp"
#include "storespecs/membtree_store_spec.hpp"
#include "storespecs/ssdbtree_store_spec.hpp"
#include "storespecs/vdev_prw_store_spec.hpp"
#include "storespecs/vdev_rw_store_spec.hpp"
#include "storespecs/volume_store_spec.hpp"
#include "valuespecs/blk_value_spec.hpp"
#include "valuespecs/cache_value_spec.hpp"
#include "valuespecs/fixedbyte_value_spec.hpp"
#include "valuespecs/logstore_value_spec.hpp"
#include "valuespecs/map_value_spec.hpp"
#include "valuespecs/var_value_spec.hpp"
#include "valuespecs/vdev_value_spec.hpp"
#include "valuespecs/vol_value_spec.hpp"

#ifndef DEBUG
extern bool same_value_gen;
#endif
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

RCU_REGISTER_INIT

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

#define G_Volume_Test BtreeLoadGen< VolumeKey, VolumeValue, VolumeStoreSpec< VolumeKey, VolumeValue >, IOMgrExecutor >

#define G_FileKV BtreeLoadGen< MapKey, BlkValue, FileStoreSpec, IOMgrExecutor >

#define G_VDev_Test_PRW BtreeLoadGen< VDevKey, VDevValue, VDevPRWStoreSpec, IOMgrExecutor >

#define G_VDev_Test_RW BtreeLoadGen< SimpleNumberKey, VDevValue, VDevRWStoreSpec, IOMgrExecutor >

#define G_LogStore_Test BtreeLoadGen< LogStoreKey, LogStoreValue, LogStoreSpec, IOMgrExecutor >

namespace {
Param parameters;
bool loadgen_verify_mode{false};
} // namespace

struct BtreeTest : public ::testing::Test {
public:
    BtreeTest() = default;
    BtreeTest(const BtreeTest&) = delete;
    BtreeTest& operator=(const BtreeTest&) = delete;
    BtreeTest(BtreeTest&&) noexcept = delete;
    BtreeTest& operator=(BtreeTest&&) noexcept = delete;
    virtual ~BtreeTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_SimpleKV_Mem > loadgen;

protected:
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
class SSDBtreeTest : public ::testing::Test {
public:
    SSDBtreeTest() = default;
    SSDBtreeTest(const SSDBtreeTest&) = delete;
    SSDBtreeTest& operator=(const SSDBtreeTest&) = delete;
    SSDBtreeTest(SSDBtreeTest&&) noexcept = delete;
    SSDBtreeTest& operator=(SSDBtreeTest&&) noexcept = delete;
    virtual ~SSDBtreeTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_SimpleKV_SSD > loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        loadgen = std::make_unique< G_SimpleKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&SSDBtreeTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(SSDBtreeTest, SimpleKVSSDTest) { this->execute(); }

class SSDBtreeVarKVTest : public ::testing::Test {
public:
    SSDBtreeVarKVTest() = default;
    SSDBtreeVarKVTest(const SSDBtreeVarKVTest&) = delete;
    SSDBtreeVarKVTest& operator=(const SSDBtreeVarKVTest&) = delete;
    SSDBtreeVarKVTest(SSDBtreeVarKVTest&&) noexcept = delete;
    SSDBtreeVarKVTest& operator=(SSDBtreeVarKVTest&&) noexcept = delete;
    virtual ~SSDBtreeVarKVTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_VarKV_SSD > loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        loadgen = std::make_unique< G_VarKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&SSDBtreeVarKVTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(SSDBtreeVarKVTest, VarKVSSDTest) { this->execute(); }

class MapTest : public ::testing::Test {
public:
    MapTest() = default;
    MapTest(const MapTest&) = delete;
    MapTest& operator=(const MapTest&) = delete;
    MapTest(MapTest&&) noexcept = delete;
    MapTest& operator=(MapTest&&) noexcept = delete;
    virtual ~MapTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    DiskInitializer< IOMgrExecutor > di;
    std::unique_ptr< G_MapKV_SSD > loadgen;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters); // internally inits mapping
        loadgen->specific_tests(SPECIFIC_TEST::MAP);
        LOGINFO("Regression Started");
        loadgen->regression(true, false, true, true);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        loadgen = std::make_unique< G_MapKV_SSD >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&MapTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2), 512);
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(MapTest, MapSSDTest) { this->execute(); }

class FileTest : public ::testing::Test {
public:
    FileTest() = default;
    FileTest(const FileTest&) = delete;
    FileTest& operator=(const FileTest&) = delete;
    FileTest(FileTest&&) noexcept = delete;
    FileTest& operator=(FileTest&&) noexcept = delete;
    virtual ~FileTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_FileKV > loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->specific_tests(SPECIFIC_TEST::MAP);
        LOGINFO("Regression Started");
        size_t size{0};
        for (size_t i{0}; i < parameters.file_names.size(); ++i) {
            const int fd{::open(parameters.file_names[i].c_str(), O_RDWR)};
            struct stat buf;
            uint64_t devsize{0};
            if (::fstat(fd, &buf) >= 0) {
                devsize = buf.st_size;
            } else {
                ::ioctl(fd, BLKGETSIZE64, &devsize);
            }
            assert(devsize > 0);
            devsize = devsize - (devsize % FileStoreSpec::MAX_SEGMENT_SIZE);
            size += devsize;
        }
        parameters.NK = size / BlkValue::BLK_SIZE;
        loadgen->initParam(parameters); // internally inits mapping
        loadgen->regression(true, false, true, true);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        loadgen = std::make_unique< G_FileKV >(parameters.NT); // starts iomgr
        di.init(loadgen->get_executor(),
                std::bind(&FileTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(FileTest, FileTest) { this->execute(); }

class VDevTest_RW : public ::testing::Test {
public:
    VDevTest_RW() = default;
    VDevTest_RW(const VDevTest_RW&) = delete;
    VDevTest_RW& operator=(const VDevTest_RW&) = delete;
    VDevTest_RW(VDevTest_RW&&) noexcept = delete;
    VDevTest_RW& operator=(VDevTest_RW&&) noexcept = delete;
    virtual ~VDevTest_RW() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_VDev_Test_RW > loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters);
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        // disable verfication for vdev test
        parameters.NT = 1; // vdev APIs are not thread-safe;
        loadgen = std::make_unique< G_VDev_Test_RW >(parameters.NT, false);
        di.init(loadgen->get_executor(),
                std::bind(&VDevTest_RW::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(VDevTest_RW, VDevTest_RW) { this->execute(); }

class VDevTest_PRW : public ::testing::Test {
public:
    VDevTest_PRW() = default;
    VDevTest_PRW(const VDevTest_PRW&) = delete;
    VDevTest_PRW& operator=(const VDevTest_PRW&) = delete;
    VDevTest_PRW(VDevTest_PRW&&) noexcept = delete;
    VDevTest_PRW& operator=(VDevTest_PRW&&) noexcept = delete;
    virtual ~VDevTest_PRW() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_VDev_Test_PRW > loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters);
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        // disable verfication for vdev test
        parameters.NT = 1; // vdev APIs are not thread-safe;
        loadgen = std::make_unique< G_VDev_Test_PRW >(parameters.NT, false);
        di.init(loadgen->get_executor(),
                std::bind(&VDevTest_PRW::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(VDevTest_PRW, VDevTest_PRW) { this->execute(); }

class CacheTest : public ::testing::Test {
public:
    CacheTest() = default;
    CacheTest(const CacheTest&) = delete;
    CacheTest& operator=(const CacheTest&) = delete;
    CacheTest(CacheTest&&) noexcept = delete;
    CacheTest& operator=(CacheTest&&) noexcept = delete;
    virtual ~CacheTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_CacheKV > loadgen;

protected:
    void execute() {
        loadgen = std::make_unique< G_CacheKV >(parameters.NT);
        loadgen->initParam(parameters);
        LOGINFO("Regression Started");
        loadgen->regression(false, false, false, false);
    }
};

TEST_F(CacheTest, CacheMemTest) { this->execute(); }

class VolumeLoadTest : public ::testing::Test {
public:
    VolumeLoadTest() = default;
    VolumeLoadTest(const VolumeLoadTest&) = delete;
    VolumeLoadTest& operator=(const VolumeLoadTest&) = delete;
    VolumeLoadTest(VolumeLoadTest&&) noexcept = delete;
    VolumeLoadTest& operator=(VolumeLoadTest&&) noexcept = delete;
    virtual ~VolumeLoadTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override{};

private:
    std::unique_ptr< G_Volume_Test > m_loadgen;
    VolumeManager< IOMgrExecutor >* m_vol_mgr = nullptr;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool m_is_complete{false};

    void init_done_cb(const std::error_condition err) {
        // internally call VolumeStoreSpec::init_store
        // Need to set NK so that we can generate lba no larger than max vol size;
        parameters.NK = m_vol_mgr->max_vol_blks();
        m_loadgen->initParam(parameters);
        LOGINFO("Starting I/O ...");
        m_loadgen->regression(true, false, false, false);
        LOGINFO("I/O Completed . ");
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            m_is_complete = true;
        }
        m_cv.notify_one();
    }

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return m_is_complete; });
    }

protected:
    void execute() {
        // start iomgr
        // volume store handles verification by itself;
        m_loadgen = std::make_unique< G_Volume_Test >(parameters.NT, false);

        m_vol_mgr = VolumeManager< IOMgrExecutor >::instance();

        const uint64_t num_vols{SISL_OPTIONS["num_vols"].as< uint64_t >()};
        m_vol_mgr->set_max_vols(num_vols);

        // start vol manager which creates a bunch of volumes;
        m_vol_mgr->start(parameters.enable_write_log, m_loadgen->get_executor(),
                         std::bind(&VolumeLoadTest::init_done_cb, this, std::placeholders::_1));

        // wait for loadgen to finish
        join();

        // call executor stop here to wake up the threads blocking on reading the queue;
        // need this with new iomgr so that vol ref can be released before we call shutdown.
        m_loadgen->get_executor().stop();

        m_vol_mgr->stop();

        VolumeManager< IOMgrExecutor >::del_instance();
    }
};

TEST_F(VolumeLoadTest, VolumeTest) { this->execute(); }

class LogStoreLoadTest : public ::testing::Test {
public:
    LogStoreLoadTest() = default;
    LogStoreLoadTest(const LogStoreLoadTest&) = delete;
    LogStoreLoadTest& operator=(const LogStoreLoadTest&) = delete;
    LogStoreLoadTest(LogStoreLoadTest&&) noexcept = delete;
    LogStoreLoadTest& operator=(LogStoreLoadTest&&) noexcept = delete;
    virtual ~LogStoreLoadTest() override = default;

protected:
    virtual void SetUp() override{};
    virtual void TearDown() override { loadgen.reset(); };

private:
    std::unique_ptr< G_LogStore_Test > loadgen;
    DiskInitializer< IOMgrExecutor > di;
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool is_complete{false};

    void join() {
        std::unique_lock< std::mutex > lk{m_mtx};
        m_cv.wait(lk, [this] { return is_complete; });
    }

    void init_done_cb(const std::error_condition err, const homeds::out_params& params1) {
        loadgen->initParam(parameters);
        LOGINFO("Regression Started");
        loadgen->regression(true, false, false, false);
        {
            std::unique_lock< std::mutex > lk{m_mtx};
            is_complete = true;
        }
        m_cv.notify_one();
    }

protected:
    void execute() {
        // disable verification because it is async write, similar as volume test load;
        // verification will be done by logstore spec;
        loadgen = std::make_unique< G_LogStore_Test >(parameters.NT, false);
        di.init(loadgen->get_executor(),
                std::bind(&LogStoreLoadTest::init_done_cb, this, std::placeholders::_1, std::placeholders::_2));
        join(); // sync wait for test to finish
        di.cleanup();
    }
};

TEST_F(LogStoreLoadTest, LogStoreTest) { this->execute(); }

SISL_OPTION_GROUP(
    test_load, (num_io, "", "num_io", "num of io", ::cxxopts::value< uint64_t >()->default_value("1000"), "number"),
    (run_time, "", "run_time", "time to run in seconds", ::cxxopts::value< uint64_t >()->default_value("60"), "number"),
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
    (num_threads, "", "num_threads", "num of threads", ::cxxopts::value< uint8_t >()->default_value("2"), "number"),
    (enable_write_log, "", "enable_write_log", "enable write log persistence",
     ::cxxopts::value< uint8_t >()->default_value("0"), "number"),
    (workload_shift_time, "", "workload_shift_time", "time in sec to shift workload",
     ::cxxopts::value< uint64_t >()->default_value("3600"), "number"),
    (files, "", "input-files", "Do IO on a set of files", cxxopts::value< std::vector< std::string > >(),
     "path,[path,...]"),
    (num_vols, "", "num_vols", "number of vols to create", ::cxxopts::value< uint64_t >()->default_value("50"),
     "number"))

SISL_OPTIONS_ENABLE(logging, test_load)

// TODO: VolumeTest couldn't be started after MapSSDTest. Seems because of the http server can't be started because of
// bing to the same port 5001
int main(int argc, char* argv[]) {
    ::testing::GTEST_FLAG(filter) = "*Map*:*Cache*";
    ::testing::InitGoogleTest(&argc, argv);

    SISL_OPTIONS_LOAD(argc, argv, logging, test_load)
    sisl::logging::SetLogger("test_load");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    parameters.NIO = SISL_OPTIONS["num_io"].as< uint64_t >();
    parameters.NK = SISL_OPTIONS["num_keys"].as< uint64_t >();
    parameters.PC = SISL_OPTIONS["per_create"].as< uint64_t >();
    parameters.PR = SISL_OPTIONS["per_read"].as< uint64_t >();
    parameters.PU = SISL_OPTIONS["per_update"].as< uint64_t >();
    parameters.PD = SISL_OPTIONS["per_delete"].as< uint64_t >();
    parameters.NRT = SISL_OPTIONS["run_time"].as< uint64_t >();
    parameters.WST = SISL_OPTIONS["workload_shift_time"].as< uint64_t >();

    parameters.PRU = SISL_OPTIONS["per_range_update"].as< uint64_t >();
    parameters.PRQ = SISL_OPTIONS["per_range_query"].as< uint64_t >();
    parameters.PRINT_INTERVAL = SISL_OPTIONS["print_interval"].as< uint64_t >();
    parameters.WARM_UP_KEYS = SISL_OPTIONS["warm_up_keys"].as< uint64_t >();
    parameters.NT = SISL_OPTIONS["num_threads"].as< uint8_t >();
    parameters.enable_write_log = SISL_OPTIONS["enable_write_log"].as< uint8_t >();

    if (parameters.PC + parameters.PR + parameters.PU + parameters.PD + parameters.PRU + parameters.PRQ != 100) {
        LOGERROR("percent should total to 100");
        return 1;
    }
    parameters.PR += parameters.PC;
    parameters.PU += parameters.PR;
    parameters.PD += parameters.PU;
    parameters.PRU += parameters.PD;
    parameters.PRQ = 100;
#ifndef DEBUG
    same_value_gen = true;
#endif

    /* disable the watch dog timer for this testing */
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) { s.generic.cp_watchdog_timer_sec = 50000; });
    HS_SETTINGS_FACTORY().save();
    if (SISL_OPTIONS.count("input-files")) {
        for (auto const& path : SISL_OPTIONS["input-files"].as< std::vector< std::string > >()) {
            parameters.file_names.push_back(path);
        }
        /* We don't support more then one file */
        assert(parameters.file_names.size() == 1);
    }
    assert(parameters.WARM_UP_KEYS <=
           parameters.NK); // this is required as we set MAX_KEYS in key spec as per value of NK

    const int result{RUN_ALL_TESTS()};
    return result;
}
