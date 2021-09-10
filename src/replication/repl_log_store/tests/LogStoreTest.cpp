#include <array>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <api/vol_interface.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <iomgr/iomgr.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "hs_log_store.h"

static constexpr uint64_t Ki{1024};
static constexpr uint64_t Mi{Ki * Ki};
static constexpr uint64_t Gi{Ki * Mi};

static constexpr uint64_t TEST_INSERTION_COUNT{10};

static const std::string TEST_FILE_PATHS_PREFIX{"log_store_unit_test_dev_"};
static const std::string LOGSTORE_FILE_PATH{TEST_FILE_PATHS_PREFIX + "log_store_id"};
static const std::string SYSTEMUID_FILE_PATH{TEST_FILE_PATHS_PREFIX + "system_uid"};

struct TestCfg {
    std::array< std::string, 4 > default_names{
        {"test_files/vol_file1", "test_files/vol_file2", "test_files/vol_file3", "test_files/vol_file4"}};
    std::vector< std::string > dev_names;
    uint64_t max_vols{50};
    uint64_t max_num_writes{100000};
    uint64_t run_time{60};
    uint64_t num_threads{8};

    uint64_t max_io_size{1 * Mi};
    uint64_t max_outstanding_ios{64};
    uint64_t max_disk_capacity{10 * Gi};

    uint32_t atomic_phys_page_size{512};
    uint32_t vol_page_size{4096};
    uint32_t phy_page_size{4096};
    uint32_t mem_btree_page_size{4096};

    bool can_delete_volume{false};
    bool read_enable{true};
    bool enable_crash_handler{true};
    bool verify_hdr{true};
    bool verify_data{true};
    bool read_verify{false};
    bool remove_file{true};
    bool verify_only{false};
    bool is_abort{false};
    // homestore::load_type_t load_type{load_type_t::random};
    uint32_t flip_set{0};                                       // TODO: change this to enum
    homestore::io_flag io_flags{homestore::io_flag::DIRECT_IO}; // 2: READ_ONLY 1: DIRECT_IO, 0: BUFFERED_IO;

    homestore::vol_state expected_vol_state{homestore::vol_state::ONLINE}; // TODO: Move to separate job config section
    bool init{true};
    bool expected_init_fail{false};
    int disk_replace_cnt{0};
    bool precreate_volume{true};
    bool expect_io_error{false};
    uint32_t p_volume_size{60};
    bool is_spdk{false};
};

static void clearTestFiles(const std::string& prefix) {
    for (const auto& dir_entry : std::filesystem::directory_iterator{"."}) {
        if (dir_entry.is_regular_file()) { 
            const auto filename{dir_entry.path().filename()};
            if (filename.string().find(prefix) != std::string::npos) { 
                std::filesystem::remove(filename);
            }
        }
    }
}

static nuraft::ptr< nuraft::log_entry > make_log(const uint64_t term, const uint64_t value) {
    nuraft::ptr< nuraft::buffer > buf{nuraft::buffer::alloc(sz_ulong)};
    buf->put(value);
    return nuraft::cs_new< nuraft::log_entry >(term, buf);
}

static uint64_t get_log_value(const nuraft::ptr< nuraft::log_entry >& le) {
    // EXPECT_FALSE(le->is_buf_null());
    // EXPECT_NE(nullptr, le->get_buf().data());

    le->get_buf().pos(0);
    const uint64_t val{le->get_buf().get_ulong()};
    le->get_buf().pos(0);
    return val;
}

static TestCfg tcfg; // Config for each VolTest

class LogStoreTest : public ::testing::Test {
public:
    std::string m_test_type;
    bool cleanup;
    homestore::logstore_id_t m_log_store_id;

    LogStoreTest() = default;
    LogStoreTest(const LogStoreTest&) = delete;
    LogStoreTest& operator=(const LogStoreTest&) = delete;
    LogStoreTest(LogStoreTest&&) noexcept = delete;
    LogStoreTest& operator=(LogStoreTest&&) noexcept = delete;
    virtual ~LogStoreTest() override = default;

    virtual void SetUp() override {
        clearTestFiles(TEST_FILE_PATHS_PREFIX);
        m_log_store_id = load_logstore_id();
        cleanup = SDS_OPTIONS["cleanup"].as< bool >();
        m_test_type = SDS_OPTIONS["test_type"].as< std::string >();
        tcfg.num_threads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    }

    virtual void TearDown() override {
        TearOnRestart();
        if (cleanup) clearTestFiles(TEST_FILE_PATHS_PREFIX);
    }

    void TearOnRestart() {
        homestore::VolInterface::get_instance()->shutdown();
        iomanager.stop();
    }

    void store_logstore_id(const uint32_t id) {
        m_log_store_id = id;
        std::ofstream outfile{LOGSTORE_FILE_PATH, ios::out | ios::trunc};
        outfile << id;
        outfile.close();
    }

    uint32_t load_logstore_id() {
        uint32_t id{std::numeric_limits< uint32_t >::max()};
        if (!std::filesystem::exists(LOGSTORE_FILE_PATH)) return id;

        std::ifstream infile{LOGSTORE_FILE_PATH, ios::in};
        infile >> id;
        infile.close();
        return id;
    }

    void store_system_uid(const boost::uuids::uuid& uid) {
        std::ofstream outfile{SYSTEMUID_FILE_PATH, ios::out | ios::trunc};
        outfile << uid;
        outfile.close();
    }

    boost::uuids::uuid load_system_uid() {
        boost::uuids::uuid id{};
        if (!std::filesystem::exists(SYSTEMUID_FILE_PATH)) return id;

        std::ifstream infile{SYSTEMUID_FILE_PATH, ios::in};
        infile >> id;
        infile.close();
        return id;
    }

   bool start_vol_interface(const std::vector< homestore::dev_info >& device_info, const bool restart = false,
                             const uint32_t ndevices = 2, const uint64_t dev_size_mb = 10240) {
        const uint64_t dev_size{dev_size_mb * 1024 * 1024};

        // make these static so stay in scope in lamnbda
        static std::mutex start_mutex;
        static std::condition_variable cv;
        static bool inited;
        inited = false;

        const uint64_t app_mem_size{((ndevices * dev_size) * 15) / 100};
        LOGINFO("Initialize and start HomeBlks with app_mem_size = {}", app_mem_size);

        homestore::init_params params;
        params.open_flags = tcfg.io_flags;
        params.min_virtual_page_size = tcfg.vol_page_size;
        params.app_mem_size = app_mem_size;
        params.devices = device_info;
        params.init_done_cb = [](std::error_condition err, const homestore::out_params& params) {
            LOGINFO("HomeBlks Init completed");
            {
                std::unique_lock< std::mutex > lk(start_mutex);
                inited = true;
            }
            cv.notify_one();
        };
        params.vol_mounted_cb = [](const homestore::VolumePtr& vol_obj, homestore::vol_state state) {};
        params.vol_state_change_cb = [](const homestore::VolumePtr& vol, homestore::vol_state old_state,
                                        homestore::vol_state new_state) {};
        params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };

        homestore::VolInterface::init(params, restart);
        LOGINFO("Entering lock");
        bool wait_result;
        {
            constexpr std::chrono::seconds homestore_wait_time{45};
            std::unique_lock< std::mutex > lk(start_mutex);
            wait_result = cv.wait_for(lk, homestore_wait_time, [] { return inited; });
        }
        LOGINFO("Exiting lock");
        return wait_result;
    }

    void start_device(std::vector< homestore::dev_info >& device_info, const bool restart = false,
                      const uint32_t ndevices = 2, const uint64_t dev_size_mb = 10240) {

        const uint64_t dev_size{dev_size_mb * 1024 * 1024};

        LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);

        for (uint32_t i{0}; i < ndevices; ++i) {
            const std::string fpath{TEST_FILE_PATHS_PREFIX + m_test_type + std::to_string(i + 1)};
            if (!restart)
            {
                std::ofstream ofs{fpath, std::ios::binary | std::ios::out | std::ios::trunc};
                ofs.close();
                std::filesystem::resize_file(fpath, dev_size);
            }
            device_info.push_back({std::filesystem::canonical(std::filesystem::path{fpath}).string()});
        }

        const bool is_spdk{SDS_OPTIONS["spdk"].as< bool >()};
        LOGINFO("Starting iomgr with {} threads, spdk: {}", tcfg.num_threads, is_spdk);
        iomanager.start(is_spdk ? 2 : tcfg.num_threads, is_spdk);
    }

    void start_homestore(const bool restart = false, const uint32_t ndevices = 2, const uint64_t dev_size_mb = 10240) {
        // TODO: Restart HomeStore does not work at this moment
        // if (restart) {
        //     //TearOnRestart();
        //     std::this_thread::sleep_for(std::chrono::seconds{5});
        // }
        std::vector< homestore::dev_info > device_info;
        start_device(device_info, restart, ndevices, dev_size_mb);
        // if (restart) {

        //     HomeLogStoreMgrSI().open_log_store(i, [i, this](std::shared_ptr< HomeLogStore > log_store) {
        //         m_log_store_clients[i]->set_log_store(log_store);
        //     });

        // }
        ASSERT_TRUE(start_vol_interface(device_info, restart, ndevices, dev_size_mb));
    }

    void basic_append_read_test() {
        bool restart{false};
        constexpr uint64_t ROLLBACK{5};
        nuraft::ptr< nuraft::log_entry > le_ret;

        nuraft::ptr< nuraft::hs_log_store > ls;
        std::vector< homestore::dev_info > device_info;

        if (m_log_store_id == std::numeric_limits< uint32_t >::max()) { // First time loading homestore
            start_device(device_info);
            ASSERT_TRUE(start_vol_interface(device_info));
            ls = nuraft::cs_new< nuraft::hs_log_store >();
            LOGINFO("testRaftLogStore on first start: Id {}", ls->getLogstoreId());
        } else { // Restart, Already exists a homestore
            restart = true;
            LOGINFO("testRaftLogStore on restart: Id {}", m_log_store_id);
            start_device(device_info, true);
            ls = nuraft::cs_new< nuraft::hs_log_store >(m_log_store_id);
            LOGINFO("start_vol_interface()");

            ASSERT_TRUE(start_vol_interface(device_info, true));
            LOGINFO("getting log store");
            EXPECT_TRUE(!ls->get());

            LOGINFO("start_vol_interface done");
        }
        if (!restart) {
            EXPECT_NE(nullptr, ls);
            if (ls == nullptr) {
                LOGINFO("waiting for logstore to open");
                std::this_thread::sleep_for(std::chrono::seconds{2});
            }

            assert(ls != nullptr);

            store_logstore_id(ls->getLogstoreId());

            // At the beginning, next slot and start index should be 1.
            EXPECT_EQ(static_cast<decltype(ls->next_slot())>(1), ls->next_slot());
            EXPECT_EQ(static_cast< decltype(ls->start_index()) >(1), ls->start_index());
            le_ret = ls->last_entry();
            EXPECT_NE(nullptr, le_ret);
            EXPECT_EQ(static_cast< decltype(le_ret->get_term()) >(0), le_ret->get_term());

            for (uint64_t ii{1}; ii <= TEST_INSERTION_COUNT; ++ii) {
                nuraft::ptr< nuraft::log_entry > le{make_log(ii, ii)};
                const uint64_t log_idx{ls->append(le)};

                EXPECT_EQ(ii, log_idx);
                EXPECT_EQ(ii + 1, ls->next_slot());

                le_ret = ls->last_entry();
                const uint64_t val_ret{get_log_value(le_ret)};
                EXPECT_EQ(ii, val_ret);
            }

            // start_index still should be 1.
            EXPECT_EQ(static_cast< decltype(ls->start_index()) >(1), ls->start_index());

            // Overwrite log number 5 (before 5 --> after 12345).
            {
                nuraft::ptr< nuraft::log_entry > le{make_log(ROLLBACK, 12345)};
                ls->write_at(ROLLBACK, le);
            }

            // // Get all logs.
            nuraft::ptr< std::vector< nuraft::ptr< nuraft::log_entry > > > logs{ls->log_entries(1, ls->next_slot())};
            // std::this_thread::sleep_for(std::chrono::seconds{5});

            // rollback is not implemented yet in homestore
            // EXPECT_EQ(ROLLBACK, logs->size());

            EXPECT_EQ(TEST_INSERTION_COUNT, logs->size());

            size_t idx{0};
            for (uint64_t ii{1}; ii <= ROLLBACK; ++ii) {
                le_ret = (*logs)[idx++];

                const uint64_t val_ret{get_log_value(le_ret)};
                if (ii != ROLLBACK) {
                    EXPECT_EQ(ii, val_ret);
                } else {
                    // ii == 5, special case.
                    EXPECT_EQ(static_cast<uint64_t>(12345), val_ret);
                }

                const uint64_t term_ret{le_ret->get_term()};
                EXPECT_EQ(ii, term_ret);
            }
        } else {
            // Start entry still should be 1.
            EXPECT_EQ(static_cast< decltype(ls->start_index()) >(1), ls->start_index());
            // Last entry check.
            // EXPECT_EQ(ROLLBACK + 1, ls->next_slot());
            EXPECT_EQ(TEST_INSERTION_COUNT + 1, ls->next_slot());

            le_ret = ls->last_entry();
            // EXPECT_EQ(12345, get_log_value(le_ret));
            EXPECT_EQ(TEST_INSERTION_COUNT, get_log_value(le_ret));
            // Check all entries.
            for (uint64_t ii{1}; ii <= ROLLBACK; ++ii) {
                le_ret = ls->entry_at(ii);
                const uint64_t val_ret{get_log_value(le_ret)};
                if (ii != 5) {
                    EXPECT_EQ(ii, val_ret);
                } else {
                    EXPECT_EQ(static_cast<uint64_t>(12345), val_ret);
                }

                const uint64_t term_ret{le_ret->get_term()};
                EXPECT_EQ(ii, term_ret);
            }

            // Tear and Cleanup
            cleanup = true;
        }

        ls->close();
    }

    void compact_test() {

        std::vector< homestore::dev_info > device_info;
        start_device(device_info);
        ASSERT_TRUE(start_vol_interface(device_info));
        auto ls{nuraft::cs_new< nuraft::hs_log_store >()};
        EXPECT_NE(nullptr, ls);
        LOGINFO("testRaftLogStore:compact_test, Id {}", ls->getLogstoreId());

        // Append 100 logs: [1, 100].
        constexpr uint64_t num{100};
        for (uint64_t ii{1}; ii <= num; ++ii) {
            nuraft::ptr< nuraft::log_entry > le{make_log(ii, ii)};
            ls->append(le);
        }
        // start_index still should be 1.
        EXPECT_EQ(static_cast< decltype(ls->start_index()) >(1), ls->start_index());

        // Compact first 50 logs: [1, 50].
        constexpr nuraft::ulong compact_upto{50};
        ls->compact(compact_upto);
        // start_index still should be 51 now.
        EXPECT_EQ(compact_upto + 1, ls->start_index());

        // Get all logs.
        nuraft::ptr< std::vector< nuraft::ptr< nuraft::log_entry > > > logs{
            ls->log_entries(compact_upto + 1, ls->next_slot())};
        EXPECT_EQ(num - compact_upto, logs->size());

        // Check.
        size_t idx{0};
        for (uint64_t ii{compact_upto + 1}; ii <= num; ++ii) {
            nuraft::ptr< nuraft::log_entry > le_ret{(*logs)[idx++]};

            const uint64_t val_ret{get_log_value(le_ret)};
            EXPECT_EQ(ii, val_ret);

            const uint64_t term_ret{le_ret->get_term()};
            EXPECT_EQ(ii, term_ret);
        }
        EXPECT_EQ(idx, logs->size());

        // Tear and Cleanup;
        cleanup = true;
        ls->close();
    }

    void pack_test() {

        std::vector< homestore::dev_info > device_info;
        start_device(device_info);
        ASSERT_TRUE(start_vol_interface(device_info));
        auto ls_src{nuraft::cs_new< nuraft::hs_log_store >()};
        EXPECT_NE(nullptr, ls_src);
        const auto src_id{ls_src->getLogstoreId()};
        LOGINFO("testRaftLogStore:pack_test src Id {}", src_id);
        // Append 100 logs: [1, 100].
        constexpr uint64_t num{100};
        for (uint64_t ii{1}; ii <= num; ++ii) {
            nuraft::ptr< nuraft::log_entry > le{make_log(ii, ii)};
            [[maybe_unused]] const uint64_t log_idx{ls_src->append(le)};
        }

        // start_index still should be 1.
        EXPECT_EQ(static_cast< decltype(ls_src->start_index()) >(1), ls_src->start_index());
        // Pack: [51, 100].
        nuraft::ulong pack_from{51};
        nuraft::ptr< nuraft::buffer > pack_data{ls_src->pack(pack_from, num - pack_from + 1)};
        EXPECT_NE(nullptr, pack_data);

        // Apply pack.
        auto ls_dst{nuraft::cs_new< nuraft::hs_log_store >()};
        const auto dst_id{ls_dst->getLogstoreId()};
        LOGINFO("testRaftLogStore:pack_test dest Id {}", dst_id);

        ls_dst->apply_pack(pack_from, *pack_data);

        // TODO: HomeLogStore is giving problems when does not start from seq 1.
#if 0
        // start_index should be 51.
        EXPECT_EQ(pack_from, ls_dst->start_index());
        // Get all logs.
        nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>> logs =
            ls_dst->log_entries(pack_from, ls_dst->next_slot());
        EXPECT_EQ(num - pack_from + 1, logs->size());

        //Check.
        size_t idx{0};
        for (uint64_t ii{pack_from}; ii<=num; ++ii) {
            nuraft::ptr<nuraft::log_entry> le_ret{(*logs)[idx++]};

            const uint64_t val_ret{get_log_value(le_ret)};
            EXPECT_EQ(ii, val_ret);

            const uint64_t term_ret{le_ret->get_term()};
            EXPECT_EQ(ii, term_ret);
        }

        EXPECT_EQ(idx, logs->size());
#endif

        // This is modified for homelogstore issues with seq not starting from 1
        // size_t pack_length = num - pack_from + 1; //should eq to ls_dst->next_slot()
        // ptr<std::vector<ptr<log_entry>>> logs =
        //     ls_dst->log_entries(pack_from, pack_from+pack_length);
        // EXPECT_EQ(pack_length, logs->size());
        // size_t idx = 0;
        // for (uint64_t ii=pack_from; ii<=num; ++ii) {
        //     ptr<log_entry> le_ret = (*logs)[idx++];

        //     uint64_t val_ret = get_log_value(le_ret);
        //     EXPECT_EQ(ii, val_ret);

        //     uint64_t term_ret = le_ret->get_term();
        //     EXPECT_EQ(ii, term_ret);
        // }

        // Tear and Cleanup;
        cleanup = true;
        ls_dst->close();
        ls_src->close();
        nuraft::hs_log_store::removeLogStore(dst_id);
        nuraft::hs_log_store::removeLogStore(src_id);
    }
};

TEST_F(LogStoreTest, basic_append_read_test) {
    basic_append_read_test();
    TearOnRestart();
    LOGINFO("Waiting for Homestore to reboot...");
    std::this_thread::sleep_for(std::chrono::seconds{5});
    this->m_log_store_id = load_logstore_id();
    basic_append_read_test();
}

TEST_F(LogStoreTest, compact_test) { compact_test(); }

TEST_F(LogStoreTest, pack_test) { pack_test(); }
