#include <gtest/gtest.h>
#include "../log_store.hpp"
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include <algorithm> // std::shuffle
#include <random>    // std::default_random_engine
#include <chrono>    // std::chrono::system_clock

using namespace homestore;
THREAD_BUFFER_INIT;
SDS_LOGGING_INIT(test_log_store, btree_structures, btree_nodes, btree_generics, cache, device, httpserver_lmod, iomgr,
                 varsize_blk_alloc, VMOD_VOL_MAPPING, volume, logdev, flip)

struct test_log_data {
    uint32_t size;
    uint8_t data[0];

    uint32_t total_size() const { return sizeof(test_log_data) + size; }
};

typedef std::function< void(logstore_seq_num_t) > test_log_store_comp_cb_t;

class SampleLogStoreClient {
public:
    SampleLogStoreClient(std::shared_ptr< HomeLogStore > store, const test_log_store_comp_cb_t& cb) {
        m_comp_cb = cb;
        m_log_store = store;
        m_log_store->register_log_found_cb(std::bind(&SampleLogStoreClient::on_log_found, this, std::placeholders::_1,
                                                     std::placeholders::_2, std::placeholders::_3));
    }

    explicit SampleLogStoreClient(const test_log_store_comp_cb_t& cb) :
            SampleLogStoreClient(home_log_store_mgr.create_new_log_store(), cb) {}

    void insert_next_batch(uint32_t batch_size) {
        auto cur_lsn = m_cur_lsn.fetch_add(batch_size);
        insert(cur_lsn, batch_size, false);
    }

    void insert(logstore_seq_num_t start_lsn, int64_t nparallel_count, bool wait_for_completion = true) {
        std::vector< logstore_seq_num_t > lsns;
        lsns.reserve(nparallel_count);

        // Shuffle ids within the range for count
        for (auto lsn = start_lsn; lsn < start_lsn + nparallel_count; ++lsn) {
            lsns.push_back(lsn);
        }
        uint32_t seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::shuffle(lsns.begin(), lsns.end(), std::default_random_engine(seed));

        ASSERT_LT(m_log_store->get_contiguous_issued_seq_num(0), start_lsn + nparallel_count);
        ASSERT_LT(m_log_store->get_contiguous_completed_seq_num(0), start_lsn + nparallel_count);
        for (auto lsn : lsns) {
            auto d = prepare_data(lsn);
            m_log_store->write_async(lsn, {(uint8_t*)d, d->total_size()}, nullptr,
                                     [d, this](logstore_seq_num_t seq_num, bool success, void* ctx) {
                                         free(d);
                                         m_comp_cb(seq_num);
                                     });
        }
    }

    void read_validate(bool expect_all_completed = false) {
        auto trunc_upto = m_log_store->truncated_upto();
        for (auto i = 0; i <= trunc_upto; ++i) {
            ASSERT_THROW(m_log_store->read_sync(i), std::out_of_range)
                << "Expected std::out_of_range exception for lsn=" << m_log_store->get_store_id() << ":" << i
                << " but not thrown";
        }

        auto upto = expect_all_completed ? m_cur_lsn.load() - 1 : m_log_store->get_contiguous_completed_seq_num(0);
        for (auto i = m_log_store->truncated_upto() + 1; i < upto; ++i) {
            try {
                auto b = m_log_store->read_sync(i);
                auto tl = (test_log_data*)b.data();
                ASSERT_EQ(tl->total_size(), b.size())
                    << "Size Mismatch for lsn=" << m_log_store->get_store_id() << ":" << i;
                validate_data(tl, i);
            } catch (const std::exception& e) {
                LOGFATAL("Unexpected out_of_range exception for lsn={}:{}", m_log_store->get_store_id(), i);
            }
        }
    }

    void read(logstore_seq_num_t lsn) {
        ASSERT_GT(lsn, m_truncated_upto_lsn);
        // m_log_store->read(id);
    }

    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
        LOGTRACE("Recovered lsn {} with log data of size {}", lsn, buf.size())
        auto tl = (test_log_data*)buf.data();
        validate_data(tl, lsn);
    }

    void truncate(logstore_seq_num_t lsn) {
        m_log_store->truncate(lsn);
        m_truncated_upto_lsn = lsn;
    }

private:
    test_log_data* prepare_data(logstore_seq_num_t lsn) {
        auto sz = rand() % max_data_size;

        // Generate buffer of randome size and fill with specific data
        auto raw_buf = (uint8_t*)malloc(sizeof(test_log_data) + sz);
        test_log_data* d = new (raw_buf) test_log_data();
        d->size = sz;
        char c = ((lsn % 94) + 33);
        for (auto i = 0u; i < sz; ++i) {
            // Get printable ascii character range
            d->data[i] = c;
        }
        return d;
    }

    void validate_data(test_log_data* d, logstore_seq_num_t lsn) {
        ASSERT_LT(d->size, max_data_size);

        char c = ((lsn % 94) + 33);
        std::string actual = std::string((const char*)&d->data[0], (size_t)d->size);
        std::string expected = std::string((size_t)d->size, c);
        ASSERT_EQ(actual, expected) << "Data mismatch for LSN=" << m_log_store->get_store_id() << ":" << lsn
                                    << " size=" << d->size;
    }

    friend class LogStoreTest;

private:
    test_log_store_comp_cb_t m_comp_cb;
    std::atomic< logstore_seq_num_t > m_truncated_upto_lsn = -1;
    std::atomic< logstore_seq_num_t > m_cur_lsn = 0;
    std::shared_ptr< HomeLogStore > m_log_store;

    static constexpr uint32_t max_data_size = 64;
};

#define sample_db SampleDB::instance()

class SampleDB {
public:
    static SampleDB& instance() {
        static SampleDB inst;
        return inst;
    }

    void start_homestore(uint32_t ndevices, uint64_t dev_size, uint32_t nthreads, uint32_t n_log_stores,
                         bool restart = false) {
        if (restart) { shutdown(); }

        std::vector< dev_info > device_info;
        std::mutex start_mutex;
        std::condition_variable cv;
        bool inited = false;

        LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
        for (uint32_t i = 0; i < ndevices; i++) {
            std::string fpath = "/tmp/" + std::to_string(i + 1);
            if (!restart) {
                std::ofstream ofs(fpath.c_str(), std::ios::binary | std::ios::out);
                ofs.seekp(dev_size - 1);
                ofs.write("", 1);
                ofs.close();
            }
            device_info.push_back({fpath});
        }

        LOGINFO("Starting iomgr with {} threads", nthreads);
        iomanager.start(1 /* total interfaces */, nthreads,
                        std::bind(&SampleDB::on_thread_msg, this, std::placeholders::_1));
        iomanager.add_drive_interface(
            std::dynamic_pointer_cast< iomgr::DriveInterface >(std::make_shared< iomgr::AioDriveInterface >()),
            true /* is_default */);

        if (restart) {
            for (auto i = 0u; i < n_log_stores; ++i) {
                home_log_store_mgr.open_log_store(i, [this](std::shared_ptr< HomeLogStore > log_store) {
                    m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
                        log_store, std::bind(&SampleDB::on_log_insert_completion, this, std::placeholders::_1)));
                });
            }
        }

        uint64_t cache_size = ((ndevices * dev_size) * 10) / 100;
        LOGINFO("Initialize and start HomeBlks with cache_size = {}", cache_size);

        boost::uuids::string_generator gen;
        init_params params;
        params.flag = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.cache_size = cache_size;
        params.disk_init = !restart;
        params.devices = device_info;
        params.is_file = true;
        params.init_done_cb = [&](std::error_condition err, const out_params& params) {
            LOGINFO("HomeBlks Init completed");
            {
                std::unique_lock< std::mutex > lk(start_mutex);
                inited = true;
            }
            cv.notify_all();
        };
        params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
        params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
        params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
        params.system_uuid = gen("01970496-0262-11e9-8eb2-f2801f1b9fd1");
        VolInterface::init(params, !restart);

        std::unique_lock< std::mutex > lk(start_mutex);
        cv.wait(lk, [&] { return inited; });

        if (!restart) {
            for (auto i = 0u; i < n_log_stores; ++i) {
                m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
                    std::bind(&SampleDB::on_log_insert_completion, this, std::placeholders::_1)));
            }
        }
    }

    void shutdown() {
        std::mutex stop_mutex;
        std::condition_variable cv;
        VolInterface::get_instance()->shutdown([&](bool success) { cv.notify_all(); });

        // Wait for the shutdown flag.
        std::unique_lock< std::mutex > lk(stop_mutex);
        cv.wait(lk, [&] { return true; });

        m_log_store_clients.clear();
        VolInterface::del_instance();
        iomanager.stop();
    }

    void on_thread_msg(const iomgr_msg& msg) {
        switch (msg.m_type) {
        case iomgr_msg_type::WAKEUP:
            if (m_on_wakeup_cb) m_on_wakeup_cb();
            break;
        default:
            break;
        }
    }

    void on_log_insert_completion(logstore_seq_num_t lsn) {
        if (m_io_closure) m_io_closure(lsn);
    }

    std::function< void() > m_on_wakeup_cb;
    test_log_store_comp_cb_t m_io_closure;
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;
};

struct LogStoreTest : public testing::Test {
public:
    void init(uint64_t n_total_records) {
        // m_nrecords_waiting_to_issue = std::lround(n_total_records / _batch_size) * _batch_size;
        m_nrecords_waiting_to_issue = n_total_records;
        m_nrecords_waiting_to_complete = 0;
        sample_db.m_on_wakeup_cb = std::bind(&LogStoreTest::do_insert, this);
        sample_db.m_io_closure = std::bind(&LogStoreTest::on_insert_completion, this, std::placeholders::_1);
    }

    void kickstart_inserts(uint32_t batch_size, uint32_t q_depth) {
        m_batch_size = batch_size;
        m_q_depth = q_depth;
        iomanager.send_msg(-1, iomgr_msg(iomgr_msg_type::WAKEUP));
    }

    void do_insert() {
        // Randomly pick a store client and write journal entry batch.
        while ((m_nrecords_waiting_to_issue.load() > 0) && (m_nrecords_waiting_to_complete.load() < m_q_depth)) {
            m_nrecords_waiting_to_issue.fetch_sub(m_batch_size);
            m_nrecords_waiting_to_complete.fetch_add(m_batch_size);
            sample_db.m_log_store_clients[rand() % sample_db.m_log_store_clients.size()]->insert_next_batch(
                m_batch_size);
        }
    }

    void on_insert_completion(logstore_seq_num_t lsn) {
        auto waiting_to_issue = m_nrecords_waiting_to_issue.load();
        if ((m_nrecords_waiting_to_complete.fetch_sub(1) == 1) && (waiting_to_issue == 0)) {
            m_pending_cv.notify_all();
        } else if (waiting_to_issue != 0) {
            do_insert();
        }
    }

    void wait_for_inserts() {
        {
            std::unique_lock< std::mutex > lk(m_pending_mtx);
            m_pending_cv.wait(
                lk, [&] { return (m_nrecords_waiting_to_issue <= 0) && (m_nrecords_waiting_to_complete <= 0); });
        }
    }

    void read_validate(bool expect_all_completed = false) {
        for (auto& lsc : sample_db.m_log_store_clients) {
            lsc->read_validate(expect_all_completed);
        }
    }

    void truncate_validate() {
        for (auto i = 0u; i < sample_db.m_log_store_clients.size(); ++i) {
            auto& lsc = sample_db.m_log_store_clients[i];

            // lsc->truncate(lsc->m_cur_lsn.load() - 1);
            lsc->truncate(lsc->m_log_store->get_contiguous_completed_seq_num(0));
            lsc->read_validate();

            auto tres = home_log_store_mgr.device_truncate(true);
#if 0
            if (parallel_to_writes) {
                if (i < m_log_store_clients.size() - 1) {
                    ASSERT_EQ(tres.idx, m_truncate_log_idx.load());
                } else {
                    // Last one should move the device truncation log idx
                    ASSERT_GT(tres.idx, m_truncate_log_idx.load());
                    m_truncate_log_idx.store(tres.idx);
                }
#endif
            ASSERT_GE(tres.idx, m_truncate_log_idx.load());
            m_truncate_log_idx.store(tres.idx);
        }
    }

protected:
    std::atomic< int64_t > m_nrecords_waiting_to_issue = 0;
    std::atomic< int64_t > m_nrecords_waiting_to_complete = 0;
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
    std::atomic< logid_t > m_truncate_log_idx = -1;

    uint32_t m_q_depth = 64;
    uint32_t m_batch_size = 1;
};

TEST_F(LogStoreTest, BurstRandInsertThenTruncate) {
    LOGINFO("Step 1: Prepare num records and create reqd log stores");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Inserting randomly within a batch of 10 in parallel fashion as a burst");
    this->kickstart_inserts(10, 5000);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 5: Truncate all of the inserts one log store at a time and validate log dev truncation is marked "
            "correctly and also validate if all data prior to truncation return exception");
    this->truncate_validate();
}

TEST_F(LogStoreTest, BurstSeqInsertAndTruncateInParallel) {
    LOGINFO("Step 1: Reinit the num records to start sequential write test");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Issue sequential inserts as a burst");
    this->kickstart_inserts(1, 5000);

    auto trunc_attempt = 0;
    LOGINFO("Step 3: In parallel to writes issue truncation upto completion");
    do {
        usleep(1000);
        this->truncate_validate();
        ++trunc_attempt;
        ASSERT_LT(trunc_attempt, 30);
        LOGINFO("Still pending completions = {}, pending issued = {}", this->m_nrecords_waiting_to_complete.load(),
                m_nrecords_waiting_to_issue.load());
    } while (((this->m_nrecords_waiting_to_complete != 0) || (m_nrecords_waiting_to_issue != 0)));
    LOGINFO("Truncation has been issued and validated for {} times before all records are completely truncated",
            trunc_attempt);

    LOGINFO("Step 4: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 5: Do a final truncation and validate");
    this->truncate_validate();
}

TEST_F(LogStoreTest, ThrottleSeqInsertThenRecover) {
    LOGINFO("Step 1: Reinit the num records to start sequential write test");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Issue sequential inserts with q depth of 64");
    this->kickstart_inserts(1, 64);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Restart homestore");
    sample_db.start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),                  // num devices
                              SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024, // device sizes
                              SDS_OPTIONS["num_threads"].as< uint32_t >(),               // num threads
                              SDS_OPTIONS["num_logstores"].as< uint32_t >(),             // num log stores
                              true                                                       // restart
    );

    LOGINFO("Step 5: Wait for recovery to complete");
    sleep(60);
}

#if 0
TEST_F(LogStoreTest, RandomAndSequentialInsertThenTruncate) {
    // ****************** Test 1 - Random write and truncate at the end **********************
    LOGINFO("Step 1: Start homestore");
    this->start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),
                          SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                          SDS_OPTIONS["num_threads"].as< uint32_t >());

    LOGINFO("Step 2: Prepare num records and create reqd log stores");
    this->init(SDS_OPTIONS["num_logstores"].as< uint32_t >(), SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 3: Inserting randomly within a batch of 10 in parallel fashion as a burst");
    this->kickstart_inserts(10);

    LOGINFO("Step 4: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 5: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 6: Truncate all of the inserts one log store at a time and validate log dev truncation is marked "
            "correctly and also validate if all data prior to truncation return exception");
    this->truncate_validate();

    // ****************** Test 2 - Sequential write and parallel truncate **********************
    LOGINFO("Step 7: Reinit the num records to start sequential write test");
    this->init(0, SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 8: Issue sequential inserts as a burst");
    this->kickstart_inserts(1);

    auto trunc_attempt = 0;
    LOGINFO("Step 9: In parallel to writes issue truncation upto completion");
    do {
        usleep(1000);
        this->truncate_validate();
        ++trunc_attempt;
        ASSERT_LT(trunc_attempt, 30);
        LOGINFO("Still pending completions = {}, pending issued = {}", this->m_nrecords_waiting_to_complete.load(),
                m_nrecords_waiting_to_issue.load());
    } while (((this->m_nrecords_waiting_to_complete != 0) || (m_nrecords_waiting_to_issue != 0)));
    LOGINFO("Truncation has been issued and validated for {} times before all records are completely truncated",
            trunc_attempt);

    LOGINFO("Step 10: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 11: Do a final truncation and validate");
    this->truncate_validate();

    LOGINFO("Step 12: Restarting the homestore, which should trigger the log store recovery");
    this->start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),
                          SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                          SDS_OPTIONS["num_threads"].as< uint32_t >(), true /* restart */);

    LOGINFO("Step 13: Wait for recovery to complete");
    sleep(60);

    LOGINFO("Step 14: Shutting down the homestore");
    this->shutdown();
}
#endif

SDS_OPTIONS_ENABLE(logging, test_log_store)
SDS_OPTION_GROUP(test_log_store,
                 (num_threads, "", "num_threads", "number of threads",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (num_devs, "", "num_devs", "number of devices to create",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                  ::cxxopts::value< uint64_t >()->default_value("5120"), "number"),
                 (dev_names, "", "dev_names", "Device List instead of default created",
                  ::cxxopts::value< std::string >(), "/dev/nvme5n1,/dev/nvme5n2"),
                 (num_logstores, "", "num_logstores", "number of log stores",
                  ::cxxopts::value< uint32_t >()->default_value("4"), "number"),
                 (num_records, "", "num_records", "number of record to test",
                  ::cxxopts::value< uint32_t >()->default_value("10000"), "number"));

#if 0
void parse() {
    if (SDS_OPTIONS.count("log_mods")) {
        std::regex re("[\\s,]+");
        auto s = SDS_OPTIONS["log_mods"].as< std::string >();
        std::sregex_token_iterator it(s.begin(), s.end(), re, -1);
        std::sregex_token_iterator reg_end;
        for (; it != reg_end; ++it) {
            auto mod_stream = std::istringstream(it->str());
            std::string module_name, module_level;
            getline(mod_stream, module_name, ':');
            auto sym = "module_level_" + module_name;
            if (auto mod_level = (spdlog::level::level_enum*)dlsym(RTLD_DEFAULT, sym.c_str()); nullptr != mod_level) {
                if (getline(mod_stream, module_level, ':')) {
                    *mod_level = (spdlog::level::level_enum)strtol(module_level.data(), nullptr, 0);
                } else {
                    *mod_level = lvl;
                }
                glob_enabled_mods.push_back(module_name);
            } else {
                LOGWARN("Could not load module logger: {}\n{}", module_name, dlerror());
            }
        }
        LOGINFO("Enabled modules:\t{}",
                std::accumulate(glob_enabled_mods.begin(), glob_enabled_mods.end(), std::string("")));
    }
}
#endif

int main(int argc, char* argv[]) {
    srand(time(0));
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, test_log_store);
    sds_logging::SetLogger("test_log_store");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    sample_db.start_homestore(
        SDS_OPTIONS["num_devs"].as< uint32_t >(), SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
        SDS_OPTIONS["num_threads"].as< uint32_t >(), SDS_OPTIONS["num_logstores"].as< uint32_t >());
    auto ret = RUN_ALL_TESTS();
    sample_db.shutdown();

    return ret;

#if 0
    home_log_store_mgr.start(true);
    auto ls = home_log_store_mgr.create_new_log_store();

    std::atomic< int64_t > pending_count = 0;
    std::mutex _mtx;
    std::condition_variable _cv;
    std::vector< std::string > s;
    s.reserve(200);

    for (auto i = 0; i < 195; i++) {
        ++pending_count;
        s.push_back(std::to_string(i));
        ls->write_async(i, {(uint8_t*)s.back().c_str(), (uint32_t)s.back().size() + 1}, nullptr,
                        [&pending_count, &_cv](logstore_seq_num_t seq_num, bool success, void* ctx) {
                            LOGINFO("Completed write of seq_num {} ", seq_num);
                            if (--pending_count == 0) { _cv.notify_all(); }
                        });
    }

    {
        std::unique_lock< std::mutex > lk(_mtx);
        _cv.wait(lk, [&] { return (pending_count == 0); });
    }
#endif
}