#include <gtest/gtest.h>
#include "../log_store.hpp"
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <iomgr/iomgr.hpp>
#include <iomgr/aio_drive_interface.hpp>
#include "api/vol_interface.hpp"
#include <algorithm> // std::shuffle
#include <random>    // std::default_random_engine
#include <chrono>    // std::chrono::system_clock
#include <fds/utils.hpp>

using namespace homestore;
THREAD_BUFFER_INIT;
RCU_REGISTER_INIT;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

struct test_log_data {
    uint32_t size;
    uint8_t data[0];

    uint32_t total_size() const { return sizeof(test_log_data) + size; }
};

typedef std::function< void(logstore_seq_num_t, logdev_key) > test_log_store_comp_cb_t;

class SampleLogStoreClient {
public:
    friend class SampleDB;

    SampleLogStoreClient(std::shared_ptr< HomeLogStore > store, const test_log_store_comp_cb_t& cb) {
        m_comp_cb = cb;
        set_log_store(store);
    }

    explicit SampleLogStoreClient(const test_log_store_comp_cb_t& cb) :
            SampleLogStoreClient(home_log_store_mgr.create_new_log_store(), cb) {}

    void set_log_store(std::shared_ptr< HomeLogStore > store) {
        m_log_store = store;
        m_log_store->register_log_found_cb(std::bind(&SampleLogStoreClient::on_log_found, this, std::placeholders::_1,
                                                     std::placeholders::_2, std::placeholders::_3));
    }

    void reset_recovery() {
        m_n_recovered_lsns = 0;
        m_n_recovered_truncated_lsns = 0;
    }

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
                                     [d, this](logstore_seq_num_t seq_num, logdev_key ld_key, void* ctx) {
                                         assert(ld_key);
                                         free(d);
                                         m_comp_cb(seq_num, ld_key);
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
                auto tl = (test_log_data*)b.bytes();
                ASSERT_EQ(tl->total_size(), b.size())
                    << "Size Mismatch for lsn=" << m_log_store->get_store_id() << ":" << i;
                validate_data(tl, i);
            } catch (const std::exception& e) {
                if (!expect_all_completed) {
                    // In case we run truncation in parallel to read, it is possible truncate moved, so adjust the
                    // truncated_upto accordingly.
                    auto trunc_upto = m_log_store->truncated_upto();
                    if (i <= trunc_upto) {
                        i = trunc_upto;
                        continue;
                    }
                }
                LOGFATAL("Unexpected out_of_range exception for lsn={}:{}", m_log_store->get_store_id(), i);
            }
        }
    }

    void recovery_validate() {
        LOGINFO("Totally recovered {} non-truncated lsns and {} truncated lsns for store {}", m_n_recovered_lsns,
                m_n_recovered_truncated_lsns, m_log_store->get_store_id());
        EXPECT_EQ(m_n_recovered_lsns, m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1)
            << "Recovered " << m_n_recovered_lsns << " valid lsns for store " << m_log_store->get_store_id()
            << " Expected to have " << m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1
            << " lsns: m_cur_lsn=" << m_cur_lsn.load() << " truncated_upto_lsn=" << m_truncated_upto_lsn;
    }

    void read(logstore_seq_num_t lsn) {
        ASSERT_GT(lsn, m_truncated_upto_lsn);
        // m_log_store->read(id);
    }

    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
        LOGDEBUG("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
        EXPECT_LE(lsn, m_cur_lsn.load()) << "Recovered incorrect lsn " << m_log_store->get_store_id() << ":" << lsn
                                         << "Expected less than cur_lsn " << m_cur_lsn.load();
        auto tl = (test_log_data*)buf.bytes();
        validate_data(tl, lsn);

        // Count only the ones which are after truncated, because recovery could receive even truncated lsns
        (lsn > m_truncated_upto_lsn) ? m_n_recovered_lsns++ : m_n_recovered_truncated_lsns++;
    }

    void truncate(logstore_seq_num_t lsn) {
        m_log_store->truncate(lsn);
        m_truncated_upto_lsn = lsn;
    }

private:
    test_log_data* prepare_data(logstore_seq_num_t lsn) {
        uint32_t sz;
        uint8_t* raw_buf;

        // Generate buffer of randome size and fill with specific data
        if ((rand() % 100) < 10) {
            // 10% of data is dma'ble aligned boundary
            auto alloc_sz = sisl::round_up((rand() % max_data_size) + sizeof(test_log_data), dma_boundary);
            int ret = posix_memalign((void**)&raw_buf, dma_boundary, alloc_sz);
            assert(ret == 0);
            sz = alloc_sz - sizeof(test_log_data);
        } else {
            sz = rand() % max_data_size;
            raw_buf = (uint8_t*)malloc(sizeof(test_log_data) + sz);
        }

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
    int64_t m_n_recovered_lsns = 0;
    int64_t m_n_recovered_truncated_lsns = 0;
    static constexpr uint32_t max_data_size = 1024;
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
        if (restart) {
            shutdown();
            sleep(5);
        }

        std::vector< dev_info > device_info;
        std::mutex start_mutex;
        std::condition_variable cv;
        bool inited = false;

        LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
        for (uint32_t i = 0; i < ndevices; i++) {
            std::string fpath = "/tmp/log_store_dev_" + std::to_string(i + 1);
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
                home_log_store_mgr.open_log_store(i, [i, this](std::shared_ptr< HomeLogStore > log_store) {
                    m_log_store_clients[i]->set_log_store(log_store);
                });
            }
        }

        uint64_t cache_size = ((ndevices * dev_size) * 10) / 100;
        LOGINFO("Initialize and start HomeBlks with cache_size = {}", cache_size);

        boost::uuids::string_generator gen;
        init_params params;
        params.open_flags = homestore::io_flag::DIRECT_IO;
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
        VolInterface::init(params, restart);

        std::unique_lock< std::mutex > lk(start_mutex);
        cv.wait(lk, [&] { return inited; });

        if (!restart) {
            for (auto i = 0u; i < n_log_stores; ++i) {
                m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(std::bind(
                    &SampleDB::on_log_insert_completion, this, std::placeholders::_1, std::placeholders::_2)));
            }
        }
    }

    void shutdown() {
        VolInterface::get_instance()->shutdown();

        // m_log_store_clients.clear();
        iomanager.stop();
    }

    void on_thread_msg(const iomgr_msg& msg) {
        switch (msg.m_type) {
        case iomgr_msg_type::CUSTOM_MSG:
            if (m_on_schedule_io_cb) m_on_schedule_io_cb();
            break;
        default:
            break;
        }
    }

    void on_log_insert_completion(logstore_seq_num_t lsn, logdev_key ld_key) {
        atomic_update_max(m_highest_log_idx, ld_key.idx);
        if (m_io_closure) m_io_closure(lsn, ld_key);
    }

    bool delete_log_store(logstore_id_t store_id) {
        bool removed = false;
        for (auto it = m_log_store_clients.begin(); it != m_log_store_clients.end(); ++it) {
            if ((*it)->m_log_store->get_store_id() == store_id) {
                home_log_store_mgr.remove_log_store(store_id);
                m_log_store_clients.erase(it);
                removed = true;
                break;
            }
        }
        return removed;
    }

    logid_t highest_log_idx() const { return m_highest_log_idx.load(); }

    std::function< void() > m_on_schedule_io_cb;
    test_log_store_comp_cb_t m_io_closure;
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;
    std::atomic< logid_t > m_highest_log_idx = -1;
};

struct LogStoreTest : public testing::Test {
public:
    void init(uint64_t n_total_records) {
        // m_nrecords_waiting_to_issue = std::lround(n_total_records / _batch_size) * _batch_size;
        m_nrecords_waiting_to_issue = n_total_records;
        m_nrecords_waiting_to_complete = 0;
        sample_db.m_on_schedule_io_cb = std::bind(&LogStoreTest::do_insert, this);
        sample_db.m_io_closure =
            std::bind(&LogStoreTest::on_insert_completion, this, std::placeholders::_1, std::placeholders::_2);

        for (auto& lsc : sample_db.m_log_store_clients) {
            lsc->reset_recovery();
        }
    }

    void kickstart_inserts(uint32_t batch_size, uint32_t q_depth) {
        m_batch_size = batch_size;
        m_q_depth = q_depth;
        iomanager.send_msg(-1, iomgr_msg(iomgr_msg_type::CUSTOM_MSG));
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

    void on_insert_completion(logstore_seq_num_t lsn, logdev_key ld_key) {
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

    int find_garbage_upto(logid_t idx) {
        int count = 0;
        auto it = m_garbage_stores_upto.begin();

        while (it != m_garbage_stores_upto.end()) {
            if (it->first >= idx) { return count; }
            ++it;
            ++count;
        }
        return count;
    }

    void truncate_validate() {
        for (auto i = 0u; i < sample_db.m_log_store_clients.size(); ++i) {
            auto& lsc = sample_db.m_log_store_clients[i];

            // lsc->truncate(lsc->m_cur_lsn.load() - 1);
            lsc->truncate(lsc->m_log_store->get_contiguous_completed_seq_num(0));
            lsc->read_validate();

            auto tres = home_log_store_mgr.device_truncate();
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

        auto upto_count = find_garbage_upto(m_truncate_log_idx.load());
        auto count = 0;
        for (auto it = m_garbage_stores_upto.begin(); count < upto_count; ++count) {
            it = m_garbage_stores_upto.erase(it);
        }
        validate_num_stores();
    }

    void recovery_validate() {
        for (auto i = 0u; i < sample_db.m_log_store_clients.size(); ++i) {
            auto& lsc = sample_db.m_log_store_clients[i];
            lsc->recovery_validate();
        }
    }

    void validate_num_stores() {
        std::vector< logstore_id_t > reg_ids, garbage_ids;
        home_log_store_mgr.logdev().get_registered_store_ids(reg_ids, garbage_ids);
        ASSERT_EQ(sample_db.m_log_store_clients.size(), reg_ids.size() - garbage_ids.size());

        auto exp_garbage_store_count = 0ul;
        auto upto_count = find_garbage_upto(sample_db.highest_log_idx() + 1);
        auto count = 0;
        for (auto it = m_garbage_stores_upto.begin(); count < upto_count; ++it, ++count) {
            exp_garbage_store_count += it->second;
        }
        ASSERT_EQ(garbage_ids.size(), exp_garbage_store_count);
    }

    void delete_validate(uint32_t store_id) {
        validate_num_stores();
        auto l_idx = sample_db.highest_log_idx();
        if (m_garbage_stores_upto.find(l_idx) != m_garbage_stores_upto.end()) {
            m_garbage_stores_upto[l_idx]++;
        } else {
            m_garbage_stores_upto.insert(std::pair< logid_t, uint32_t >(l_idx, 1u));
        }
        sample_db.delete_log_store(store_id);
        validate_num_stores();
    }

protected:
    std::atomic< int64_t > m_nrecords_waiting_to_issue = 0;
    std::atomic< int64_t > m_nrecords_waiting_to_complete = 0;
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
    std::atomic< logid_t > m_truncate_log_idx = -1;
    std::map< logid_t, uint32_t > m_garbage_stores_upto;

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

#if 0
TEST_F(LogStoreTest, ThrottleSeqInsertThenRecover) {
    LOGINFO("Step 1: Reinit the num records to start sequential write test");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Issue sequential inserts with q depth of 30");
    this->kickstart_inserts(1, 30);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 5: Restart homestore");
    sample_db.start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),                  // num devices
                              SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024, // device sizes
                              SDS_OPTIONS["num_threads"].as< uint32_t >(),               // num threads
                              SDS_OPTIONS["num_logstores"].as< uint32_t >(),             // num log stores
                              true                                                       // restart
    );
    this->recovery_validate();
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 6: Restart homestore again to validate recovery on consecutive restarts");
    sample_db.start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),                  // num devices
                              SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024, // device sizes
                              SDS_OPTIONS["num_threads"].as< uint32_t >(),               // num threads
                              SDS_OPTIONS["num_logstores"].as< uint32_t >(),             // num log stores
                              true                                                       // restart
    );
    this->recovery_validate();
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 7: Issue more sequential inserts after restarts with q depth of 15");
    this->kickstart_inserts(1, 15);

    LOGINFO("Step 8: Wait for the previous Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 9: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 10: Restart homestore again to validate recovery of inserted data after restarts");
    sample_db.start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),                  // num devices
                              SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024, // device sizes
                              SDS_OPTIONS["num_threads"].as< uint32_t >(),               // num threads
                              SDS_OPTIONS["num_logstores"].as< uint32_t >(),             // num log stores
                              true                                                       // restart
    );
    this->recovery_validate();
}
#endif

TEST_F(LogStoreTest, DeleteMultipleLogStores) {
    auto nrecords = (SDS_OPTIONS["num_records"].as< uint32_t >() * 5) / 100;

    LOGINFO("Step 1: Reinit the {} to start sequential write test", nrecords);
    this->init(nrecords);

    LOGINFO("Step 2: Issue sequential inserts with q depth of 40");
    this->kickstart_inserts(1, 40);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 5: Remove log store 0");
    this->delete_validate(0);

    LOGINFO("Step 6: Truncate all of the remaining log stores and validate log dev truncation is marked "
            "correctly and also validate if all data prior to truncation return exception");
    this->truncate_validate();

    LOGINFO("Step 7: Do IO on remaining log stores for records={}", nrecords);
    this->init(nrecords);
    this->kickstart_inserts(1, 40);
    this->wait_for_inserts();

    LOGINFO("Step 8: Remove log store 1");
    this->delete_validate(1);

    LOGINFO("Step 9: Truncate again, this time expected to have first log store delete is actually garbage collected");
    this->truncate_validate();
}

SDS_OPTIONS_ENABLE(logging, test_log_store)
SDS_OPTION_GROUP(test_log_store,
                 (num_threads, "", "num_threads", "number of threads",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (num_devs, "", "num_devs", "number of devices to create",
                  ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                 (dev_size_mb, "", "dev_size_mb", "size of each device in MB",
                  ::cxxopts::value< uint64_t >()->default_value("10240"), "number"),
                 (dev_names, "", "dev_names", "Device List instead of default created",
                  ::cxxopts::value< std::string >(), "/dev/nvme5n1,/dev/nvme5n2"),
                 (num_logstores, "", "num_logstores", "number of log stores",
                  ::cxxopts::value< uint32_t >()->default_value("4"), "number"),
                 (num_records, "", "num_records", "number of record to test",
                  ::cxxopts::value< uint32_t >()->default_value("10000"), "number"),
                 (hb_stats_port, "", "hb_stats_port", "Stats port for HTTP service",
                  cxxopts::value< int32_t >()->default_value("5002"), "port"));

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
