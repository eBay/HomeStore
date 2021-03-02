#include <algorithm> // std::shuffle
#include <array>
#include <atomic>
#include <chrono>    // std::chrono::system_clock
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>    // std::default_random_engine
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <fds/utils.hpp>
#include <folly/Synchronized.h>
#include <iomgr/aio_drive_interface.hpp>
#include <iomgr/iomgr.hpp>
#include <sds_logging/logging.h>
#include <sds_options/options.h>

#include "api/vol_interface.hpp"
#include "test_common/homestore_test_common.hpp"

#include "../log_store.hpp"

#include <gtest/gtest.h>

using namespace homestore;
THREAD_BUFFER_INIT;
RCU_REGISTER_INIT;
SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)

struct test_log_data {
    test_log_data() = default;
    test_log_data(const test_log_data&) = delete;
    test_log_data(test_log_data&&) noexcept = delete;
    test_log_data& operator=(const test_log_data&) = delete;
    test_log_data& operator=(test_log_data&&) noexcept = delete;
    ~test_log_data() = default;

    uint32_t size; 
    uint8_t data[1]; // 0 size arrays are illegal according to C++ standard

    uint32_t total_size() const { return sizeof(test_log_data) + size - 1; }
};

typedef std::function< void(logstore_seq_num_t, logdev_key) > test_log_store_comp_cb_t;
class Timer {
public:
    Timer() : beg_{clock_::now()} {}
    Timer(const Timer&) = delete;
    Timer(Timer&&) noexcept = delete;
    Timer& operator=(const Timer&) = delete;
    Timer& operator=(Timer&&) noexcept = delete;
    ~Timer() = default;

    void reset() { beg_ = clock_::now(); }
    [[nodiscard]] double elapsed() const { return std::chrono::duration_cast< second_ >(clock_::now() - beg_).count(); }

private:
    typedef std::chrono::high_resolution_clock clock_;
    typedef std::chrono::duration< double, std::ratio< 1 > > second_;
    std::chrono::time_point< clock_ > beg_;
};

class SampleLogStoreClient {
public:
    friend class SampleDB;

    SampleLogStoreClient(std::shared_ptr< HomeLogStore > store, const test_log_store_comp_cb_t& cb) : m_comp_cb{cb} {
        set_log_store(store);
    }

    explicit SampleLogStoreClient(const test_log_store_comp_cb_t& cb) :
            SampleLogStoreClient(home_log_store_mgr.create_new_log_store(false /* append_mode */), cb) {}

    SampleLogStoreClient(const SampleLogStoreClient&) = delete;
    SampleLogStoreClient(SampleLogStoreClient&&) noexcept = delete;
    SampleLogStoreClient& operator=(const SampleLogStoreClient&) = delete;
    SampleLogStoreClient& operator=(SampleLogStoreClient&&) noexcept = delete;
    ~SampleLogStoreClient() = default;

    void set_log_store(std::shared_ptr< HomeLogStore > store) {
        m_log_store = store;
        m_log_store->register_log_found_cb(std::bind(&SampleLogStoreClient::on_log_found, this, std::placeholders::_1,
                                                     std::placeholders::_2, std::placeholders::_3));
    }

    void reset_recovery() {
        m_n_recovered_lsns = 0;
        m_n_recovered_truncated_lsns = 0;
    }

    void insert_next_batch(const uint32_t batch_size, const uint32_t nholes = 0) {
        const auto cur_lsn{m_cur_lsn.fetch_add(batch_size + nholes)};
        insert(cur_lsn, batch_size, nholes, false);
    }

    void insert(const logstore_seq_num_t start_lsn, const int64_t nparallel_count, int64_t nholes = 0,
                const bool wait_for_completion = true) {
        std::vector< logstore_seq_num_t > lsns;
        lsns.reserve(nparallel_count + nholes);

        // Shuffle ids within the range for count
        for (auto lsn{start_lsn}; lsn < start_lsn + nparallel_count + nholes; ++lsn) {
            lsns.push_back(lsn);
        }
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::shuffle(lsns.begin(), lsns.end(), re);

        ASSERT_LT(m_log_store->get_contiguous_issued_seq_num(0), start_lsn + nparallel_count + nholes);
        ASSERT_LT(m_log_store->get_contiguous_completed_seq_num(0), start_lsn + nparallel_count + nholes);
        for (const auto lsn : lsns) {
            if (nholes) {
                m_hole_lsns.wlock()->insert(std::make_pair<>(lsn, false));
                --nholes;
            } else {
                bool io_memory{false};
                auto* const d{prepare_data(lsn, io_memory)};
                m_log_store->write_async(lsn, {reinterpret_cast< uint8_t* >(d), d->total_size(), false}, nullptr,
                                         [io_memory, d, this](logstore_seq_num_t seq_num, const sisl::io_blob& b,
                                                              logdev_key ld_key, void* ctx) {
                                             assert(ld_key);
                                             if (io_memory) {
                                                 iomanager.iobuf_free(reinterpret_cast< uint8_t* >(d));
                                             } else {
                                                 std::free(static_cast< void* >(d));
                                             }
                                             m_comp_cb(seq_num, ld_key);
                                         });
            }
        }
    }

    void iterate_validate(const bool expect_all_completed = false) {
        const auto trunc_upto{m_log_store->truncated_upto()};
        const auto& hole_end{m_hole_lsns.rlock()->end()};
        const auto upto{expect_all_completed ? m_cur_lsn.load() - 1 : m_log_store->get_contiguous_completed_seq_num(0)};

        int64_t idx{trunc_upto + 1};
        bool hole_expected{false};
    start_iterate:
        try {
            auto hole_entry{m_hole_lsns.rlock()->find(idx)};
            if ((hole_entry != hole_end) && !hole_entry->second) { // Hole entry exists and not filled
                ASSERT_THROW([[maybe_unused]] const auto result{m_log_store->read_sync(idx)}, std::out_of_range)
                    << "Expected std::out_of_range exception for read of hole lsn=" << m_log_store->get_store_id()
                    << ":" << idx << " but not thrown";
                hole_expected = true;
            } else {
                m_log_store->foreach (
                    idx,
                    [upto, hole_end, &idx, &hole_expected, &hole_entry, this](const int64_t seq_num,
                                                                              const homestore::log_buffer& b) -> bool {
                        if ((hole_entry != hole_end) && hole_entry->second) { // Hole entry exists, but filled
                            EXPECT_EQ(b.size(), 0ul);
                        } else {
                            auto* const tl{reinterpret_cast< test_log_data* >(b.bytes())};
                            EXPECT_EQ(tl->total_size(), b.size());
                            validate_data(tl, seq_num);
                        }
                        idx++;
                        hole_entry = m_hole_lsns.rlock()->find(idx);
                        if ((hole_entry != hole_end) && !hole_entry->second) { // Hole entry exists and not filled
                            hole_expected = true;
                            return false;
                        }
                        return (seq_num + 1 < upto) ? true : false;
                    });
            }
        } catch (const std::exception& e) {
            if (!expect_all_completed) {
                // In case we run truncation in parallel to read, it is possible truncate moved, so adjust the
                // truncated_upto accordingly.
                const auto trunc_upto{m_log_store->truncated_upto()};
                if (idx <= trunc_upto) {
                    idx = trunc_upto + 1;
                    goto start_iterate;
                }
            }
            LOGFATAL("Unexpected out_of_range exception for lsn={}:{}", m_log_store->get_store_id(), idx);
        }
        if ((hole_expected == true) && (idx <= upto)) {
            // Skipping reading from a hole
            ++idx;
            hole_expected = false;
            goto start_iterate;
        }
    }

    void read_validate(const bool expect_all_completed = false) {
        const auto trunc_upto{m_log_store->truncated_upto()};
        for (std::remove_const_t<decltype(trunc_upto)> i{0}; i <= trunc_upto; ++i) {
            ASSERT_THROW([[maybe_unused]] const auto result{m_log_store->read_sync(i)}, std::out_of_range)
                << "Expected std::out_of_range exception for lsn=" << m_log_store->get_store_id() << ":" << i
                << " but not thrown";
        }

        const auto& hole_end{m_hole_lsns.rlock()->end()};
        const auto upto{expect_all_completed ? m_cur_lsn.load() - 1 : m_log_store->get_contiguous_completed_seq_num(0)};
        for (auto i{m_log_store->truncated_upto() + 1}; i < upto; ++i) {
            const auto hole_entry{m_hole_lsns.rlock()->find(i)};
            if ((hole_entry != hole_end) && (!hole_entry->second)) { // Hole entry exists and not filled
                ASSERT_THROW([[maybe_unused]] const auto result{m_log_store->read_sync(i)}, std::out_of_range)
                    << "Expected std::out_of_range exception for read of hole lsn=" << m_log_store->get_store_id()
                    << ":" << i << " but not thrown";
            } else {
                try {
                    const auto b{m_log_store->read_sync(i)};

                    if ((hole_entry != hole_end) && (hole_entry->second)) { // Hole entry exists, but filled
                        ASSERT_EQ(b.size(), 0ul)
                            << "Expected null entry for lsn=" << m_log_store->get_store_id() << ":" << i;
                    } else {
                        auto* const tl{reinterpret_cast< test_log_data* >(b.bytes())};
                        ASSERT_EQ(tl->total_size(), b.size())
                            << "Size Mismatch for lsn=" << m_log_store->get_store_id() << ":" << i;
                        validate_data(tl, i);
                    }
                } catch (const std::exception& e) {
                    if (!expect_all_completed) {
                        // In case we run truncation in parallel to read, it is possible truncate moved, so adjust the
                        // truncated_upto accordingly.
                        const auto trunc_upto{m_log_store->truncated_upto()};
                        if (i <= trunc_upto) {
                            i = trunc_upto;
                            continue;
                        }
                    }
                    LOGFATAL("Unexpected out_of_range exception for lsn={}:{}", m_log_store->get_store_id(), i);
                }
            }
        }
    }

    void fill_hole_and_validate() {
        const auto start{m_log_store->truncated_upto()};
        m_hole_lsns.withWLock([&](auto& holes_list) {
            try {
                for (auto& hole_entry : holes_list) {
                    if (!hole_entry.second) { // Not filled already
                        ASSERT_EQ(m_log_store->get_contiguous_completed_seq_num(start) + 1, hole_entry.first)
                            << "Expected next hole at the location for lsn=" << m_log_store->get_store_id() << ":"
                            << hole_entry.first;
                        m_log_store->fill_gap(hole_entry.first);
                        hole_entry.second = true;
                    }
                }

                if (holes_list.size()) {
                    ASSERT_GE(m_log_store->get_contiguous_completed_seq_num(start), holes_list.crbegin()->first)
                        << "After all holes are filled, expected contiguous seq_num to be moved ahead for store_id "
                        << m_log_store->get_store_id();
                }

            } catch (std::exception& e) { LOGFATAL("Caught exception e {}", e.what()); }
        });
    }

    void recovery_validate() {
        LOGINFO("Totally recovered {} non-truncated lsns and {} truncated lsns for store {}", m_n_recovered_lsns,
                m_n_recovered_truncated_lsns, m_log_store->get_store_id());
        EXPECT_EQ(m_n_recovered_lsns, m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1)
            << "Recovered " << m_n_recovered_lsns << " valid lsns for store " << m_log_store->get_store_id()
            << " Expected to have " << m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1
            << " lsns: m_cur_lsn=" << m_cur_lsn.load() << " truncated_upto_lsn=" << m_truncated_upto_lsn;
    }

    void read(const logstore_seq_num_t lsn) {
        ASSERT_GT(lsn, m_truncated_upto_lsn);
        // m_log_store->read(id);
    }

    void on_log_found(const logstore_seq_num_t lsn, const log_buffer buf, void* const ctx) {
        LOGDEBUG("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
        EXPECT_LE(lsn, m_cur_lsn.load()) << "Recovered incorrect lsn " << m_log_store->get_store_id() << ":" << lsn
                                         << "Expected less than cur_lsn " << m_cur_lsn.load();
        auto* const tl{reinterpret_cast< test_log_data* >(buf.bytes())};
        validate_data(tl, lsn);

        // Count only the ones which are after truncated, because recovery could receive even truncated lsns
        (lsn > m_truncated_upto_lsn) ? m_n_recovered_lsns++ : m_n_recovered_truncated_lsns++;
    }

    void truncate(const logstore_seq_num_t lsn) {
        m_log_store->truncate(lsn);
        m_truncated_upto_lsn = lsn;
    }

    [[nodiscard]] bool has_all_lsns_truncated() const {
        return (m_truncated_upto_lsn.load() == (m_cur_lsn.load() - 1));
    }

    [[nodiscard]] static test_log_data* prepare_data(const logstore_seq_num_t lsn, bool& io_memory) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        uint32_t sz{0};
        uint8_t* raw_buf{nullptr};

        // Generate buffer of random size and fill with specific data
        std::uniform_int_distribution< uint8_t > gen_percentage{0, 99};
        std::uniform_int_distribution< uint32_t > gen_data_size{0, max_data_size - 1};
        if (gen_percentage(re) < static_cast< uint8_t >(10)) {
            // 10% of data is dma'ble aligned boundary
            const auto alloc_sz{sisl::round_up(gen_data_size(re) + (sizeof(test_log_data) - 1), dma_boundary)};
            raw_buf = iomanager.iobuf_alloc(dma_boundary, alloc_sz);
            sz = alloc_sz - (sizeof(test_log_data) - 1);
            io_memory = true;
        } else {
            sz = gen_data_size(re);
            raw_buf = static_cast< uint8_t* >(std::malloc((sizeof(test_log_data) - 1) + sz));
            io_memory = false;
        }

        test_log_data* const d{new (raw_buf) test_log_data()};
        d->size = sz;

        assert(reinterpret_cast<uint8_t*>(d) == raw_buf);

        const char c{static_cast<char>((lsn % 94) + 33)};
        std::memset(static_cast< void* >(d->data), c, static_cast<size_t>(d->size));
        return d;
    }

private:
    void validate_data(const test_log_data* const d, const logstore_seq_num_t lsn) {
        const char c{static_cast<char>((lsn % 94) + 33)};
        const std::string actual{reinterpret_cast< const char* >(&d->data[0]), static_cast< size_t >(d->size)};
        const std::string expected(static_cast< size_t >(d->size), c); // needs to be () because of same reason as vector
        ASSERT_EQ(actual, expected) << "Data mismatch for LSN=" << m_log_store->get_store_id() << ":" << lsn
                                    << " size=" << d->size;
    }

    friend class LogStoreTest;

private:
    test_log_store_comp_cb_t m_comp_cb;
    std::atomic< logstore_seq_num_t > m_truncated_upto_lsn = -1;
    std::atomic< logstore_seq_num_t > m_cur_lsn = 0;
    std::shared_ptr< HomeLogStore > m_log_store;
    folly::Synchronized< std::map< logstore_seq_num_t, bool > > m_hole_lsns;
    int64_t m_n_recovered_lsns = 0;
    int64_t m_n_recovered_truncated_lsns = 0;
    static constexpr uint32_t max_data_size = 1024;
};

#define sample_db SampleDB::instance()

class SampleDB {
private:
    SampleDB() = default;

public:
    friend class LogStoreTest;

    SampleDB(const SampleDB&) = delete;
    SampleDB(SampleDB&&) noexcept = delete;
    SampleDB& operator=(const SampleDB&) = delete;
    SampleDB& operator=(SampleDB&&) noexcept = delete;
    ~SampleDB() = default;

    [[nodiscard]] static SampleDB& instance() {
        static SampleDB inst;
        return inst;
    }

    void start_homestore(const uint32_t ndevices, const uint64_t dev_size, uint32_t nthreads, const uint32_t n_log_stores,
                         const bool restart = false) {
        if (restart) {
            shutdown();
            std::this_thread::sleep_for(std::chrono::seconds{5});
        }

        std::vector< dev_info > device_info;
        std::mutex start_mutex;
        std::condition_variable cv;
        bool inited{false};

        LOGINFO("creating {} device files with each of size {} ", ndevices, dev_size);
        for (uint32_t i{0}; i < ndevices; ++i) {
            const std::string fpath{"/tmp/log_store_dev_" + std::to_string(i + 1)};
            if (!restart) {
                std::ofstream ofs{fpath, std::ios::binary | std::ios::out};
                ofs.seekp(dev_size - 1);
                ofs.write("", 1);
                ofs.close();
            }
            device_info.push_back({fpath});
        }

        bool is_spdk{SDS_OPTIONS["spdk"].as< bool >()};
        /* if --spdk is not set, check env variable if user want to run spdk */
        if (!is_spdk && std::getenv(SPDK_ENV_VAR_STRING.c_str())) { is_spdk = true; }
        if (is_spdk) { nthreads = 2; }

        LOGINFO("Starting iomgr with {} threads, spdk: {}", nthreads, is_spdk);
        iomanager.start(nthreads, is_spdk);

        if (restart) {
            for (std::remove_const_t<decltype(n_log_stores)> i{0}; i < n_log_stores; ++i) {
                home_log_store_mgr.open_log_store(i, false /* append_mode */,
                                                  [i, this](std::shared_ptr< HomeLogStore > log_store) {
                                                      m_log_store_clients[i]->set_log_store(log_store);
                                                  });
            }
        }

        const uint64_t app_mem_size{((ndevices * dev_size) * 15) / 100};
        LOGINFO("Initialize and start HomeBlks with app_mem_size = {}", app_mem_size);

        boost::uuids::string_generator gen;
        init_params params;
        params.open_flags = homestore::io_flag::DIRECT_IO;
        params.min_virtual_page_size = 4096;
        params.app_mem_size = app_mem_size;
        params.devices = device_info;
        params.init_done_cb = [&](std::error_condition err, const out_params& params) {
            LOGINFO("HomeBlks Init completed");
            {
                std::unique_lock< std::mutex > lk{start_mutex};
                inited = true;
            }
            cv.notify_all();
        };
        params.vol_mounted_cb = [](const VolumePtr& vol_obj, vol_state state) {};
        params.vol_state_change_cb = [](const VolumePtr& vol, vol_state old_state, vol_state new_state) {};
        params.vol_found_cb = [](boost::uuids::uuid uuid) -> bool { return true; };
        VolInterface::init(params, restart);

        std::unique_lock< std::mutex > lk{start_mutex};
        cv.wait(lk, [&] { return inited; });

        if (!restart) {
            for (std::remove_const_t<decltype(n_log_stores)> i{0}; i < n_log_stores; ++i) {
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

    void on_log_insert_completion(const logstore_seq_num_t lsn, const logdev_key ld_key) {
        atomic_update_max(m_highest_log_idx, ld_key.idx);
        if (m_io_closure) m_io_closure(lsn, ld_key);
    }

    [[nodiscard]] bool  delete_log_store(const logstore_id_t store_id) {
        bool removed{false};
        for (auto it{std::begin(m_log_store_clients)}; it != std::end(m_log_store_clients); ++it) {
            if ((*it)->m_log_store->get_store_id() == store_id) {
                home_log_store_mgr.remove_log_store(store_id);
                m_log_store_clients.erase(it);
                removed = true;
                break;
            }
        }
        return removed;
    }

    [[nodiscard]] logid_t highest_log_idx() const { return m_highest_log_idx.load(); }

    std::function< void() > m_on_schedule_io_cb;
    test_log_store_comp_cb_t m_io_closure;
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;
    std::atomic< logid_t > m_highest_log_idx = -1;
};

class LogStoreTest : public testing::Test {
public:
    LogStoreTest() = default;
    LogStoreTest(const LogStoreTest&) = delete;
    LogStoreTest(LogStoreTest&&) noexcept = delete;
    LogStoreTest& operator=(const LogStoreTest&) = delete;
    LogStoreTest& operator=(LogStoreTest&&) noexcept = delete;
    virtual ~LogStoreTest() override = default;

protected:    
    virtual void SetUp() override{};
    virtual void TearDown() override{};

    void init(const uint64_t n_total_records, const std::vector< std::pair< size_t, int > >& inp_freqs = {}) {
        // m_nrecords_waiting_to_issue = std::lround(n_total_records / _batch_size) * _batch_size;
        m_nrecords_waiting_to_issue = n_total_records;
        m_nrecords_waiting_to_complete = 0;
        sample_db.m_on_schedule_io_cb = std::bind(&LogStoreTest::do_insert, this);
        sample_db.m_io_closure =
            std::bind(&LogStoreTest::on_insert_completion, this, std::placeholders::_1, std::placeholders::_2);

        for (auto& lsc : sample_db.m_log_store_clients) {
            lsc->reset_recovery();
        }
        set_store_workload_freq(inp_freqs); // Equal distribution by default
    }

    void kickstart_inserts(const uint32_t batch_size, const uint32_t q_depth, const uint32_t holes_per_batch = 0) {
        m_batch_size = batch_size;
        m_q_depth = q_depth;
        m_holes_per_batch = holes_per_batch;
        iomanager.run_on(iomgr::thread_regex::all_io, [](io_thread_addr_t addr) {
            if (sample_db.m_on_schedule_io_cb) sample_db.m_on_schedule_io_cb();
        });
    }

    void do_insert() {
        // Randomly pick a store client and write journal entry batch.
        while ((m_nrecords_waiting_to_issue.load() > 0) && (m_nrecords_waiting_to_complete.load() < m_q_depth)) {
            m_nrecords_waiting_to_issue.fetch_sub(m_batch_size);
            m_nrecords_waiting_to_complete.fetch_add(m_batch_size);
            pick_log_store()->insert_next_batch(m_batch_size, std::min(m_batch_size, m_holes_per_batch));
        }
    }

    void on_insert_completion(const logstore_seq_num_t lsn, const logdev_key ld_key) {
        const auto waiting_to_issue{m_nrecords_waiting_to_issue.load()};
        if ((m_nrecords_waiting_to_complete.fetch_sub(1) == 1) && (waiting_to_issue == 0)) {
            m_pending_cv.notify_all();
        } else if (waiting_to_issue != 0) {
            do_insert();
        }
    }

    void wait_for_inserts() {
        {
            std::unique_lock< std::mutex > lk{m_pending_mtx};
            m_pending_cv.wait(
                lk, [&] { return (m_nrecords_waiting_to_issue <= 0) && (m_nrecords_waiting_to_complete <= 0); });
        }
    }

    void read_validate(const bool expect_all_completed = false) {
        for (const auto& lsc : sample_db.m_log_store_clients) {
            lsc->read_validate(expect_all_completed);
        }
    }

    void iterate_validate(const bool expect_all_completed = false) {
        for (const auto& lsc : sample_db.m_log_store_clients) {
            lsc->iterate_validate(expect_all_completed);
        }
    }
    void dump_validate(const int64_t expected_num_records, const bool print_content = false) {
        homestore::log_dump_req dump_req{homestore::log_dump_req()};
        if (print_content) dump_req.verbosity_level = log_dump_verbosity::CONTENT;
        // must use operator= construction as copy construction results in error
        nlohmann::json json_dump = home_log_store_mgr.dump_log_store(dump_req);
        LOGINFO("Printing json dump of all logstores. \n {}", json_dump.dump());
        EXPECT_EQ(sample_db.m_log_store_clients.size(), json_dump.size());
        int64_t count{0};
        for (const auto& logdump : json_dump) {
            const auto itr{logdump.find("log_records")};
            if (itr != std::end(logdump)) { count += static_cast< int64_t >(logdump["log_records"].size()); }
        }
        EXPECT_EQ(expected_num_records, count);
    }
    void dump_validate_filter(const logstore_id_t id, const logstore_seq_num_t start_seq, const logstore_seq_num_t end_seq,
                              const bool print_content = false) {
        for (const auto& lsc : sample_db.m_log_store_clients) {
            if (lsc->m_log_store->get_store_id() == id) {
                homestore::log_dump_req dump_req{homestore::log_dump_req()};

                if (print_content) dump_req.verbosity_level = log_dump_verbosity::CONTENT;
                dump_req.log_store = lsc->m_log_store;
                dump_req.start_seq_num = start_seq;
                dump_req.end_seq_num = end_seq;

                // must use operator= construction as copy construction results in error
                nlohmann::json json_dump = home_log_store_mgr.dump_log_store(dump_req);
                LOGINFO("Printing json dump of logstore id {}, start_seq {}, end_seq {}, \n\n {}", id, start_seq,
                        end_seq, json_dump.dump());
                const auto itr_id{json_dump.find(std::to_string(id))};
                if (itr_id != std::end(json_dump))
                {
                    const auto itr_records{itr_id->find("log_records")};
                    if (itr_records != std::end(*itr_id))
                    {
                        EXPECT_EQ(static_cast<size_t>(end_seq - start_seq + 1), itr_records->size());
                    } else {
                        EXPECT_FALSE(true);
                    }
                } else
                {
                    EXPECT_FALSE(true);
                }
                
                return;
            }
        }
    }

    [[nodiscard]] int find_garbage_upto(const logid_t idx) {
        int count{0};
        auto it{std::begin(m_garbage_stores_upto)};

        while (it != std::end(m_garbage_stores_upto)) {
            if (it->first > idx) { return count; }
            ++it;
            ++count;
        }
        return count;
    }

    void fill_hole_and_validate() {
        for (size_t i{0}; i < sample_db.m_log_store_clients.size(); ++i) {
            const auto& lsc{sample_db.m_log_store_clients[i]};
            lsc->fill_hole_and_validate();
        }
    }

    void truncate_validate(const bool is_parallel_to_write = false) {
        for (size_t i{0}; i < sample_db.m_log_store_clients.size(); ++i) {
            const auto& lsc{sample_db.m_log_store_clients[i]};

            // lsc->truncate(lsc->m_cur_lsn.load() - 1);
            lsc->truncate(lsc->m_log_store->get_contiguous_completed_seq_num(0));
            lsc->read_validate();
        }

        home_log_store_mgr.device_truncate(
            [this, is_parallel_to_write](const logdev_key& trunc_loc) {
                bool expect_forward_progress{true};
                uint32_t n_fully_truncated{0};
                if (is_parallel_to_write) {
                    for (const auto& lsc : sample_db.m_log_store_clients) {
                        if (lsc->has_all_lsns_truncated()) ++n_fully_truncated;
                    }

                    // While inserts are going on, truncation can guaranteed to be forward progressed if none of the log
                    // stores are fully truncated. If all stores are fully truncated, its obvious no progress, but even
                    // if one of the store is fully truncated, then it might be possible that logstore is holding lowest
                    // logdev location and waiting for next flush to finish to move the safe logdev location.
                    expect_forward_progress = (n_fully_truncated == 0);
                }

                if (expect_forward_progress) {
                    if (trunc_loc == logdev_key::out_of_bound_ld_key()) {
                        LOGINFO("No forward progress for device truncation yet.");
                    } else
                    {
                        // Validate the truncation is actually moving forw1ard
                        ASSERT_GT(trunc_loc.idx, m_truncate_log_idx.load());
                        m_truncate_log_idx.store(trunc_loc.idx);
                    }
                } else {
                    LOGINFO("Do not expect forward progress for device truncation");
                }
            },
            true /* wait_till_done */);

        const auto upto_count{find_garbage_upto(m_truncate_log_idx.load())};
        std::remove_const_t<decltype(upto_count)> count{0};
        for (auto it{std::begin(m_garbage_stores_upto)}; count < upto_count; ++count) {
            it = m_garbage_stores_upto.erase(it);
        }
        validate_num_stores();
    }

    void recovery_validate() {
        for (size_t i{0}; i < sample_db.m_log_store_clients.size(); ++i) {
            const auto& lsc{sample_db.m_log_store_clients[i]};
            lsc->recovery_validate();
        }
    }

    void validate_num_stores() {
        std::vector< logstore_id_t > reg_ids, garbage_ids;
        home_log_store_mgr.logdev().get_registered_store_ids(reg_ids, garbage_ids);
        ASSERT_EQ(sample_db.m_log_store_clients.size(), reg_ids.size() - garbage_ids.size());

        size_t exp_garbage_store_count{0};
        auto upto_count{find_garbage_upto(sample_db.highest_log_idx() + 1)};
        decltype(upto_count) count{0};
        for (auto it{std::begin(m_garbage_stores_upto)}; count < upto_count; ++it, ++count) {
            exp_garbage_store_count += it->second;
        }
        ASSERT_EQ(garbage_ids.size(), exp_garbage_store_count);
    }

    void delete_validate(const uint32_t store_id) {
        validate_num_stores();
        const auto l_idx{sample_db.highest_log_idx()};
        if (m_garbage_stores_upto.find(l_idx) != m_garbage_stores_upto.end()) {
            m_garbage_stores_upto[l_idx]++;
        } else {
            m_garbage_stores_upto.insert(std::pair< logid_t, uint32_t >(l_idx, 1u));
        }
        [[maybe_unused]] const bool result{sample_db.delete_log_store(store_id)};
        validate_num_stores();
    }

    void set_store_workload_freq(const std::vector< std::pair< size_t, int > >& inp_freqs) {
        int cum_freqs{0};
        sisl::sparse_vector< std::optional< int > > store_freqs;

        for (auto& f : inp_freqs) {
            // No duplication
            ASSERT_EQ(store_freqs[f.first].has_value(), false) << "Input error, frequency list cannot be duplicate";
            store_freqs[f.first] = f.second;
            cum_freqs += f.second;
        }

        ASSERT_LE(cum_freqs, 100) << "Input error, frequency pct cannot exceed 100";
        int default_freq = (100 - cum_freqs) / (sample_db.m_log_store_clients.size() - inp_freqs.size());

        size_t d{0};
        for (size_t s{0}; s < sample_db.m_log_store_clients.size(); ++s) {
            const auto upto{store_freqs[s].has_value() ? *store_freqs[s] : default_freq};
            for (std::remove_const_t<decltype(upto)> i{0}; i < upto; ++i) {
                m_store_distribution[d++] = s;
            }
            LOGINFO("LogStore Client: {} distribution pct = {}", s, upto);
        }
        // Fill in the last reminder with last store
        while (d < 100) {
            m_store_distribution[d++] = sample_db.m_log_store_clients.size() - 1;
        }
    }

private:
    SampleLogStoreClient* pick_log_store() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< size_t > gen_log_store{0, 99};
        return sample_db.m_log_store_clients[m_store_distribution[gen_log_store(re)]].get();
    }

protected:
    std::atomic< int64_t > m_nrecords_waiting_to_issue = 0;
    std::atomic< int64_t > m_nrecords_waiting_to_complete = 0;
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
    std::atomic< logid_t > m_truncate_log_idx = -1;
    std::map< logid_t, uint32_t > m_garbage_stores_upto;
    std::array< uint32_t, 100 > m_store_distribution;

    uint32_t m_q_depth{64};
    uint32_t m_batch_size{1};
    uint32_t m_holes_per_batch{0};
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

    LOGINFO("Step 4.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
    this->iterate_validate(true);

    const uint64_t running_time{SDS_OPTIONS["longevity_tests"].as< uint64_t >()};
    // Exclude dump logstore test from longevity tests
    if (running_time == 0) {
        LOGINFO("Step 4.2: Read all inserts and dump all logstore records into json");
        this->dump_validate(SDS_OPTIONS["num_records"].as< uint32_t >());

        LOGINFO("Step 4.2: Read some specific interval/filter of seq number in one logstore and dump it into json");
        this->dump_validate_filter(0, 10, 100, true);
    }

    LOGINFO("Step 5: Truncate all of the inserts one log store at a time and validate log dev truncation is marked "
            "correctly and also validate if all data prior to truncation return exception");
    this->truncate_validate();
}

TEST_F(LogStoreTest, BurstSeqInsertAndTruncateInParallel) {
    LOGINFO("Step 1: Reinit the num records to start sequential write test");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Issue sequential inserts as a burst");
    this->kickstart_inserts(1, 5000);

    uint16_t trunc_attempt{0};
    LOGINFO("Step 3: In parallel to writes issue truncation upto completion");
    do {
        std::this_thread::sleep_for(std::chrono::microseconds(1000));
        this->truncate_validate(true /* is_parallel_to_write */);
        ++trunc_attempt;
        ASSERT_LT(trunc_attempt, static_cast<uint16_t>(30));
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

TEST_F(LogStoreTest, RandInsertsWithHoles) {
    LOGINFO("Step 1: Reinit the num records to start sequential write test");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Issue randomy within a batch of 10 with 1 hole per batch");
    this->kickstart_inserts(10, 5000, 1);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 4.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
    this->iterate_validate(true);

    LOGINFO("Step 5: Fill the hole and do validation if they are indeed filled");
    this->fill_hole_and_validate();

    LOGINFO("Step 6: Do a final truncation and validate");
    this->truncate_validate();
}

TEST_F(LogStoreTest, VarRateInsertThenTruncate) {
    const auto nrecords{SDS_OPTIONS["num_records"].as< uint32_t >()};
    LOGINFO("Step 1: Reinit the num records={} and insert them as batch of 10 with qdepth=500 and wait for all records "
            "to be inserted and then validate them",
            nrecords);
    this->init(nrecords);
    this->kickstart_inserts(10, 500);
    this->wait_for_inserts();
    this->read_validate(true);
    this->iterate_validate(true);
    this->truncate_validate();

    LOGINFO("Step 2: Stop the workload on stores 0,1 and write num records={} on other stores, wait for their "
            "completion, validate it is readable, then truncate - all in a loop for 3 times",
            nrecords);
    for (auto i{0u}; i < 3u; ++i) {
        LOGINFO("Step 2.{}.1: Write and wait for {}", i + 1, nrecords);
        this->init(nrecords, {{0, 0}, {1, 0}});
        this->kickstart_inserts(10, 500);
        this->wait_for_inserts();
        this->read_validate(true);
        this->iterate_validate(true);

        LOGINFO("Step 2.{}.2: Do a truncation on all log stores and validate", i + 1);
        this->truncate_validate();
    }

    LOGINFO("Step 3: Change data rate on stores 0,1 but still slower than other stores, write num_records={} wait for "
            "their completion, validate it is readable, then truncate - all in a loop for 3 times",
            nrecords);
    for (auto i{0u}; i < 3u; ++i) {
        LOGINFO("Step 3.{}.1: Write and wait for {}", i + 1, nrecords);
        this->init(nrecords, {{0, 5}, {1, 20}});
        this->kickstart_inserts(10, 500);
        this->wait_for_inserts();
        this->read_validate(true);
        this->iterate_validate(true);
        LOGINFO("Step 3.{}.2: Do a truncation on all log stores and validate", i + 1);
        this->truncate_validate();
    }

    LOGINFO("Step 4: Write the data with similar variable data rate, but truncate run in parallel to writes");
    this->init(nrecords, {{0, 20}, {1, 20}});
    this->kickstart_inserts(10, 10);

    for (auto i{0u}; i < 5u; ++i) {
        std::this_thread::sleep_for(std::chrono::microseconds{300});
        LOGINFO("Step 4.{}: Truncating ith time with 200us delay between each truncation", i + 1);
        this->truncate_validate(true);
    }

    this->wait_for_inserts();
    this->read_validate(true);
    this->iterate_validate(true);
    this->truncate_validate();
}

TEST_F(LogStoreTest, ThrottleSeqInsertThenRecover) {
    LOGINFO("Step 1: Reinit the num records to start sequential write test");
    this->init(SDS_OPTIONS["num_records"].as< uint32_t >());

    LOGINFO("Step 2: Issue sequential inserts with q depth of 30");
    this->kickstart_inserts(1, 30);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 4.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
    this->iterate_validate(true);

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

    LOGINFO("Step 9.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
    this->iterate_validate(true);

    LOGINFO("Step 10: Restart homestore again to validate recovery of inserted data after restarts");
    sample_db.start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),                  // num devices
                              SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024, // device sizes
                              SDS_OPTIONS["num_threads"].as< uint32_t >(),               // num threads
                              SDS_OPTIONS["num_logstores"].as< uint32_t >(),             // num log stores
                              true                                                       // restart
    );
    this->recovery_validate();
}

TEST_F(LogStoreTest, DeleteMultipleLogStores) {
    const auto nrecords{(SDS_OPTIONS["num_records"].as< uint32_t >() * 5) / 100};

    LOGINFO("Step 1: Reinit the {} to start sequential write test", nrecords);
    this->init(nrecords);

    LOGINFO("Step 2: Issue sequential inserts with q depth of 40");
    this->kickstart_inserts(1, 40);

    LOGINFO("Step 3: Wait for the Inserts to complete");
    this->wait_for_inserts();

    LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
    this->read_validate(true);

    LOGINFO("Step 4.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
    this->iterate_validate(true);

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

TEST_F(LogStoreTest, WriteSyncThenRead) {
    std::shared_ptr< homestore::HomeLogStore > tmp_log_store{homestore::home_log_store_mgr.create_new_log_store(false)};
    const auto store_id{tmp_log_store->get_store_id()};
    LOGINFO("Created new log store -> id {}", store_id);
    const unsigned count{10};
    for (unsigned i{0}; i < count; ++i) {

        bool io_memory{false};
        auto* const d{SampleLogStoreClient::prepare_data(i, io_memory)};
        const bool succ{tmp_log_store->write_sync(i, {reinterpret_cast< uint8_t* >(d), d->total_size(), false})};
        EXPECT_TRUE(succ);
        LOGINFO("Written sync data for LSN -> {}", i);

        if (io_memory) {
            iomanager.iobuf_free(reinterpret_cast< uint8_t* >(d));
        } else {
            std::free(static_cast< void* >(d));
        }

        auto b{tmp_log_store->read_sync(i)};
        auto* const tl{reinterpret_cast< test_log_data* >(b.bytes())};
        ASSERT_EQ(tl->total_size(), b.size()) << "Size Mismatch for lsn=" << store_id << ":" << i;
        const char c{static_cast<char>((i % 94) + 33)};
        const std::string actual{reinterpret_cast< const char* >(&tl->data[0]), static_cast< size_t >(tl->size)};
        const std::string expected(static_cast< size_t >(tl->size) , c); // needs to be () because of same reason as vector
        ASSERT_EQ(actual, expected) << "Data mismatch for LSN=" << store_id << ":" << i << " size=" << tl->size;
    }

    homestore::home_log_store_mgr.remove_log_store(store_id);
    LOGINFO("Remove logstore -> i {}", store_id);
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
                  cxxopts::value< int32_t >()->default_value("5002"), "port"),
                 (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"),
                 (longevity_tests, "", "longevity_tests", "Run tests for a longer time",
                  ::cxxopts::value< uint64_t >()->default_value("0"), "time in seconds"));

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
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging, test_log_store);
    sds_logging::SetLogger("test_log_store");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");

    auto n_log_stores{SDS_OPTIONS["num_logstores"].as< uint32_t >()};
    if (n_log_stores < 4u) {
        LOGINFO("Log store test needs minimum 4 log stores for testing, setting them to 4");
        n_log_stores = 4u;
    }
    const uint64_t running_time{SDS_OPTIONS["longevity_tests"].as< uint64_t >()};
    int ret{0};
    sample_db.start_homestore(SDS_OPTIONS["num_devs"].as< uint32_t >(),
                              SDS_OPTIONS["dev_size_mb"].as< uint64_t >() * 1024 * 1024,
                              SDS_OPTIONS["num_threads"].as< uint32_t >(), n_log_stores);
    if (running_time == 0) {
        ret = RUN_ALL_TESTS();
    } else {
        Timer tmr;
        LOGINFO("Running longevity test for {} seconds.", running_time);
        ::testing::GTEST_FLAG(filter) = "-LogStoreTest.DeleteMultipleLogStores:LogStoreTest.WriteSyncThenRead";
        uint16_t count{0};
        while ((tmr.elapsed() < running_time) && (ret == 0)) {
            ret = RUN_ALL_TESTS();
            ++count;
            LOGINFO("Running longevity test, iteration {}", count);
        }
        if (ret != 0) {
            LOGERROR("longevity test failed, ran for {} seconds, number of iterations {}", tmr.elapsed(), count);
        }
        else
        {
            LOGINFO("longevity test ended, ran for {} seconds, number of iterations {}", tmr.elapsed(), count);
        }
    }

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
