/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <algorithm> // std::shuffle
#include <array>
#include <atomic>
#include <chrono> // std::chrono::system_clock
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random> // std::default_random_engine
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <sisl/fds/buffer.hpp>
#include <folly/Synchronized.h>
#include <iomgr/io_environment.hpp>
#include <iomgr/http_server.hpp>
#include <iomgr/iomgr_flip.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <gtest/gtest.h>

#include <homestore/homestore.hpp>
#include <homestore/logstore_service.hpp>

#include "logstore/log_dev.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;
RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

struct test_log_data {
    test_log_data() = default;
    test_log_data(const test_log_data&) = delete;
    test_log_data(test_log_data&&) noexcept = delete;
    test_log_data& operator=(const test_log_data&) = delete;
    test_log_data& operator=(test_log_data&&) noexcept = delete;
    ~test_log_data() = default;

    uint32_t size;

    uint8_t* get_data() { return uintptr_cast(this) + sizeof(test_log_data); };
    uint8_t const* get_data_const() const { return r_cast< uint8_t const* >(this) + sizeof(test_log_data); }
    const uint8_t* get_data() const { return r_cast< const uint8_t* >(this) + sizeof(test_log_data); }
    uint32_t total_size() const { return sizeof(test_log_data) + size; }
    std::string get_data_str() const {
        return std::string(r_cast< const char* >(get_data_const()), static_cast< size_t >(size));
    }
};

typedef std::function< void(logdev_id_t, logstore_seq_num_t, logdev_key) > test_log_store_comp_cb_t;
class SampleLogStoreClient {
public:
    SampleLogStoreClient(std::shared_ptr< HomeLogStore > store, const logdev_id_t logdev_id,
                         const test_log_store_comp_cb_t& cb) :
            m_store_id{store->get_store_id()}, m_comp_cb{cb}, m_logdev_id{logdev_id} {
        set_log_store(store);
    }

    explicit SampleLogStoreClient(const logdev_id_t logdev_id, const test_log_store_comp_cb_t& cb) :
            SampleLogStoreClient(logstore_service().create_new_log_store(logdev_id, false /* append_mode */), logdev_id,
                                 cb) {}

    SampleLogStoreClient(const SampleLogStoreClient&) = delete;
    SampleLogStoreClient(SampleLogStoreClient&&) noexcept = delete;
    SampleLogStoreClient& operator=(const SampleLogStoreClient&) = delete;
    SampleLogStoreClient& operator=(SampleLogStoreClient&&) noexcept = delete;
    ~SampleLogStoreClient() = default;

    void set_log_store(std::shared_ptr< HomeLogStore > store) {
        m_log_store = store;
        m_log_store->register_log_found_cb(bind_this(SampleLogStoreClient::on_log_found, 3));
    }

    void reset_recovery() {
        m_n_recovered_lsns = 0;
        m_n_recovered_truncated_lsns = 0;
    }

    void insert_next_batch(uint32_t batch_size) {
        const auto cur_lsn = m_cur_lsn.fetch_add(batch_size);
        LOGINFO("cur_lsn is {} for store {} log_dev {}", cur_lsn, m_log_store->get_store_id(),
                m_log_store->get_logdev()->get_id());
        insert(cur_lsn, batch_size, false);
    }

    void insert(logstore_seq_num_t start_lsn, int64_t nparallel_count, bool wait_for_completion = true) {
        std::vector< logstore_seq_num_t > lsns;
        lsns.reserve(nparallel_count);

        for (auto lsn{start_lsn}; lsn < start_lsn + nparallel_count; ++lsn) {
            lsns.push_back(lsn);
        }

        ASSERT_LT(m_log_store->get_contiguous_issued_seq_num(-1), start_lsn + nparallel_count);
        ASSERT_LT(m_log_store->get_contiguous_completed_seq_num(-1), start_lsn + nparallel_count);
        for (const auto lsn : lsns) {
            bool io_memory{false};
            auto* d = prepare_data(lsn, io_memory);
            m_log_store->write_async(
                lsn, {uintptr_cast(d), d->total_size(), false}, nullptr,
                [io_memory, d, this](logstore_seq_num_t seq_num, const sisl::io_blob& b, logdev_key ld_key, void* ctx) {
                    assert(ld_key);
                    if (io_memory) {
                        iomanager.iobuf_free(uintptr_cast(d));
                    } else {
                        std::free(voidptr_cast(d));
                    }
                    m_comp_cb(m_logdev_id, seq_num, ld_key);
                });
        }

        // Because of restart in tests, we have torce the flush of log entries.
        m_log_store->get_logdev()->flush_if_necessary(1);
    }

    void read_validate(const bool expect_all_completed = false) {
        const auto trunc_upto = m_log_store->truncated_upto();
        for (std::remove_const_t< decltype(trunc_upto) > i{0}; i <= trunc_upto; ++i) {
            ASSERT_THROW(m_log_store->read_sync(i), std::out_of_range)
                << "Expected std::out_of_range exception for lsn=" << m_log_store->get_store_id() << ":" << i
                << " but not thrown";
        }

        const auto upto =
            expect_all_completed ? m_cur_lsn.load() - 1 : m_log_store->get_contiguous_completed_seq_num(-1);
        for (auto i = m_log_store->truncated_upto() + 1; i < upto; ++i) {
            try {
                const auto b = m_log_store->read_sync(i);
                auto* tl = r_cast< test_log_data const* >(b.bytes());
                ASSERT_EQ(tl->total_size(), b.size())
                    << "Size Mismatch for lsn=" << m_log_store->get_store_id() << ":" << i;
                validate_data(tl, i);

            } catch (const std::exception& e) {
                LOGFATAL("Unexpected out_of_range exception for lsn={}:{} upto {} trunc_upto {}",
                         m_log_store->get_store_id(), i, upto, trunc_upto);
            }
        }
    }

    void rollback_validate(uint32_t num_lsns_to_rollback) {
        if ((m_cur_lsn - num_lsns_to_rollback - 1) <= m_log_store->get_contiguous_issued_seq_num(-1)) { return; }
        auto const upto_lsn = m_cur_lsn.fetch_sub(num_lsns_to_rollback) - num_lsns_to_rollback - 1;
        m_log_store->rollback(upto_lsn);
        ASSERT_EQ(m_log_store->get_contiguous_completed_seq_num(-1), upto_lsn)
            << "Last completed seq num is not reset after rollback";
        ASSERT_EQ(m_log_store->get_contiguous_issued_seq_num(-1), upto_lsn)
            << "Last issued seq num is not reset after rollback";
        read_validate(true);
    }

    void recovery_validate() {
        LOGINFO(
            "Totally recovered {} non-truncated lsns and {} truncated lsns for store {} log_dev {} truncated_upto {}",
            m_n_recovered_lsns, m_n_recovered_truncated_lsns, m_log_store->get_store_id(),
            m_log_store->get_logdev()->get_id(), m_truncated_upto_lsn.load());
        if (m_n_recovered_lsns != (m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1)) {
            EXPECT_EQ(m_n_recovered_lsns, m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1)
                << "Recovered " << m_n_recovered_lsns << " valid lsns for store " << m_log_store->get_store_id()
                << " Expected to have " << m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1
                << " lsns: m_cur_lsn=" << m_cur_lsn.load() << " truncated_upto_lsn=" << m_truncated_upto_lsn
                << "store id=" << m_log_store->get_store_id() << " log_dev id=" << m_log_store->get_logdev()->get_id();
            assert(false);
        }
    }

    void on_log_found(const logstore_seq_num_t lsn, const log_buffer buf, void* ctx) {
        // LOGINFO("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
        EXPECT_LE(lsn, m_cur_lsn.load()) << "Recovered incorrect lsn " << m_log_store->get_store_id() << ":" << lsn
                                         << "Expected less than cur_lsn " << m_cur_lsn.load();
        auto* tl = r_cast< test_log_data const* >(buf.bytes());
        validate_data(tl, lsn);

        // Count only the ones which are after truncated, because recovery could receive even truncated lsns
        (lsn > m_truncated_upto_lsn) ? ++m_n_recovered_lsns : ++m_n_recovered_truncated_lsns;
    }

    void truncate(const logstore_seq_num_t lsn) {
        if (lsn <= m_truncated_upto_lsn) return;
        m_log_store->truncate(lsn);
        m_truncated_upto_lsn = lsn;
    }

    void flush() { m_log_store->flush(); }

    bool has_all_lsns_truncated() const { return (m_truncated_upto_lsn.load() == (m_cur_lsn.load() - 1)); }

    static test_log_data* prepare_data(const logstore_seq_num_t lsn, bool& io_memory) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        uint32_t sz{0};
        uint8_t* raw_buf{nullptr};

        // Generate buffer of random size and fill with specific data
        std::uniform_int_distribution< uint8_t > gen_percentage{0, 99};
        std::uniform_int_distribution< uint32_t > gen_data_size{0, max_data_size - 1};
        if (gen_percentage(re) < static_cast< uint8_t >(10)) {
            // 10% of data is dma'ble aligned boundary
            const auto alloc_sz = sisl::round_up(gen_data_size(re) + sizeof(test_log_data), s_max_flush_multiple);
            raw_buf = iomanager.iobuf_alloc(dma_address_boundary, alloc_sz);
            sz = alloc_sz - sizeof(test_log_data);
            io_memory = true;
        } else {
            sz = gen_data_size(re);
            raw_buf = static_cast< uint8_t* >(std::malloc(sizeof(test_log_data) + sz));
            io_memory = false;
        }

        test_log_data* d = new (raw_buf) test_log_data();
        d->size = sz;

        assert(uintptr_cast(d) == raw_buf);

        const char c = static_cast< char >((lsn % 94) + 33);
        std::memset(voidptr_cast(d->get_data()), c, static_cast< size_t >(d->size));
        return d;
    }

private:
    void validate_data(const test_log_data* d, const logstore_seq_num_t lsn) {
        const char c = static_cast< char >((lsn % 94) + 33);
        const std::string actual = d->get_data_str();
        const std::string expected(static_cast< size_t >(d->size),
                                   c); // needs to be () because of same reason as vector
        ASSERT_EQ(actual, expected) << "Data mismatch for LSN=" << m_log_store->get_store_id() << ":" << lsn
                                    << " size=" << d->size;
    }

    friend class LogStoreLongRun;

private:
    static constexpr uint32_t max_data_size = 1024;
    static uint64_t s_max_flush_multiple;

    logstore_id_t m_store_id;
    test_log_store_comp_cb_t m_comp_cb;
    std::atomic< logstore_seq_num_t > m_truncated_upto_lsn = -1;
    std::atomic< logstore_seq_num_t > m_cur_lsn = 0;
    std::shared_ptr< HomeLogStore > m_log_store;
    int64_t m_n_recovered_lsns = 0;
    int64_t m_n_recovered_truncated_lsns = 0;
    logdev_id_t m_logdev_id;
};

uint64_t SampleLogStoreClient::s_max_flush_multiple = 0;

class LogStoreLongRun : public ::testing::Test {
public:
    void start_homestore(bool restart = false) {
        auto n_log_stores = SISL_OPTIONS["num_logstores"].as< uint32_t >();
        auto n_log_devs = SISL_OPTIONS["num_logdevs"].as< uint32_t >();
        if (n_log_stores < 4u) {
            LOGINFO("Log store test needs minimum 4 log stores for testing, setting them to 4");
            n_log_stores = 4u;
        }

        if (restart) {
            for (auto& lsc : m_log_store_clients) {
                lsc->flush();
            }
            m_helper.change_start_cb([this, n_log_stores]() {
                HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
                    // Disable flush and resource mgr timer in UT.
                    s.logstore.flush_timer_frequency_us = 0;
                    s.resource_limits.resource_audit_timer_ms = 0;
                });
                HS_SETTINGS_FACTORY().save();
                for (uint32_t i{0}; i < n_log_stores; ++i) {
                    SampleLogStoreClient* client = m_log_store_clients[i].get();
                    logstore_service().open_logdev(client->m_logdev_id, flush_mode_t::EXPLICIT);
                    logstore_service()
                        .open_log_store(client->m_logdev_id, client->m_store_id, false /* append_mode */)
                        .thenValue([i, this, client](auto log_store) { client->set_log_store(log_store); });
                }
            });
            m_helper.restart_homestore();
        } else {
            m_helper.start_homestore(
                "test_log_store_long_run",
                {{HS_SERVICE::META, {.size_pct = 5.0}},
                 {HS_SERVICE::LOG,
                  {.size_pct = 84.0, .chunk_size = 64 * 1024 * 1024, .min_chunk_size = 8 * 1024 * 1024}}},
                [this, restart, n_log_stores]() {
                    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
                        // Disable flush and resource mgr timer in UT.
                        s.logstore.flush_timer_frequency_us = 0;
                        s.resource_limits.resource_audit_timer_ms = 0;
                    });
                    HS_SETTINGS_FACTORY().save();
                });

            std::vector< logdev_id_t > logdev_id_vec;
            for (uint32_t i{0}; i < n_log_devs; ++i)
                logdev_id_vec.push_back(logstore_service().create_new_logdev(flush_mode_t::EXPLICIT));

            for (uint32_t i{0}; i < n_log_stores; ++i)
                m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
                    logdev_id_vec[i % n_log_devs], bind_this(LogStoreLongRun::on_log_insert_completion, 3)));

            SampleLogStoreClient::s_max_flush_multiple =
                logstore_service().get_logdev(logdev_id_vec[0])->get_flush_size_multiple();
        }
    }

    void shutdown(bool cleanup = true) {
        m_helper.shutdown_homestore(cleanup);
        if (cleanup) { m_log_store_clients.clear(); }
    }

    void delete_log_store(logstore_id_t store_id) {
        for (auto it = std::begin(m_log_store_clients); it != std::end(m_log_store_clients); ++it) {
            if ((*it)->m_log_store->get_store_id() == store_id) {
                auto log_dev_id = (*it)->m_logdev_id;
                logstore_service().remove_log_store(log_dev_id, store_id);
                m_log_store_clients.erase(it);
                break;
            }
        }
    }

    void init() {
        for (auto& lsc : m_log_store_clients) {
            lsc->reset_recovery();
        }
    }

    void kickstart_inserts(uint64_t n_total_records, uint32_t batch_size, uint32_t q_depth) {
        m_nrecords_waiting_to_issue = m_log_store_clients.size() * n_total_records;
        m_nrecords_waiting_to_complete = 0;

        m_batch_size = batch_size;
        m_q_depth = (m_log_store_clients.size() + 1) * q_depth;
        iomanager.run_on_forget(iomgr::reactor_regex::all_io, [this]() { do_insert(); });
    }

    void do_insert() {
        // We insert batch of records for each logstore in round robin fashion.
        auto it = m_log_store_clients.begin();
        for (;;) {
            uint32_t batch_size{0};
            {
                std::unique_lock< std::mutex > lock{m_pending_mtx};
                const bool insert = (m_nrecords_waiting_to_issue > 0) && (m_nrecords_waiting_to_complete < m_q_depth);
                if (insert) {
                    batch_size = std::min< uint32_t >(m_batch_size, m_nrecords_waiting_to_issue);
                    m_nrecords_waiting_to_issue -= batch_size;
                    m_nrecords_waiting_to_complete += batch_size;
                } else {
                    break;
                }
            }

            (*it)->insert_next_batch(batch_size);
            it++;
            if (it == m_log_store_clients.end()) { it = m_log_store_clients.begin(); }
        }
    }

    void on_log_insert_completion(logdev_id_t fid, logstore_seq_num_t lsn, logdev_key ld_key) {
        on_insert_completion(fid, lsn, ld_key);
    }

    void on_insert_completion([[maybe_unused]] logdev_id_t fid, logstore_seq_num_t lsn, logdev_key ld_key) {
        bool notify{false};
        uint64_t waiting_to_issue{0};
        {
            std::unique_lock< std::mutex > lock{m_pending_mtx};
            waiting_to_issue = m_nrecords_waiting_to_issue;
            if ((--m_nrecords_waiting_to_complete == 0) && (waiting_to_issue == 0)) { notify = true; }
        }
        if (notify) {
            m_pending_cv.notify_all();
        } else if (waiting_to_issue > 0) {
            do_insert();
        }
    }

    void wait_for_inserts() {
        std::unique_lock< std::mutex > lk{m_pending_mtx};
        m_pending_cv.wait(lk,
                          [&] { return (m_nrecords_waiting_to_issue == 0) && (m_nrecords_waiting_to_complete == 0); });
    }

    void read_validate(bool expect_all_completed = false) {
        for (const auto& lsc : m_log_store_clients) {
            lsc->read_validate(expect_all_completed);
        }
    }

    void rollback_validate() {
        for (const auto& lsc : m_log_store_clients) {
            lsc->rollback_validate(1);
        }
    }

    void truncate_validate(bool is_parallel_to_write = false) {
        int skip_truncation = 0;

        for (size_t i{0}; i < m_log_store_clients.size(); ++i) {
            const auto& lsc = m_log_store_clients[i];
            const auto t_seq_num = lsc->m_log_store->truncated_upto() + 1;
            const auto c_seq_num = lsc->m_log_store->get_contiguous_completed_seq_num(-1);
            if (t_seq_num == c_seq_num) {
                ++skip_truncation;
                continue;
            }
            lsc->truncate(c_seq_num);
            lsc->read_validate();
        }

        if (skip_truncation) {
            /* not needed to call device truncate as one log store is not truncated */
            return;
        }

        logstore_service().device_truncate();

        validate_num_stores();
    }

    void flush() {
        for (auto& lsc : m_log_store_clients) {
            lsc->flush();
        }
    }

    void recovery_validate() {
        for (size_t i{0}; i < m_log_store_clients.size(); ++i) {
            const auto& lsc = m_log_store_clients[i];
            lsc->recovery_validate();
        }
    }

    void delete_create_logstore() {
        // Delete a random logstore.
        std::uniform_int_distribution< uint64_t > gen{0, m_log_store_clients.size() - 1};
        uint64_t idx = gen(rd);
        delete_log_store(m_log_store_clients[idx]->m_store_id);
        validate_num_stores();

        // Create a new logstore.
        auto logdev_id = logstore_service().create_new_logdev(flush_mode_t::EXPLICIT);
        m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
            logdev_id, bind_this(LogStoreLongRun::on_log_insert_completion, 3)));
        validate_num_stores();
    }

    void validate_num_stores() {
        size_t actual_valid_ids{0};

        for (auto& logdev : logstore_service().get_all_logdevs()) {
            std::vector< logstore_id_t > reg_ids, garbage_ids;
            logdev->get_registered_store_ids(reg_ids, garbage_ids);
            actual_valid_ids += reg_ids.size() - garbage_ids.size();
        }

        ASSERT_EQ(actual_valid_ids, m_log_store_clients.size());
    }

    virtual void SetUp() override { start_homestore(); }
    virtual void TearDown() override { shutdown(true /* cleanup*/); }

    uint64_t get_elapsed_time(Clock::time_point start) {
        std::chrono::seconds sec = std::chrono::duration_cast< std::chrono::seconds >(Clock::now() - start);
        return sec.count();
    }

    bool elapsed(uint64_t print_every_n_secs) {
        static Clock::time_point start = Clock::now();
        auto elapsed_time = get_elapsed_time(start);
        if (elapsed_time > print_every_n_secs) {
            start = Clock::now();
            return true;
        }
        return false;
    }

private:
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;
    uint64_t m_nrecords_waiting_to_issue{0};
    uint64_t m_nrecords_waiting_to_complete{0};
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
    uint32_t m_q_depth{64};
    uint32_t m_batch_size{1};
    std::random_device rd{};
    std::default_random_engine re{rd()};
    test_common::HSTestHelper m_helper;
};

TEST_F(LogStoreLongRun, LongRunning) {
    auto run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    auto num_iterations = SISL_OPTIONS["num_iterations"].as< uint32_t >();
    auto num_records = SISL_OPTIONS["num_records"].as< uint32_t >();
    auto start_time = Clock::now();
    uint32_t iterations = 1;

    init();

    while (true) {
        // Start insert of 100 log entries on all logstores with num batch of 10 in parallel fashion as a burst.
        kickstart_inserts(num_records, 10 /* batch */, 5000 /* q_depth */);

        // Wait for inserts.
        wait_for_inserts();

        if (iterations % 60 == 0) {
            // Validate all the logstores.
            read_validate(true);
        }

        if (iterations % 15 == 0) {
            // Truncate at random lsn every 15 iterations.
            truncate_validate();
        }

        if (iterations % 10 == 0) {
            // Restart at every 30 iterations.
            LOGDEBUG("Restart homestore");
            start_homestore(true /* restart */);
            recovery_validate();
            init();
        }

        if (iterations % 60 == 0) {
            // Add and validate rollback records.
            rollback_validate();
        }

        if (iterations % 10 == 0) {
            // Add and validate rollback records.
            delete_create_logstore();
        }

        if (iterations % 10 == 0) { LOGINFO("Iterations completed {}", iterations); }

        auto elapsed = get_elapsed_time(start_time);
        if (elapsed >= run_time && iterations >= num_iterations) {
            LOGINFO("Finished test. Num iterations {} Elapsed {}", iterations, elapsed);
            break;
        }

        iterations++;
    }
}

SISL_OPTIONS_ENABLE(logging, test_log_store_long_run, iomgr, test_common_setup)
SISL_OPTION_GROUP(test_log_store_long_run,
                  (num_logstores, "", "num_logstores", "number of log stores",
                   ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
                  (num_logdevs, "", "num_logdevs", "number of log devs",
                   ::cxxopts::value< uint32_t >()->default_value("10"), "number"),
                  (num_records, "", "num_records", "number of record to test",
                   ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
                  (num_iterations, "", "num_iterations", "Iterations",
                   ::cxxopts::value< uint32_t >()->default_value("1"), "the number of iterations to run each test"),
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("600"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_log_store_long_run, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_log_store_long_run");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");

    auto num_logstores = SISL_OPTIONS["num_logstores"].as< uint32_t >();
    auto num_logdevs = SISL_OPTIONS["num_logdevs"].as< uint32_t >();

    if (num_logstores < num_logdevs) {
        LOGFATAL("num_logstores {} should be greater or equal than num_logdevs {} to make sure there is at least one "
                 "logstore per logdev",
                 num_logstores, num_logdevs);
    }

    return RUN_ALL_TESTS();
}
