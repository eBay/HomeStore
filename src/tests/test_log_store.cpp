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
class Timer {
public:
    Timer() : beg_{clock_::now()} {}
    Timer(const Timer&) = delete;
    Timer(Timer&&) noexcept = delete;
    Timer& operator=(const Timer&) = delete;
    Timer& operator=(Timer&&) noexcept = delete;
    ~Timer() = default;

    void reset() { beg_ = clock_::now(); }
    double elapsed() const { return std::chrono::duration_cast< second_ >(clock_::now() - beg_).count(); }

private:
    typedef std::chrono::high_resolution_clock clock_;
    typedef std::chrono::duration< double, std::ratio< 1 > > second_;
    std::chrono::time_point< clock_ > beg_;
};

class SampleLogStoreClient {
public:
    friend class SampleDB;

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

    void insert_next_batch(uint32_t batch_size, uint32_t nholes = 0) {
        const auto cur_lsn = m_cur_lsn.fetch_add(batch_size + nholes);
        insert(cur_lsn, batch_size, nholes, false);
    }

    void insert(logstore_seq_num_t start_lsn, int64_t nparallel_count, int64_t nholes = 0,
                bool wait_for_completion = true) {
        std::vector< logstore_seq_num_t > lsns;
        lsns.reserve(nparallel_count + nholes);

        // Shuffle ids within the range for count
        for (auto lsn{start_lsn}; lsn < start_lsn + nparallel_count + nholes; ++lsn) {
            lsns.push_back(lsn);
        }
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::shuffle(lsns.begin(), lsns.end(), re);

        ASSERT_LT(m_log_store->get_contiguous_issued_seq_num(-1), start_lsn + nparallel_count + nholes);
        ASSERT_LT(m_log_store->get_contiguous_completed_seq_num(-1), start_lsn + nparallel_count + nholes);
        for (const auto lsn : lsns) {
            if (nholes) {
                m_hole_lsns.wlock()->insert(std::make_pair<>(lsn, false));
                --nholes;
            } else {
                bool io_memory{false};
                auto* d = prepare_data(lsn, io_memory);
                m_log_store->write_async(lsn, {uintptr_cast(d), d->total_size(), false}, nullptr,
                                         [io_memory, d, this](logstore_seq_num_t seq_num, const sisl::io_blob& b,
                                                              logdev_key ld_key, void* ctx) {
                                             assert(ld_key);
                                             if (io_memory) {
                                                 iomanager.iobuf_free(uintptr_cast(d));
                                             } else {
                                                 std::free(voidptr_cast(d));
                                             }
                                             m_comp_cb(m_logdev_id, seq_num, ld_key);
                                         });
            }
        }

        // Because of restart in tests, we have torce the flush of log entries.
        m_log_store->get_logdev()->flush_if_necessary(1);
    }

    void iterate_validate(const bool expect_all_completed = false) {
        const auto trunc_upto = m_log_store->truncated_upto();
        const auto& hole_end = m_hole_lsns.rlock()->end();
        const auto upto =
            expect_all_completed ? m_cur_lsn.load() - 1 : m_log_store->get_contiguous_completed_seq_num(-1);

        int64_t idx = trunc_upto + 1;
        bool hole_expected{false};
    start_iterate:
        try {
            auto hole_entry = m_hole_lsns.rlock()->find(idx);
            if ((hole_entry != hole_end) && !hole_entry->second) { // Hole entry exists and not filled
                ASSERT_THROW(m_log_store->read_sync(idx), std::out_of_range)
                    << "Expected std::out_of_range exception for read of hole lsn=" << m_log_store->get_store_id()
                    << ":" << idx << " but not thrown";
                hole_expected = true;
            } else {
                m_log_store->foreach (
                    idx,
                    [upto, hole_end, &idx, &hole_expected, &hole_entry, this](const int64_t seq_num,
                                                                              const log_buffer& b) -> bool {
                        if ((hole_entry != hole_end) && hole_entry->second) { // Hole entry exists, but filled
                            EXPECT_EQ(b.size(), 0ul);
                        } else {
                            auto const* tl = r_cast< test_log_data const* >(b.bytes());
                            EXPECT_EQ(tl->total_size(), b.size());
                            validate_data(tl, seq_num);
                        }
                        ++idx;
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
                const auto trunc_upto = m_log_store->truncated_upto();
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
        const auto trunc_upto = m_log_store->truncated_upto();
        for (std::remove_const_t< decltype(trunc_upto) > i{0}; i <= trunc_upto; ++i) {
            ASSERT_THROW(m_log_store->read_sync(i), std::out_of_range)
                << "Expected std::out_of_range exception for lsn=" << m_log_store->get_store_id() << ":" << i
                << " but not thrown";
        }

        const auto& hole_end = m_hole_lsns.rlock()->end();
        const auto upto =
            expect_all_completed ? m_cur_lsn.load() - 1 : m_log_store->get_contiguous_completed_seq_num(-1);
        for (auto i = m_log_store->truncated_upto() + 1; i < upto; ++i) {
            const auto hole_entry = m_hole_lsns.rlock()->find(i);
            if ((hole_entry != hole_end) && (!hole_entry->second)) { // Hole entry exists and not filled
                ASSERT_THROW(m_log_store->read_sync(i), std::out_of_range)
                    << "Expected std::out_of_range exception for read of hole lsn=" << m_log_store->get_store_id()
                    << ":" << i << " but not thrown";
            } else {
                try {
                    const auto b = m_log_store->read_sync(i);

                    if ((hole_entry != hole_end) && (hole_entry->second)) { // Hole entry exists, but filled
                        ASSERT_EQ(b.size(), 0ul)
                            << "Expected null entry for lsn=" << m_log_store->get_store_id() << ":" << i;
                    } else {
                        auto* tl = r_cast< test_log_data const* >(b.bytes());
                        ASSERT_EQ(tl->total_size(), b.size())
                            << "Size Mismatch for lsn=" << m_log_store->get_store_id() << ":" << i;
                        validate_data(tl, i);
                    }
                } catch (const std::exception& e) {
                    logstore_seq_num_t trunc_upto = m_log_store->truncated_upto();
                    if (!expect_all_completed) {
                        LOGINFO("got store {} trunc_upto {} {} {}", m_log_store->get_store_id(), trunc_upto, i,
                                m_log_store->log_records().get_status(2).dump(' ', 2));
                        if (i <= trunc_upto) {
                            i = trunc_upto;
                            continue;
                        }
                    }
                    LOGINFO("Unexpected out_of_range exception for lsn={}:{} upto {} trunc_upto {}",
                            m_log_store->get_store_id(), i, upto, trunc_upto);
                    LOGFATAL("");
                }
            }
        }
    }

    logstore_seq_num_t get_truncated_upto() { return m_log_store->truncated_upto(); }

    void fill_hole_and_validate() {
        const auto start = m_log_store->truncated_upto();
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
        LOGINFO("Totally recovered {} non-truncated lsns and {} truncated lsns for store {} log_dev {}",
                m_n_recovered_lsns, m_n_recovered_truncated_lsns, m_log_store->get_store_id(),
                m_log_store->get_logdev()->get_id());
        if (m_truncated_upto_lsn.load() > 0 &&
            m_n_recovered_lsns != (m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1)) {
            EXPECT_EQ(m_n_recovered_lsns, m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1)
                << "Recovered " << m_n_recovered_lsns << " valid lsns for store " << m_log_store->get_store_id()
                << " Expected to have " << m_cur_lsn.load() - m_truncated_upto_lsn.load() - 1
                << " lsns: m_cur_lsn=" << m_cur_lsn.load() << " truncated_upto_lsn=" << m_truncated_upto_lsn;
            assert(false);
        }
    }

    void rollback_validate(uint32_t num_lsns_to_rollback) {
        auto const upto_lsn = m_cur_lsn.fetch_sub(num_lsns_to_rollback) - num_lsns_to_rollback - 1;
        m_log_store->rollback(upto_lsn);
        ASSERT_EQ(m_log_store->get_contiguous_completed_seq_num(-1), upto_lsn)
            << "Last completed seq num is not reset after rollback";
        ASSERT_EQ(m_log_store->get_contiguous_issued_seq_num(-1), upto_lsn)
            << "Last issued seq num is not reset after rollback";
        read_validate(true);
    }

    void read(const logstore_seq_num_t lsn) {
        ASSERT_GT(lsn, m_truncated_upto_lsn);
        // m_log_store->read(id);
    }

    void rollback_record_count(uint32_t expected_count) {
        auto actual_count = m_log_store->get_logdev()->log_dev_meta().num_rollback_records(m_log_store->get_store_id());
        ASSERT_EQ(actual_count, expected_count);
    }

    void on_log_found(const logstore_seq_num_t lsn, const log_buffer buf, void* ctx) {
        LOGDEBUG("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
        EXPECT_LE(lsn, m_cur_lsn.load()) << "Recovered incorrect lsn " << m_log_store->get_store_id() << ":" << lsn
                                         << "Expected less than cur_lsn " << m_cur_lsn.load();
        auto* tl = r_cast< test_log_data const* >(buf.bytes());
        validate_data(tl, lsn);

        // Count only the ones which are after truncated, because recovery could receive even truncated lsns
        (lsn > m_truncated_upto_lsn) ? ++m_n_recovered_lsns : ++m_n_recovered_truncated_lsns;
    }

    void truncate(const logstore_seq_num_t lsn) {
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

    friend class LogStoreTest;

private:
    static constexpr uint32_t max_data_size = 1024;
    static uint64_t s_max_flush_multiple;

    logstore_id_t m_store_id;
    test_log_store_comp_cb_t m_comp_cb;
    std::atomic< logstore_seq_num_t > m_truncated_upto_lsn = -1;
    std::atomic< logstore_seq_num_t > m_cur_lsn = 0;
    std::shared_ptr< HomeLogStore > m_log_store;
    folly::Synchronized< std::map< logstore_seq_num_t, bool > > m_hole_lsns;
    int64_t m_n_recovered_lsns = 0;
    int64_t m_n_recovered_truncated_lsns = 0;
    logdev_id_t m_logdev_id;
};

uint64_t SampleLogStoreClient::s_max_flush_multiple = 0;

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

    static SampleDB& instance() {
        static SampleDB inst;
        return inst;
    }

    void start_homestore(bool restart = false) {
        auto n_log_devs = SISL_OPTIONS["num_logdevs"].as< uint32_t >();
        auto n_log_stores = SISL_OPTIONS["num_logstores"].as< uint32_t >();

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
                "test_log_store",
                {{HS_SERVICE::META, {.size_pct = 5.0}},
                 {HS_SERVICE::LOG,
                  {.size_pct = 84.0, .chunk_size = 8 * 1024 * 1024, .min_chunk_size = 8 * 1024 * 1024}}},
                [this, restart, n_log_stores]() {
                    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
                        // Disable flush and resource mgr timer in UT.
                        s.logstore.flush_timer_frequency_us = 0;
                        s.resource_limits.resource_audit_timer_ms = 0;
                    });
                    HS_SETTINGS_FACTORY().save();
                });

            std::vector< logdev_id_t > logdev_id_vec;
            for (uint32_t i{0}; i < n_log_devs; ++i) {
                logdev_id_vec.push_back(logstore_service().create_new_logdev(flush_mode_t::EXPLICIT));
            }

            for (uint32_t i{0}; i < n_log_stores; ++i) {
                m_log_store_clients.push_back(std::make_unique< SampleLogStoreClient >(
                    logdev_id_vec[i % n_log_devs], bind_this(SampleDB::on_log_insert_completion, 3)));
            }
            SampleLogStoreClient::s_max_flush_multiple =
                logstore_service().get_logdev(logdev_id_vec[0])->get_flush_size_multiple();
        }
    }

    void shutdown(bool cleanup = true) {
        m_helper.shutdown_homestore(cleanup);
        if (cleanup) {
            m_log_store_clients.clear();
            std::unique_lock lock{m_completion_mtx};
            m_highest_log_idx.clear();
        }
    }

    void on_log_insert_completion(logdev_id_t fid, logstore_seq_num_t lsn, logdev_key ld_key) {
        {
            std::unique_lock lock{m_completion_mtx};
            if (m_highest_log_idx.count(fid) == 0) { m_highest_log_idx[fid] = std::atomic{-1}; }
            atomic_update_max(m_highest_log_idx[fid], ld_key.idx);
        }

        if (m_io_closure) m_io_closure(fid, lsn, ld_key);
    }

    bool delete_log_store(logstore_id_t store_id) {
        bool removed{false};
        for (auto it = std::begin(m_log_store_clients); it != std::end(m_log_store_clients); ++it) {
            if ((*it)->m_log_store->get_store_id() == store_id) {
                logstore_service().remove_log_store((*it)->m_logdev_id, store_id);
                m_log_store_clients.erase(it);
                removed = true;
                break;
            }
        }
        return removed;
    }

    logid_t highest_log_idx(logdev_id_t fid) {
        std::unique_lock lock{m_completion_mtx};
        return m_highest_log_idx.count(fid) ? m_highest_log_idx[fid].load() : -1;
    }

private:
    std::vector< std::string > m_dev_names;
    std::function< void() > m_on_schedule_io_cb;
    test_log_store_comp_cb_t m_io_closure;
    std::vector< std::unique_ptr< SampleLogStoreClient > > m_log_store_clients;
    std::map< logdev_id_t, std::atomic< logid_t > > m_highest_log_idx;
    test_common::HSTestHelper m_helper;
    std::mutex m_completion_mtx;
};

class LogStoreTest : public ::testing::Test {
public:
    LogStoreTest() = default;
    LogStoreTest(const LogStoreTest&) = delete;
    LogStoreTest(LogStoreTest&&) noexcept = delete;
    LogStoreTest& operator=(const LogStoreTest&) = delete;
    LogStoreTest& operator=(LogStoreTest&&) noexcept = delete;
    virtual ~LogStoreTest() override = default;

protected:
    virtual void SetUp() override { SampleDB::instance().start_homestore(); };
    virtual void TearDown() override { SampleDB::instance().shutdown(); };

    void init(uint64_t n_total_records, const std::vector< std::pair< size_t, int > >& inp_freqs = {}) {
        // m_nrecords_waiting_to_issue = std::lround(n_total_records / _batch_size) * _batch_size;
        m_nrecords_waiting_to_issue = n_total_records;
        m_nrecords_waiting_to_complete = 0;
        SampleDB::instance().m_on_schedule_io_cb = std::bind(&LogStoreTest::do_insert, this);
        SampleDB::instance().m_io_closure = bind_this(LogStoreTest::on_insert_completion, 3);

        for (auto& lsc : SampleDB::instance().m_log_store_clients) {
            lsc->reset_recovery();
        }
        set_store_workload_freq(inp_freqs); // Equal distribution by default
    }

    void kickstart_inserts(uint32_t batch_size, uint32_t q_depth, uint32_t holes_per_batch = 0) {
        m_batch_size = batch_size;
        m_q_depth = q_depth;
        m_holes_per_batch = holes_per_batch;
        iomanager.run_on_forget(iomgr::reactor_regex::all_io, []() {
            if (SampleDB::instance().m_on_schedule_io_cb) SampleDB::instance().m_on_schedule_io_cb();
        });
    }

    void do_insert() {
        // Randomly pick a store client and write journal entry batch.
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
            pick_log_store()->insert_next_batch(batch_size, std::min(batch_size, m_holes_per_batch));
        }
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
        for (const auto& lsc : SampleDB::instance().m_log_store_clients) {
            lsc->read_validate(expect_all_completed);
        }
    }

    void iterate_validate(bool expect_all_completed = false) {
        for (const auto& lsc : SampleDB::instance().m_log_store_clients) {
            lsc->iterate_validate(expect_all_completed);
        }
    }
    void dump_validate(int64_t expected_num_records, bool print_content = false) {
        log_dump_req dump_req;
        if (print_content) dump_req.verbosity_level = log_dump_verbosity::CONTENT;
        // must use operator= construction as copy construction results in error

        size_t dump_sz{0};
        int64_t rec_count{0};
        auto logdev_vec = logstore_service().get_all_logdevs();
        for (auto& logdev : logdev_vec) {
            nlohmann::json json_dump = logdev->dump_log_store(dump_req);
            dump_sz += json_dump.size();

            LOGDEBUG("Printing json dump of all logstores in logdev {}. \n {}", logdev->get_id(), json_dump.dump());
            for (const auto& logdump : json_dump) {
                const auto itr = logdump.find("log_records");
                if (itr != std::end(logdump)) { rec_count += static_cast< int64_t >(logdump["log_records"].size()); }
            }
        }
        EXPECT_EQ(SampleDB::instance().m_log_store_clients.size(), dump_sz);
        EXPECT_EQ(expected_num_records, rec_count);
    }

    void dump_validate_filter(bool print_content = false) {
        for (const auto& lsc : SampleDB::instance().m_log_store_clients) {
            logstore_id_t id = lsc->m_log_store->get_store_id();
            const auto fid = lsc->m_logdev_id;
            logstore_seq_num_t start_seq = lsc->m_log_store->truncated_upto() + 1;
            logstore_seq_num_t end_seq = lsc->m_log_store->get_contiguous_completed_seq_num(-1);
            log_dump_req dump_req;
            if (print_content) dump_req.verbosity_level = log_dump_verbosity::CONTENT;
            dump_req.log_store = lsc->m_log_store;
            dump_req.start_seq_num = start_seq;
            dump_req.end_seq_num = end_seq;

            // must use operator= construction as copy construction results in error
            auto logdev = lsc->m_log_store->get_logdev();
            nlohmann::json json_dump = logdev->dump_log_store(dump_req);
            LOGDEBUG("Printing json dump of log_dev={} logstore id {}, start_seq {}, end_seq {}, \n\n {}", fid, id,
                     start_seq, end_seq, json_dump.dump());
            const auto itr_id = json_dump.find(std::to_string(id));
            if (itr_id != std::end(json_dump)) {
                const auto itr_records = itr_id->find("log_records");
                if (itr_records != std::end(*itr_id)) {
                    EXPECT_EQ(static_cast< size_t >(end_seq - start_seq + 1), itr_records->size());
                } else {
                    EXPECT_FALSE(true);
                }
            } else {
                EXPECT_FALSE(true);
            }
        }
        return;
    }

    int find_garbage_upto(logdev_id_t logdev_id, logid_t idx) {
        int count{0};
        auto it = std::begin(m_garbage_stores_upto[logdev_id]);

        while (it != std::end(m_garbage_stores_upto[logdev_id])) {
            if (it->first > idx) { return count; }
            ++it;
            ++count;
        }
        return count;
    }

    void fill_hole_and_validate() {
        for (size_t i = 0; i < SampleDB::instance().m_log_store_clients.size(); ++i) {
            const auto& lsc = SampleDB::instance().m_log_store_clients[i];
            lsc->fill_hole_and_validate();
        }
    }

    void truncate_validate(bool is_parallel_to_write = false) {
        int skip_truncation = 0;
        for (size_t i{0}; i < SampleDB::instance().m_log_store_clients.size(); ++i) {
            const auto& lsc = SampleDB::instance().m_log_store_clients[i];

            // lsc->truncate(lsc->m_cur_lsn.load() - 1);
            const auto t_seq_num = lsc->m_log_store->truncated_upto();
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

        bool expect_forward_progress{true};
        uint32_t n_fully_truncated{0};
        if (is_parallel_to_write) {
            for (const auto& lsc : SampleDB::instance().m_log_store_clients) {
                if (lsc->has_all_lsns_truncated()) ++n_fully_truncated;
            }

            // While inserts are going on, truncation can guaranteed to be forward progressed if none of the
            // log stores are fully truncated. If all stores are fully truncated, its obvious no progress,
            // but even if one of the store is fully truncated, then it might be possible that logstore is
            // holding lowest logdev location and waiting for next flush to finish to move the safe logdev
            // location.
            expect_forward_progress = (n_fully_truncated == 0);
        }

        if (expect_forward_progress) {
            // we have multiple log_store for each logdev, so we need to update the highest truncated lsn and then do
            // the verification
            for (const auto& lsc : SampleDB::instance().m_log_store_clients) {
                auto fid = lsc->m_log_store->get_logdev()->get_id();
                auto trunc_loc = lsc->m_log_store->get_trunc_ld_key();
                if (trunc_loc == logdev_key::out_of_bound_ld_key()) {
                    LOGINFO("No forward progress for device truncation yet.")
                } else {
                    auto idx = m_truncate_log_idx.count(fid) ? m_truncate_log_idx[fid].load() : -1;
                    if (trunc_loc.idx > m_truncate_log_idx[fid].load()) {
                        m_truncate_log_idx[fid].store(trunc_loc.idx);
                    }
                }
            }
        } else {
            LOGINFO("Do not expect forward progress for device truncation");
        }

        for (auto& logdev : logstore_service().get_all_logdevs()) {
            auto fid = logdev->get_id();
            auto idx = m_truncate_log_idx.count(fid) ? m_truncate_log_idx[fid].load() : -1;
            const auto upto_count = find_garbage_upto(fid, idx);
            std::remove_const_t< decltype(upto_count) > count{0};
            for (auto it = std::begin(m_garbage_stores_upto[fid]); count < upto_count; ++count) {
                it = m_garbage_stores_upto[fid].erase(it);
            }
        }

        validate_num_stores();
    }

    void flush() {
        for (auto& lsc : SampleDB::instance().m_log_store_clients) {
            lsc->flush();
        }
    }

    void recovery_validate() {
        for (size_t i{0}; i < SampleDB::instance().m_log_store_clients.size(); ++i) {
            const auto& lsc = SampleDB::instance().m_log_store_clients[i];
            lsc->recovery_validate();
        }
    }

    void rollback_validate(uint32_t num_lsns_to_rollback) { pick_log_store()->rollback_validate(num_lsns_to_rollback); }

    void post_truncate_rollback_validate() {
        for (size_t i{0}; i < SampleDB::instance().m_log_store_clients.size(); ++i) {
            const auto& lsc = SampleDB::instance().m_log_store_clients[i];
            lsc->rollback_record_count(0ul);
        }
    }

    void reset_recovery() {
        for (size_t i{0}; i < SampleDB::instance().m_log_store_clients.size(); ++i) {
            const auto& lsc = SampleDB::instance().m_log_store_clients[i];
            lsc->reset_recovery();
        }
    }

    void validate_num_stores() {
        size_t actual_valid_ids{0};
        size_t actual_garbage_ids{0};
        size_t exp_garbage_store_count{0};

        for (auto& logdev : logstore_service().get_all_logdevs()) {
            auto fid = logdev->get_id();
            std::vector< logstore_id_t > reg_ids, garbage_ids;

            logdev->get_registered_store_ids(reg_ids, garbage_ids);
            actual_valid_ids += reg_ids.size() - garbage_ids.size();
            actual_garbage_ids += garbage_ids.size();

            auto upto_count = find_garbage_upto(fid, SampleDB::instance().highest_log_idx(fid) + 1);
            decltype(upto_count) count{0};
            for (auto it = std::begin(m_garbage_stores_upto[fid]); count < upto_count; ++it, ++count) {
                exp_garbage_store_count += it->second;
            }
        }
        ASSERT_EQ(actual_valid_ids, SampleDB::instance().m_log_store_clients.size());
        // Becasue we randomly assign logstore to logdev, some logdev will be empty.
        // ASSERT_EQ(actual_garbage_ids, exp_garbage_store_count);
    }

    void delete_validate(uint32_t idx) {
        auto& db = SampleDB::instance();
        auto fid = db.m_log_store_clients[idx]->m_logdev_id;
        validate_num_stores();

        const auto l_idx = db.highest_log_idx(fid);
        if (m_garbage_stores_upto[fid].find(l_idx) != m_garbage_stores_upto[fid].end()) {
            m_garbage_stores_upto[fid][l_idx]++;
        } else {
            m_garbage_stores_upto[fid].insert(std::pair< logid_t, uint32_t >(l_idx, 1u));
        }

        db.delete_log_store(db.m_log_store_clients[idx]->m_store_id);
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
        int default_freq = (100 - cum_freqs) / (SampleDB::instance().m_log_store_clients.size() - inp_freqs.size());

        size_t d{0};
        std::string print_str("LogStore Client/Distribution pct: ");
        for (size_t s{0}; s < SampleDB::instance().m_log_store_clients.size(); ++s) {
            const auto upto = store_freqs[s].has_value() ? *store_freqs[s] : default_freq;
            for (std::remove_const_t< decltype(upto) > i{0}; i < upto; ++i) {
                m_store_distribution[d++] = s;
            }
            fmt::format_to(std::back_inserter(print_str), "[{}]={} ", s, upto);
        }
        LOGINFO("{}", print_str);

        // Fill in the last reminder with last store
        while (d < 100) {
            m_store_distribution[d++] = SampleDB::instance().m_log_store_clients.size() - 1;
        }
    }

private:
    SampleLogStoreClient* pick_log_store() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< size_t > gen_log_store{0, 99};
        return SampleDB::instance().m_log_store_clients[m_store_distribution[gen_log_store(re)]].get();
    }

protected:
    uint64_t m_nrecords_waiting_to_issue{0};
    uint64_t m_nrecords_waiting_to_complete{0};
    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
    std::map< logdev_id_t, std::atomic< logid_t > > m_truncate_log_idx;
    std::map< logdev_id_t, std::map< logid_t, uint32_t > > m_garbage_stores_upto;
    std::array< uint32_t, 100 > m_store_distribution;

    uint32_t m_q_depth{64};
    uint32_t m_batch_size{1};
    uint32_t m_holes_per_batch{0};
};

TEST_F(LogStoreTest, BurstRandInsertThenTruncate) {
    const auto num_records = SISL_OPTIONS["num_records"].as< uint32_t >();
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        LOGINFO("Step 1: Prepare num records and create reqd log stores");
        this->init(num_records);

        LOGINFO("Step 2: Inserting randomly within a batch of 10 in parallel fashion as a burst");
        this->kickstart_inserts(10, 5000);

        LOGINFO("Step 3: Wait for the Inserts to complete");
        this->wait_for_inserts();

        LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
        this->read_validate(true);

        LOGINFO("Step 4.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
        this->iterate_validate(true);

        // Exclude dump from further iterations
        if (iteration == 0) {
            LOGINFO("Step 4.2: Read all inserts and dump all logstore records into json");
            this->dump_validate(num_records);

            LOGINFO("Step 4.2: Read some specific interval/filter of seq number in one logstore and dump it into json");
            this->dump_validate_filter(true);
        }

        LOGINFO("Step 5: Truncate all of the inserts one log store at a time and validate log dev truncation is marked "
                "correctly and also validate if all data prior to truncation return exception");
        this->truncate_validate();

        LOGINFO("Step 6: Restart homestore");
        SampleDB::instance().start_homestore(true /* restart */);
        this->recovery_validate();
        this->init(num_records);

        LOGINFO("Step 7: Issue more sequential inserts after restarts with q depth of 15");
        this->kickstart_inserts(1, 15);

        LOGINFO("Step 8: Wait for the previous Inserts to complete");
        this->wait_for_inserts();

        LOGINFO("Step 9: Read all the inserts one by one for each log store to validate if what is written is valid");
        this->read_validate(true);
    }
}

TEST_F(LogStoreTest, BurstSeqInsertAndTruncateInParallel) {
    const auto num_records = SISL_OPTIONS["num_records"].as< uint32_t >();
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        LOGINFO("Step 1: Reinit the num records to start sequential write test");
        this->init(num_records);

        LOGINFO("Step 2: Issue sequential inserts as a burst");
        this->kickstart_inserts(1, 5000);

        uint16_t trunc_attempt{0};
        LOGINFO("Step 3: In parallel to writes issue truncation upto completion");
        uint64_t nrecords_waiting_to_complete{0};
        uint64_t nrecords_waiting_to_issue{0};
        do {
            std::this_thread::sleep_for(std::chrono::microseconds(1000));
            this->truncate_validate(true /* is_parallel_to_write */);
            {
                std::unique_lock< std::mutex > lock{m_pending_mtx};
                nrecords_waiting_to_complete = this->m_nrecords_waiting_to_complete;
                nrecords_waiting_to_issue = this->m_nrecords_waiting_to_issue;
            }
            LOGINFO("Still pending completions = {}, pending issued = {}", nrecords_waiting_to_complete,
                    nrecords_waiting_to_issue);
        } while (((nrecords_waiting_to_complete > 0) || (nrecords_waiting_to_issue > 0)));
        LOGINFO("Truncation has been issued and validated for {} times before all records are completely truncated",
                trunc_attempt);

        LOGINFO("Step 4: Wait for the Inserts to complete");
        this->wait_for_inserts();

        LOGINFO("Step 5: Do a final truncation and validate");
        this->truncate_validate();
    }
}

TEST_F(LogStoreTest, RandInsertsWithHoles) {
    const auto num_records = SISL_OPTIONS["num_records"].as< uint32_t >();
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        LOGINFO("Step 1: Reinit the num records to start sequential write test");
        this->init(num_records);

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
}

TEST_F(LogStoreTest, VarRateInsertThenTruncate) {
    const auto nrecords = SISL_OPTIONS["num_records"].as< uint32_t >();
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        LOGINFO("Step 1: Reinit the num records={} and insert them as batch of 10 with qdepth=500 and wait for all "
                "records "
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

        LOGINFO("Step 3: Change data rate on stores 0,1 but still slower than other stores, write num_records={} "
                "wait for "
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
}

TEST_F(LogStoreTest, ThrottleSeqInsertThenRecover) {
    // somewhere between 4-15 iterations depending on if run with other tests or not this will fail
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();
    const auto num_records = SISL_OPTIONS["num_records"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        LOGINFO("Step 1: Reinit the num records to start sequential write test");
        this->init(num_records);

        LOGINFO("Step 2: Issue sequential inserts with q depth of 30");
        this->kickstart_inserts(1, 30);

        LOGINFO("Step 3: Wait for the Inserts to complete");
        this->wait_for_inserts();

        LOGINFO("Step 4: Read all the inserts one by one for each log store to validate if what is written is valid");
        this->read_validate(true);

        LOGINFO("Step 4.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
        this->iterate_validate(true);

        LOGINFO("Step 5: Restart homestore");
        SampleDB::instance().start_homestore(true);
        this->recovery_validate();
        this->init(num_records);

        LOGINFO("Step 5a: Read all the inserts one by one for each log store to validate if what is written is valid");
        this->read_validate(true);

        LOGINFO("Step 6: Restart homestore again to validate recovery on consecutive restarts");
        SampleDB::instance().start_homestore(true);
        this->recovery_validate();
        this->init(num_records);

        LOGINFO("Step 7: Issue more sequential inserts after restarts with q depth of 15");
        this->kickstart_inserts(1, 15);

        LOGINFO("Step 8: Wait for the previous Inserts to complete");
        this->wait_for_inserts();

        LOGINFO("Step 9: Read all the inserts one by one for each log store to validate if what is written is valid");
        this->read_validate(true);

        LOGINFO("Step 9.1: Iterate all inserts one by one for each log store and validate if what is written is valid");
        this->iterate_validate(true);

        LOGINFO("Step 10: Restart homestore again to validate recovery after inserts");
        SampleDB::instance().start_homestore(true);
        this->recovery_validate();
        this->init(num_records);

        LOGINFO("Step 11: Truncate");
        this->truncate_validate();
    }
}

TEST_F(LogStoreTest, FlushSync) {
    LOGINFO("Step 1: Delay the flush threshold and flush timer to very high value to ensure flush works fine")
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.logstore.max_time_between_flush_us = 5000000ul; // 5 seconds
        s.logstore.flush_threshold_size = 1048576ul;      // 1MB
    });
    HS_SETTINGS_FACTORY().save();

    LOGINFO("Step 2: Reinit the 10 records to start sequential write test");
    this->init(1000);

    LOGINFO("Step 3: Issue sequential inserts with q depth of 10");
    this->kickstart_inserts(1, 10);

    LOGINFO("Step 4: Do a sync flush");
    this->flush();

    LOGINFO("Step 5: Reset the settings back")
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.logstore.max_time_between_flush_us = 300ul;
        s.logstore.flush_threshold_size = 64ul;
    });
    HS_SETTINGS_FACTORY().save();

    LOGINFO("Step 6: Wait for the Inserts to complete");
    this->wait_for_inserts();

#ifdef _PRERELEASE
    LOGINFO("Step 7: Simulate flush_sync running parallel to regular flush. This is achieved by doing flip to delay "
            "regular flush and do flush_sync");
    flip::FlipClient* fc = iomgr_flip::client_instance();

    flip::FlipFrequency freq;
    freq.set_count(1);
    freq.set_percent(100);

    flip::FlipCondition dont_care_cond;
    fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &dont_care_cond);
    fc->inject_delay_flip("simulate_log_flush_delay", {dont_care_cond}, freq, 5000000); // Delay by 5seconds
#endif

    LOGINFO("Step 8: Reissue sequential inserts with q depth of 10");
    this->init(10);
    this->kickstart_inserts(1, 10);

    LOGINFO("Step 9: Do a parallel sync flush");
    this->flush();

    LOGINFO("Step 10: Wait for the Inserts to complete");
    this->wait_for_inserts();

#ifdef _PRERELEASE
    fc->remove_flip("simulate_log_flush_delay");
#endif
}

TEST_F(LogStoreTest, DeleteMultipleLogStores) {
    const auto nrecords = (SISL_OPTIONS["num_records"].as< uint32_t >() * 5) / 100;

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
    const auto iterations = SISL_OPTIONS["iterations"].as< uint32_t >();

    for (uint32_t iteration{0}; iteration < iterations; ++iteration) {
        LOGINFO("Iteration {}", iteration);
        auto logdev_id = logstore_service().create_new_logdev(flush_mode_t::EXPLICIT);
        auto tmp_log_store = logstore_service().create_new_log_store(logdev_id, false);
        const auto store_id = tmp_log_store->get_store_id();
        LOGINFO("Created new log store -> id {}", store_id);
        const unsigned count{10};
        for (unsigned i{0}; i < count; ++i) {

            bool io_memory{false};
            auto* d = SampleLogStoreClient::prepare_data(i, io_memory);
            tmp_log_store->write_and_flush(i, {uintptr_cast(d), d->total_size(), false});
            LOGINFO("Written sync data for LSN -> {}", i);

            if (io_memory) {
                iomanager.iobuf_free(uintptr_cast(d));
            } else {
                std::free(voidptr_cast(d));
            }

            auto b = tmp_log_store->read_sync(i);
            auto* tl = r_cast< test_log_data const* >(b.bytes());
            ASSERT_EQ(tl->total_size(), b.size()) << "Size Mismatch for lsn=" << store_id << ":" << i;
            const char c = static_cast< char >((i % 94) + 33);
            const std::string actual = tl->get_data_str();
            const std::string expected(static_cast< size_t >(tl->size),
                                       c); // needs to be () because of same reason as vector
            ASSERT_EQ(actual, expected) << "Data mismatch for LSN=" << store_id << ":" << i << " size=" << tl->size;
        }

        logstore_service().remove_log_store(logdev_id, store_id);
        LOGINFO("Remove logstore -> i {}", store_id);
    }
}

SISL_OPTIONS_ENABLE(logging, test_log_store, iomgr, test_common_setup)
SISL_OPTION_GROUP(test_log_store,
                  (num_logdevs, "", "num_logdevs", "number of log devs",
                   ::cxxopts::value< uint32_t >()->default_value("4"), "number"),
                  (num_logstores, "", "num_logstores",
                   "number of log stores in all, they will spread to each logdev evenly",
                   ::cxxopts::value< uint32_t >()->default_value("16"), "number"),
                  (num_records, "", "num_records", "number of record to test",
                   ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
                  (iterations, "", "iterations", "Iterations", ::cxxopts::value< uint32_t >()->default_value("1"),
                   "the number of iterations to run each test"));

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_log_store, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_log_store");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");
    return RUN_ALL_TESTS();
}
