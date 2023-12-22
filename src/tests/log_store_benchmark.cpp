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
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include <benchmark/benchmark.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/logstore_service.hpp>
#include "test_common/homestore_test_common.hpp"

using namespace homestore;
SISL_LOGGING_DEF(HOMESTORE_LOG_MODS)
std::vector< std::string > test_common::HSTestHelper::s_dev_names;

SISL_OPTIONS_ENABLE(logging, log_store_benchmark, iomgr, test_common_setup)
SISL_OPTION_GROUP(log_store_benchmark,
                  (num_logstores, "", "num_logstores", "number of log stores",
                   ::cxxopts::value< uint32_t >()->default_value("1"), "number"),
                  (num_entries, "", "num_entries", "number of log records",
                   ::cxxopts::value< uint64_t >()->default_value("100000"), "number"),
                  (qdepth, "", "qdepth", "qdepth per thread", ::cxxopts::value< uint32_t >()->default_value("32"),
                   "number"),
                  (max_record_size, "", "max_record_size", "max record size",
                   ::cxxopts::value< uint32_t >()->default_value("1024"), "number"));

static constexpr size_t ITERATIONS{100000};

class BenchLogStore {
public:
    friend class SampleDB;
    BenchLogStore() {
        m_log_store =
            logstore_service().create_new_log_store(LogStoreService::DATA_LOG_FAMILY_IDX, true /* append_mode */);
        m_log_store->register_log_found_cb(bind_this(BenchLogStore::on_log_found, 3));
        m_nth_entry.store(0);
        generate_rand_data();
    }

    BenchLogStore(const BenchLogStore&) = delete;
    BenchLogStore& operator=(const BenchLogStore&) = delete;
    BenchLogStore(BenchLogStore&&) noexcept = delete;
    BenchLogStore& operator=(BenchLogStore&&) noexcept = delete;
    ~BenchLogStore() = default;

    void kickstart_io() {
        m_done = false;
        iomanager.run_on_forget(iomgr::reactor_regex::all_io, [this]() {
            for (uint32_t i{0}; i < m_q_depth; ++i) {
                issue_io();
            };
        });
    }

    void wait_for_appends() {
        {
            std::unique_lock< std::mutex > lk{m_pending_mtx};
            m_pending_cv.wait(lk, [&] { return (m_done); });
        }
        DLOGDEBUG("All appends completed for iteration={} and waiting is done, outstanding = {}", m_iteration,
                  m_outstanding.load());
        m_done = false;
        ++m_iteration;
    }

private:
    void issue_io() {
        m_outstanding.fetch_add(1, std::memory_order_acq_rel);
        if (!do_append()) {
            DLOGDEBUG("Notify that append has reached limit outstanding = {}", m_outstanding.load());
            bool notify{false};
            {
                std::unique_lock< std::mutex > lk{m_pending_mtx};
                notify = m_done = (m_outstanding.fetch_sub(1, std::memory_order_acq_rel) == 1);
            }

            if (notify) {
                DLOGDEBUG("Notify that append has completed, outstanding = {}", m_outstanding.load());
                m_pending_cv.notify_all();
            }
        }
    }

    bool do_append() {
        auto const ind = m_nth_entry.fetch_add(1, std::memory_order_acq_rel);
        auto const iter_ind = (ind - 1) / m_iteration + 1;
        if (iter_ind >= int64_cast(m_nentries)) { return false; }

        DLOGDEBUG("Appending log entry for iteration_ind={} ind={}", iter_ind, ind);
        m_log_store->append_async(
            sisl::io_blob(uintptr_cast(m_data[iter_ind].data()), uint32_cast(m_data[iter_ind].size()), false), nullptr,
            [this](logstore_seq_num_t, sisl::io_blob&, bool, void*) {
                if (m_outstanding.fetch_sub(1, std::memory_order_acq_rel) < int_cast(m_q_depth)) { issue_io(); };
            });
        return true;
    }

    void read(logstore_seq_num_t lsn) { m_log_store->read_sync(lsn); }

    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
        // LOGDEBUG("Recovered lsn {}:{} with log data of size {}", m_log_store->get_store_id(), lsn, buf.size())
    }

    void generate_rand_data() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< uint32_t > data_size{0, m_max_data_size - 1};

        static unsigned char ch{0};
        m_data.reserve(m_nentries);

        for (uint64_t i{0}; i < m_nentries; ++i) {
            const auto sz{data_size(re)};
            m_data.emplace_back(std::string(sz, ++ch));
        }
    }

private:
    std::shared_ptr< HomeLogStore > m_log_store;
    std::atomic< int32_t > m_outstanding{0};
    std::atomic< int64_t > m_nth_entry{0};

    const uint64_t m_nentries{SISL_OPTIONS["num_entries"].as< uint64_t >()};
    const uint32_t m_q_depth{SISL_OPTIONS["qdepth"].as< uint32_t >()};
    const uint32_t m_max_data_size{SISL_OPTIONS["max_record_size"].as< uint32_t >()};

    std::mutex m_pending_mtx;
    std::condition_variable m_pending_cv;
    bool m_done{false};
    uint32_t m_iteration{1};

    std::vector< std::string > m_data;
    logstore_family_id_t m_family;
    logstore_id_t m_store_id;
};

static void test_append(benchmark::State& state) {
    auto bls = std::make_unique< BenchLogStore >();
    for (auto _ : state) { // Loops upto iteration count
        bls->kickstart_io();
        bls->wait_for_appends();
    }
}

static void setup() {
    test_common::HSTestHelper::start_homestore("test_log_store",
                                               {{HS_SERVICE::META, {.size_pct = 5.0}},
                                                {HS_SERVICE::LOG_REPLICATED, {.size_pct = 85.0}},
                                                {HS_SERVICE::LOG_LOCAL, {.size_pct = 2.0}}});
}

static void teardown() { test_common::HSTestHelper::shutdown_homestore(); }

// BENCHMARK(test_append)->Iterations(10)->Threads(SISL_OPTIONS["num_threads"].as< uint32_t >());
BENCHMARK(test_append)->Iterations(1);

int main(int argc, char** argv) {
    SISL_OPTIONS_LOAD(argc, argv, logging, log_store_benchmark, iomgr, test_common_setup)
    sisl::logging::SetLogger("log_store_benchmark");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    setup();
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    LOGINFO("Metrics: {}", sisl::MetricsFarm::getInstance().get_result_in_json()["LogStores"].dump(4));
    teardown();
}
