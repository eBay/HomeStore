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
// Benchmark for index crash recovery with many large index tables. It runs as two processes on the same device files,
// so it works in release builds, which have no crash flips:
//
//   --phase load     Creates num_tables tables, preloads and flushes them, then inserts churn_per_table new random
//                    keys into every table within a single CP. It triggers that CP and SIGKILLs itself kill_delay_ms
//                    later, so the CP journal is on disk but the flush is incomplete. The preloaded keys of every
//                    table are saved next to the device files.
//   --phase recover  Starts HomeStore on the same devices, which recovers all tables from the CP journal, logs the
//                    wall time of the start and verifies that every preloaded key survived.
//
// IndexService logs the per-phase timings ("Index recovery timing", "Index wbcache recovery timing").
// Copy the device files after the load phase to rerun recovery on the same crash image.
#include <gtest/gtest.h>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <fstream>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "common/homestore_config.hpp"
#include "test_common/homestore_test_common.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_decls.h"

using namespace homestore;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_index_recovery_bench, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_recovery_bench)

SISL_OPTION_GROUP(test_index_recovery_bench,
                  (phase, "", "phase", "load or recover", ::cxxopts::value< std::string >()->default_value("load"),
                   "load|recover"),
                  (num_tables, "", "num_tables", "number of index tables",
                   ::cxxopts::value< uint32_t >()->default_value("8"), "number"),
                  (preload_per_table, "", "preload_per_table", "keys preloaded and flushed into each table",
                   ::cxxopts::value< uint64_t >()->default_value("1000000"), "number"),
                  (churn_per_table, "", "churn_per_table", "new keys inserted into each table in the crashed CP",
                   ::cxxopts::value< uint64_t >()->default_value("200000"), "number"),
                  (churn_skew, "", "churn_skew",
                   "spread the churn unevenly: table i gets churn_per_table * 2(i+1)/(num_tables+1) new keys",
                   ::cxxopts::value< bool >()->default_value("false"), "true or false"),
                  (keys_per_cp, "", "keys_per_cp", "keys per table between CPs while preloading",
                   ::cxxopts::value< uint64_t >()->default_value("250000"), "number"),
                  (kill_delay_ms, "", "kill_delay_ms", "delay between triggering the last CP and SIGKILL",
                   ::cxxopts::value< uint32_t >()->default_value("50"), "number"),
                  (verify, "", "verify", "verify all preloaded keys after recovery",
                   ::cxxopts::value< bool >()->default_value("true"), "true or false"),
                  (seed, "", "seed", "random seed", ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

using BtreeType = FixedLenBtree::BtreeType;
using clock_type = std::chrono::steady_clock;

static int64_t elapsed_ms(clock_type::time_point since) {
    return std::chrono::duration_cast< std::chrono::milliseconds >(clock_type::now() - since).count();
}

static std::string keys_file(uuid_t const& uuid) {
    return "/tmp/test_index_recovery_bench_keys_" + boost::uuids::to_string(uuid);
}

struct IndexRecoveryBench : public test_common::HSTestHelper, public ::testing::Test {
    class BenchIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        explicit BenchIndexServiceCallbacks(IndexRecoveryBench* test) : m_test{test} {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            auto bt = std::make_shared< BtreeType >(std::move(sb), m_test->m_cfg);
            std::unique_lock lg{m_test->m_tables_mtx};
            m_test->m_tables.push_back(bt);
            return bt;
        }

    private:
        IndexRecoveryBench* m_test;
    };

    void SetUp() override {
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            s.generic.cp_timer_us = 0x8000000000000000; // Only explicit CPs
            s.resource_limits.dirty_buf_percent = 100;
            HS_SETTINGS_FACTORY().save();
        });

        m_cfg = BtreeConfig(4096);
        m_cfg.m_leaf_node_type = FixedLenBtree::leaf_node_type;
        m_cfg.m_int_node_type = FixedLenBtree::interior_node_type;

        auto const load = (SISL_OPTIONS["phase"].as< std::string >() == "load");
        auto const start = clock_type::now();
        start_homestore(
            "test_index_recovery_bench",
            {{HS_SERVICE::META, {.size_pct = 5.0}},
             {HS_SERVICE::INDEX, {.size_pct = 85.0, .index_svc_cbs = new BenchIndexServiceCallbacks(this)}}},
            nullptr, {}, load /* init_device */);
        LOGINFO("Bench: HomeStore start took {} ms", elapsed_ms(start));
        // Recovered tables are built with m_cfg during start, so its node size has to be known up front.
        ASSERT_EQ(hs()->index_service().node_size(), m_cfg.node_size()) << "unexpected index node size";
    }

    void TearDown() override {
        m_tables.clear();
        shutdown_homestore(false /* cleanup */);
    }

    // Runs fn(table_idx) for every table on its own thread.
    void for_each_table(std::function< void(uint32_t) > const& fn) {
        std::vector< std::thread > threads;
        for (uint32_t i{0}; i < m_tables.size(); ++i) {
            threads.emplace_back([&fn, i]() { fn(i); });
        }
        for (auto& t : threads) {
            t.join();
        }
    }

    static void insert_keys(BtreeType& bt, std::mt19937_64& rng, uint64_t count, std::vector< uint64_t >* keys) {
        for (uint64_t n{0}; n < count; ++n) {
            auto const k = rng() >> 1; // Stay clear of the max key value
            TestFixedKey key{k};
            TestFixedValue value{uint32_cast(n)};
            TestFixedValue existing;
            auto req = BtreeSinglePutRequest{&key, &value, btree_put_type::UPSERT, &existing};
            if (bt.put(req) != btree_status_t::success) {
                LOGERROR("Bench: put of key {} failed", k);
                std::abort();
            }
            if (keys) { keys->push_back(k); }
        }
    }

    void load_and_crash() {
        auto const num_tables = SISL_OPTIONS["num_tables"].as< uint32_t >();
        auto const preload = SISL_OPTIONS["preload_per_table"].as< uint64_t >();
        auto const churn = SISL_OPTIONS["churn_per_table"].as< uint64_t >();
        auto const keys_per_cp = std::max< uint64_t >(1, SISL_OPTIONS["keys_per_cp"].as< uint64_t >());
        auto seed = SISL_OPTIONS["seed"].as< uint64_t >();
        if (seed == 0) { seed = std::random_device{}(); }
        LOGINFO("Bench: tables={} preload_per_table={} churn_per_table={} seed={}", num_tables, preload, churn, seed);

        for (uint32_t i{0}; i < num_tables; ++i) {
            auto bt = std::make_shared< BtreeType >(boost::uuids::random_generator()(),
                                                    boost::uuids::random_generator()(), 0, m_cfg);
            hs()->index_service().add_index_table(bt);
            m_tables.push_back(bt);
        }
        std::vector< std::mt19937_64 > rngs;
        for (uint32_t i{0}; i < num_tables; ++i) {
            rngs.emplace_back(seed + i);
        }
        std::vector< std::vector< uint64_t > > preloaded(num_tables);

        // Preload every table and flush it with periodic CPs.
        auto phase_start = clock_type::now();
        for (uint64_t done{0}; done < preload; done += keys_per_cp) {
            auto const batch = std::min(keys_per_cp, preload - done);
            for_each_table([&](uint32_t i) { insert_keys(*m_tables[i], rngs[i], batch, &preloaded[i]); });
            trigger_cp(true);
        }
        LOGINFO("Bench: preload of {} keys took {} ms", preload * num_tables, elapsed_ms(phase_start));

        for (uint32_t i{0}; i < num_tables; ++i) {
            auto const fname = keys_file(m_tables[i]->uuid());
            std::ofstream out{fname, std::ios::binary | std::ios::trunc};
            out.write(r_cast< char const* >(preloaded[i].data()), preloaded[i].size() * sizeof(uint64_t));
            out.close();
            if (!out) {
                LOGERROR("Bench: failed to write the keys of table {} to {}", i, fname);
                std::abort();
            }
        }

        // Insert the churn of every table into a single CP, then crash in the middle of its flush.
        phase_start = clock_type::now();
        auto const skew = SISL_OPTIONS["churn_skew"].as< bool >();
        auto const table_churn = [&](uint32_t i) { return skew ? churn * 2 * (i + 1) / (num_tables + 1) : churn; };
        std::atomic< uint64_t > total_churn{0};
        for_each_table([&](uint32_t i) {
            insert_keys(*m_tables[i], rngs[i], table_churn(i), nullptr);
            total_churn.fetch_add(table_churn(i));
        });
        LOGINFO("Bench: churn of {} keys (skewed={}) took {} ms", total_churn.load(), skew, elapsed_ms(phase_start));

        trigger_cp(false);
        std::this_thread::sleep_for(std::chrono::milliseconds{SISL_OPTIONS["kill_delay_ms"].as< uint32_t >()});
        LOGINFO("Bench: killing the process during the CP flush");
        sisl::logging::GetLogger()->flush();
        std::raise(SIGKILL);
    }

    void verify_recovered() {
        auto const start = clock_type::now();
        std::atomic< uint64_t > missing{0};
        std::atomic< uint64_t > verified{0};
        for_each_table([&](uint32_t i) {
            auto const& bt = m_tables[i];
            std::ifstream in{keys_file(bt->uuid()), std::ios::binary | std::ios::ate};
            if (!in) {
                LOGERROR("Bench: no saved keys for table {}", boost::uuids::to_string(bt->uuid()));
                missing.fetch_add(1);
                return;
            }
            std::vector< uint64_t > keys(in.tellg() / sizeof(uint64_t));
            in.seekg(0);
            in.read(r_cast< char* >(keys.data()), keys.size() * sizeof(uint64_t));
            if (!in || (keys.size() != SISL_OPTIONS["preload_per_table"].as< uint64_t >())) {
                LOGERROR("Bench: table {} has {} saved keys, expected {}", boost::uuids::to_string(bt->uuid()),
                         keys.size(), SISL_OPTIONS["preload_per_table"].as< uint64_t >());
                missing.fetch_add(1);
                return;
            }
            for (auto const k : keys) {
                TestFixedKey key{k};
                TestFixedValue value;
                auto req = BtreeSingleGetRequest{&key, &value};
                if (bt->get(req) != btree_status_t::success) { missing.fetch_add(1); }
            }
            verified.fetch_add(keys.size());
        });
        ASSERT_EQ(missing.load(), 0) << "preloaded keys missing after recovery";
        LOGINFO("Bench: verified {} preloaded keys in {} ms", verified.load(), elapsed_ms(start));
    }

    BtreeConfig m_cfg{4096};
    std::mutex m_tables_mtx;
    std::vector< std::shared_ptr< BtreeType > > m_tables;
};

TEST_F(IndexRecoveryBench, CrashRecoveryTime) {
    if (SISL_OPTIONS["phase"].as< std::string >() == "load") {
        load_and_crash();
        return;
    }
    LOGINFO("Bench: recovered {} tables", m_tables.size());
    ASSERT_EQ(m_tables.size(), SISL_OPTIONS["num_tables"].as< uint32_t >());
    if (SISL_OPTIONS["verify"].as< bool >()) { verify_recovered(); }
}

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_index_recovery_bench, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_index_recovery_bench");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");
    return RUN_ALL_TESTS();
}
