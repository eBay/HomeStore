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
#include <gtest/gtest.h>
#include <boost/uuid/random_generator.hpp>

#include <sisl/utility/enum.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_helper.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_decls.h"

using namespace homestore;

SISL_OPTIONS_ENABLE(logging, test_cow_btree_recovery, iomgr, test_common_setup)

// TODO Add tests to do write,remove after recovery.
// TODO Test with var len key with io mgr page size is 512.

SISL_OPTION_GROUP(
    test_cow_btree_recovery,
    (test_type, "", "test_type", "What type of test, [unit | functional | stress ]",
     ::cxxopts::value< std::string >()->default_value("unit"), "string"),
    (num_ios, "", "num_ios", "[override] number of io operations to test", ::cxxopts::value< uint32_t >(), "number"),
    (num_btrees, "", "num_btrees", "[override] number of btrees to test", ::cxxopts::value< uint32_t >(), "number"),
    (num_cps, "", "num_cps", "[override] number of cps to test", ::cxxopts::value< uint32_t >(), "number"),
    (num_entries, "", "num_entries", "[override] number of entries per btree", ::cxxopts::value< uint32_t >(),
     "number"),
    (run_time, "", "run_time", "[override] run time for io", ::cxxopts::value< uint32_t >(), "seconds"),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (preload_size, "", "preload_size", "[ovveride] number of entries to preload tree with",
     ::cxxopts::value< uint32_t >(), "number"),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

struct COWBtreeTestOptions : public BtreeTestOptions {
    uint32_t num_cps;
    uint32_t num_btrees;
};
COWBtreeTestOptions g_opts;

void log_obj_life_counter() {
    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);
}

static void set_options() {
    if (SISL_OPTIONS["test_type"].as< std::string >() == "unit") {
        g_opts.num_entries = 5000;
        g_opts.preload_size = 2500;
        g_opts.num_ios = 500;
        g_opts.run_time_secs = 36000; // Limit is on ios than time
        g_opts.num_btrees = 2;
        g_opts.num_cps = 0;
    } else if (SISL_OPTIONS["test_type"].as< std::string >() == "functional") {
        g_opts.num_entries = 50000;
        g_opts.preload_size = 25000;
        g_opts.num_ios = 50000;
        g_opts.run_time_secs = 36000; // Limit is on ios than time
        g_opts.num_btrees = 2;
        g_opts.num_cps = 25;
    }

    if (SISL_OPTIONS.count("num_entries")) { g_opts.num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("preload_size")) { g_opts.preload_size = SISL_OPTIONS["preload_size"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("num_ios")) { g_opts.num_ios = SISL_OPTIONS["num_ios"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("run_time")) { g_opts.run_time_secs = SISL_OPTIONS["run_time"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("num_cps")) { g_opts.num_cps = SISL_OPTIONS["num_cps"].as< uint32_t >(); }
    if (SISL_OPTIONS.count("disable_merge")) { g_opts.disable_merge = SISL_OPTIONS["disable_merge"].as< bool >(); }

    if (SISL_OPTIONS.count("seed")) {
        LOGINFO("Using seed {} to sow the random generation", SISL_OPTIONS["seed"].as< uint64_t >());
        g_re.seed(SISL_OPTIONS["seed"].as< uint64_t >());
    }
}

struct BtreeTest : public test_common::HSTestHelper, public ::testing::Test {
    using T = VarObjSizeBtree< IndexStore::Type::COPY_ON_WRITE_BTREE >;
    using K = typename T::KeyType;
    using V = typename T::ValueType;

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeTest* test) : m_test(test) {}
        std::shared_ptr< Index > on_index_table_found(superblk< IndexSuperBlock >&& sb) override {
            // Locate the helper corresponding to this btree ordinal
            auto it1 = m_test->m_bt_helpers.find(sb->ordinal);
            if (it1 == m_test->m_bt_helpers.end()) {
                auto it2 = m_test->m_destroyed_bt_helpers.find(sb->ordinal);
                RELEASE_ASSERT((it2 != m_test->m_destroyed_bt_helpers.end()),
                               "BT Helper for ordinal={} is not found, some issue in destroying btree?", sb->ordinal);
                LOGINFO("Prior to restart, btree_ordinal={} was attempted to destroy, but CP was not taken, so we "
                        "recovered that as well",
                        sb->ordinal);
                bool happened;
                std::tie(it1, happened) = m_test->m_bt_helpers.insert(*it2);
                m_test->m_destroyed_bt_helpers.erase(it2);
            }

            ++m_test->m_recovered;
            auto bt_helper = it1->second.get();
            bt_helper->SetUp(std::make_shared< Btree< K, V > >(bt_helper->m_cfg, std::move(sb)), true /* load */,
                             true /* multi_threaded */);
            return bt_helper->m_bt;
        }

    private:
        BtreeTest* m_test;
    };
    friend class TestIndexServiceCallbacks;

    BtreeTest() : testing::Test() {}

    void SetUp() override {
        start_homestore(
            "test_btree",
            {{ServiceType::META, {.size_pct = 10.0}},
             {ServiceType::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, {homestore::dev_info{"", homestore::HSDevType::Fast, 0}});
        // For persistent btree, we try to create a default size, but with only 1 device explictly, since this tests
        // start restart homestore several times and its better to use 1 disk always.

        // Test cp flush of write back.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        auto const multi_threaded =
            (testing::UnitTest::GetInstance()->current_test_info()->name() == std::string("ConcurrentMultiOps"));

        for (uint32_t i{0}; i < g_opts.num_btrees; ++i) {
            create_new_btree();
        }
    }

    uint32_t create_new_btree() {
        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        auto bt_helper = std::make_shared< BtreeTestHelper< T > >(g_opts);
        bt_helper->SetUp(std::make_shared< Btree< K, V > >(bt_helper->m_cfg, uuid, parent_uuid, 0), false /* load */,
                         true /* multi_threaded */);
        hs()->index_service().add_index_table(bt_helper->m_bt);
        auto ordinal = bt_helper->m_bt->ordinal();
        m_bt_helpers.insert(std::make_pair(bt_helper->m_bt->ordinal(), std::move(bt_helper)));
        return ordinal;
    }

    void destroy_a_btree() {
        if (m_bt_helpers.empty()) { return; }

        auto it = m_bt_helpers.begin();
        auto [ordinal, bt_helper] = *it;

        hs()->index_service().destroy_index_table(bt_helper->m_bt).thenValue([this, bt_helper, ordinal](auto&&) {
            m_destroyed_bt_helpers.insert(std::make_pair(ordinal, bt_helper));
        });
        bt_helper->m_bt.reset();
        m_bt_helpers.erase(it);
    }

    void io_on_btrees() {
        std::vector< std::string > input_ops = {"put:70", "remove:30"};
        for (auto& [_, bt_helper] : m_bt_helpers) {
            bt_helper->multi_op_execute(bt_helper->build_op_list(input_ops));
        }
    }

    void validate_btrees() {
        for (auto& [_, bt_helper] : m_bt_helpers) {
            bt_helper->query_all_paginate(500);
        }
    }

    void TearDown() override {
        for (auto& [_, bt_helper] : m_bt_helpers) {
            hs()->index_service().destroy_index_table(bt_helper->m_bt);
            bt_helper->m_bt.reset();
            bt_helper->TearDown();
        }
        shutdown_homestore(false);
        log_obj_life_counter();
    }

    void restart_homestore(uint32_t shutdown_delay_sec = 5) override {
        m_recovered = 0;
        this->params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        for (auto& [_, bt_helper] : this->m_bt_helpers) {
            bt_helper->m_bt.reset();
        }

        test_common::HSTestHelper::restart_homestore(shutdown_delay_sec);
    }

    void restart_and_validate() {
        LOGINFO("Restart homestore and validate if before and after states of btrees are identical");
        for (auto& [_, bt_helper] : this->m_bt_helpers) {
            std::string fname = fmt::format("/tmp/btree_{}_before.txt", bt_helper->m_bt->ordinal());
            bt_helper->dump_to_file(fname);
        }
        restart_homestore();
        LOGINFO(" Restarted homestore with {} indexes recovered", m_recovered);

        ASSERT_EQ(m_recovered, this->m_bt_helpers.size()) << "Number of btrees before and after restart mismatch";
        for (auto& [_, bt_helper] : this->m_bt_helpers) {
            std::string before_fname = fmt::format("/tmp/btree_{}_before.txt", bt_helper->m_bt->ordinal());
            std::string after_fname = fmt::format("/tmp/btree_{}_after.txt", bt_helper->m_bt->ordinal());
            bt_helper->dump_to_file(after_fname);
            bt_helper->compare_files(before_fname, after_fname); // Validate with dumping
            bt_helper->query_all_paginate(500);                  // Validate with query as well.
        }
    }

    void trigger_incremental_map_cp() { do_trigger_cp(false /* full_map_cp */, false /* crash */); }

    void trigger_full_map_cp() { do_trigger_cp(true /* full_map_cp */, false /* crash */); }

    void post_crash_validate() {
        // Post crash reapply on all btrees
        for (auto& [_, bt_helper] : this->m_bt_helpers) {
            bt_helper->reapply_after_crash();
            bt_helper->query_all_paginate(500); // Validate with query as well.
        }
    }

    struct CPParams {
        enum class RestartType : uint8_t { none, clean, crash };

        uint32_t num_new_btrees{0};                                     // # of new btrees to create before cp
        uint32_t num_destroy_btrees{0};                                 // # of btrees to destroy before cp
        uint32_t num_io_btrees{std::numeric_limits< uint32_t >::max()}; // # of btrees to do IO
        bool is_full_map_flush_cp{false};                               // Is it a full map flush cp or incremental
        RestartType restart_post_cp{RestartType::none};                 // Should we restart the homestore after cp

        std::string restart_type() const {
            switch (restart_post_cp) {
            case RestartType::none:
                return "none";
            case RestartType::clean:
                return "clean";
            case RestartType::crash:
                return "crash";
            default:
                return "unknown";
            }
        }
    };

    void action_with_cp(CPParams p) {
        std::vector< uint32_t > created;
        created.reserve(p.num_new_btrees);

        for (uint32_t i{0}; i < p.num_new_btrees; ++i) {
            created.push_back(create_new_btree());
        }

        auto created_list = [](std::vector< uint32_t > const& v) -> std::string {
            std::string str = v.empty() ? "" : std::to_string(v[0]);
            for (size_t i{1}; i < v.size(); ++i) {
                str += std::string(",") + std::to_string(v[i]);
            }
            return str;
        };

        auto first_n = [](std::map< uint32_t, std::shared_ptr< BtreeTestHelper< T > > > const& m,
                          size_t n) -> std::string {
            auto it = m.begin();
            std::string str = (it == m.end() || n == 0) ? "" : std::to_string(it->first);
            size_t i{1};
            for (++it; (it != m.end()) && (i < n); ++it, ++i) {
                str += std::string(",") + std::to_string(it->first);
            }
            return str;
        };

        if (p.num_io_btrees > this->m_bt_helpers.size()) { p.num_io_btrees = this->m_bt_helpers.size(); }
        LOGINFO("CPSpec: Create btrees=[{}] -> IO on btrees=[{}] -> Destroy btrees=[{}] -> CP_type={} -> Restart?={}",
                created_list(created), first_n(m_bt_helpers, p.num_io_btrees),
                first_n(m_bt_helpers, p.num_destroy_btrees), p.is_full_map_flush_cp ? "FullFlush" : "IncrementalFlush",
                p.restart_type());

        std::vector< std::string > input_ops = {"put:70", "remove:30"};
        uint32_t b{0};
        for (auto& [_, bt_helper] : this->m_bt_helpers) {
            if (b++ == p.num_io_btrees) { break; }
            bt_helper->multi_op_execute(bt_helper->build_op_list(input_ops));
        }

        for (uint32_t i{0}; i < p.num_destroy_btrees; ++i) {
            destroy_a_btree();
        }

        if (p.restart_post_cp == CPParams::RestartType::crash) {
            do_trigger_cp(p.is_full_map_flush_cp /* full_map_cp */, true /* crash */);
            post_crash_validate();
        } else if (p.restart_post_cp == CPParams::RestartType::clean) {
            do_trigger_cp(p.is_full_map_flush_cp /* full_map_cp */, false /* crash */);
            restart_and_validate();
        } else {
            do_trigger_cp(p.is_full_map_flush_cp /* full_map_cp */, false /* crash */);
        }
    }

#ifdef _PRERELEASE
    void set_btree_flip(std::string const& flip_name, std::optional< uint32_t > bt_ordinal = std::nullopt,
                        uint32_t count = 1, uint32_t percent = 100) {
        flip::FlipCondition cond;
        auto fc = iomgr_flip::client_instance();
        if (bt_ordinal) {
            fc->create_condition("btree_ordinal", flip::Operator::EQUAL, (int)*bt_ordinal, &cond);
        } else {
            fc->create_condition("", flip::Operator::DONT_CARE, (int)1, &cond);
        }
        flip::FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        fc->inject_noreturn_flip(flip_name, {cond}, freq);
    }
#endif

private:
    void do_trigger_cp(bool full_map_cp, bool crash) {
        LOGINFO("Trigger {} Map Flush CP {}", full_map_cp ? "Full" : "Incremental", crash ? " to simulate crash" : "");

        // Modify the settings to take incremental map flushes only once
        HS_SETTINGS_FACTORY().modifiable_settings([full_map_cp](auto& s) {
            s.btree.cow_max_incremental_map_flushes = full_map_cp ? 0 : 100000;
            HS_SETTINGS_FACTORY().save();
        });
        if (crash) {
            test_common::HSTestHelper::trigger_cp(false /* wait */);
#ifdef _PRERELEASE
            this->wait_for_crash_recovery();
#endif
        } else {
            test_common::HSTestHelper::trigger_cp(true /* wait */);
            for (auto& [_, bt_helper] : this->m_bt_helpers) {
                bt_helper->save_snapshot(); // Save every btree shadow as snapshot
            }
        }
    }

protected:
    std::map< uint32_t, std::shared_ptr< BtreeTestHelper< T > > > m_bt_helpers;
    std::map< uint32_t, std::shared_ptr< BtreeTestHelper< T > > > m_destroyed_bt_helpers;
    uint32_t m_recovered{0};
};

TEST_F(BtreeTest, DeleteCheckSizeReduction) {
    std::vector< std::string > input_ops = {"put:70", "remove:30"};
    for (auto& [_, bt_helper] : this->m_bt_helpers) {
        bt_helper->multi_op_execute(bt_helper->build_op_list(input_ops));
    }

    auto const before_space = hs()->index_service().space_occupied();
    for (auto& [_, bt_helper] : this->m_bt_helpers) {
        destroy_a_btree();
    }
    auto const after_space = hs()->index_service().space_occupied();
    ASSERT_LT(after_space, before_space) << "Destroy of btree didn't recapture space";
}

TEST_F(BtreeTest, IOThenFullMapFlushThenRestart) {
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::clean});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, IOThenIncrementalMapFlushThenRestart) {
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::clean});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, CreateThenFullMapFlushThenRestart) {
    action_with_cp({.num_new_btrees = 1,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::clean});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, CreateThenIncrementalMapFlushThenRestart) {
    action_with_cp({.num_new_btrees = 1,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::clean});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, DestroyThenFullMapFlushThenRestart) {
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 1,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::clean});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, DestroyThenIncrementalMapFlushThenRestart) {
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 1,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::clean});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, RandomMultiOps) {
    if (SISL_OPTIONS["test_type"].as< std::string >() == "unit") { GTEST_SKIP(); }

    static std::uniform_int_distribution< uint32_t > new_rand_count{0, 3};
    static std::uniform_int_distribution< uint32_t > destroy_rand_count{0, 2};
    static std::normal_distribution<> io_rand_count{(double)(g_opts.num_btrees), 4.0};
    static std::uniform_int_distribution< uint32_t > rand_cp_type{0, 3}; // 25% times for full map cp
    static std::uniform_int_distribution< uint32_t > rand_restart{0, 3}; // 25% times for restart

    for (uint32_t i{0}; i < g_opts.num_cps; ++i) {
        action_with_cp({.num_new_btrees = new_rand_count(g_re),
                        .num_destroy_btrees = destroy_rand_count(g_re),
                        .num_io_btrees = (uint32_t)std::lround(io_rand_count(g_re)),
                        .is_full_map_flush_cp = (rand_cp_type(g_re) == 0),
                        .restart_post_cp =
                            (rand_restart(g_re) == 0) ? CPParams::RestartType::clean : CPParams::RestartType::none});
    }

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

#ifdef _PRERELEASE
TEST_F(BtreeTest, CrashBeforeFirstCp) {
    // Simulate the crash even before first cp. Here we trigger crash CP, so no actual CP is taken in this test
    this->set_btree_flip("crash_on_flush_cow_btree_nodes");
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::crash});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, CrashDuringFlushNodes) {
    // Take couple of CPs, one full map and then one incremental
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::none});
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::none});

    // Simulate the crash after couple of cps by triggering an incremental cp.
    this->set_btree_flip("crash_on_flush_cow_btree_nodes", (uint32_t)1);
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::crash});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, CrashBeforeIncrementalCpCommit) {
    // Take couple of CPs, one full map and then one incremental
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::none});
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::none});

    // Simulate the crash on next cp
    this->set_btree_flip("crash_before_incr_map_flush_commit");
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::crash});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}

TEST_F(BtreeTest, CrashBeforeLastFullMapCpCommit) {
    // Take couple of CPs, one full map and then one incremental
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::none});
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = false,
                    .restart_post_cp = CPParams::RestartType::none});

    // Set the flip to crash while full map cp flush is ongoing on the last btree, which means other btrees have
    // successfully completed the full map flush cp and the last one isn't. This should test both replay of map updates
    // which already committed and one btree which has not.
    this->set_btree_flip("crash_during_full_map_flush", (uint32_t)1);
    action_with_cp({.num_new_btrees = 0,
                    .num_destroy_btrees = 0,
                    .num_io_btrees = std::numeric_limits< uint32_t >::max(),
                    .is_full_map_flush_cp = true,
                    .restart_post_cp = CPParams::RestartType::crash});

    LOGINFO("Post Restart we do IO on all recovered btrees");
    this->io_on_btrees();
}
#endif

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_cow_btree_recovery, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_cow_btree_recovery");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");

    set_options();
    auto ret = RUN_ALL_TESTS();
    return ret;
}
