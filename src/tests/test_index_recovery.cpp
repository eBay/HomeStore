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
#include <iomgr/iomgr_flip.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_helper.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_decls.h"

using namespace homestore;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(test_index_recovery, logging, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_recovery)

std::vector< std::string > test_common::HSTestHelper::s_dev_names;

SISL_OPTION_GROUP(
    test_index_recovery,
    (num_iters, "", "num_iters", "number of iterations for rand ops",
     ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
    (num_entries, "", "num_entries", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("20"), "number"),
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("360000"), "seconds"),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    //   (flip_list, "", "flip_list", "btree flip list",
    //    ::cxxopts::value< std::vector< std::string > >(), "flips [...]"),
    (preload_size, "", "preload_size", "number of entries to preload tree with",
     ::cxxopts::value< uint32_t >()->default_value("10"), "number"),
    (init_device, "", "init_device", "init device", ::cxxopts::value< bool >()->default_value("1"), ""),
    (cleanup_after_shutdown, "", "cleanup_after_shutdown", "cleanup after shutdown",
     ::cxxopts::value< bool >()->default_value("1"), ""),
    //   (enable_crash, "", "enable_crash", "enable crash", ::cxxopts::value< bool >()->default_value("0"), ""),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

static void change_cp_time(uint64_t value_us) {
    HS_SETTINGS_FACTORY().modifiable_settings([value_us](auto& s) {
        s.generic.cp_timer_us = value_us;
        HS_SETTINGS_FACTORY().save();
    });
    LOGINFO("\n\n\nCP TIMER changed to {}", value_us);
}

template < typename TestType >
struct BtreeRecoveryTest : public BtreeTestHelper< TestType >, public ::testing::Test {

    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeRecoveryTest* test) : m_test(test) {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("root bnode_id {} version {}", sb->root_node, sb->link_version);
            m_test->m_cfg = BtreeConfig(hs()->index_service().node_size());
            m_test->m_cfg.m_leaf_node_type = T::leaf_node_type;
            m_test->m_cfg.m_int_node_type = T::interior_node_type;
            m_test->m_bt = std::make_shared< typename T::BtreeType >(std::move(sb), m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        BtreeRecoveryTest* m_test;
    };

    BtreeRecoveryTest() : testing::Test() {}

    void restart_homestore() {
        test_common::HSTestHelper::start_homestore(
            "test_index_recovery",
            {{HS_SERVICE::META, {}}, {HS_SERVICE::INDEX, {.index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, true, false /* restart */);
    }
    void destroy_btree() {
        auto cpg = hs()->cp_mgr().cp_guard();
        auto op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
        const auto [ret, free_node_cnt] = this->m_bt->destroy_btree(op_context);
        ASSERT_EQ(ret, btree_status_t::success) << "btree destroy failed";
        this->m_bt.reset();
    }

    void SetUp() override {
        test_common::HSTestHelper::start_homestore(
            "test_index_recovery",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, false, SISL_OPTIONS["init_device"].as< bool >());

        LOGINFO("Node size {} ", hs()->index_service().node_size());
        this->m_cfg = BtreeConfig(hs()->index_service().node_size());

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        // Test cp flush of write back.
        // not here
        // set it as 0 HS_DYNAMIC_CONFIG(generic.cp_timer_us) to make the CP to fail
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 100000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();
        homestore::hs()->resource_mgr().register_dirty_buf_exceed_cb(
            [this]([[maybe_unused]] int64_t dirty_buf_count, bool critical) {});
        // Create index table and attach to index service.
        BtreeTestHelper< TestType >::SetUp();
        if (this->m_bt == nullptr) {
            this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        } else {
            this->m_bt->retrieve_root_node();
            LOGINFO("root bnode_id {} version {}", this->m_bt->root_node_id(), this->m_bt->root_link_version());
            test_common::HSTestHelper::trigger_cp(true /* wait */);
            populate_shadow_map();
        }

        hs()->index_service().add_index_table(this->m_bt);
        LOGINFO("Added index table to index service");
    }
    void populate_shadow_map() {
        this->m_shadow_map.load(m_shadow_filename);
        ASSERT_EQ(this->m_shadow_map.size(), this->m_bt->count_keys(this->m_bt->root_node_id()))
            << "shadow map size and tree size mismatch";
        this->get_all();
    }

    void TearDown() override {
        bool cleanup = SISL_OPTIONS["cleanup_after_shutdown"].as< bool >();
        LOGINFO("cleanup the dump map and index data? {}", cleanup);
        if (!cleanup) {
            this->m_shadow_map.save(m_shadow_filename);
        } else {
            if (std::filesystem::remove(m_shadow_filename)) {
                LOGINFO("File {} removed successfully", m_shadow_filename);
            } else {
                LOGINFO("Error: failed to remove {}", m_shadow_filename);
            }
        }
        LOGINFO("Teardown with Root bnode_id {} tree size: {}", this->m_bt->root_node_id(),
                this->m_bt->count_keys(this->m_bt->root_node_id()));
        BtreeTestHelper< TestType >::TearDown();
        //        test_common::HSTestHelper::shutdown_homestore(cleanup);
        test_common::HSTestHelper::shutdown_homestore(false);
    }

private:
    const std::string m_shadow_filename = "/tmp/shadow_map.txt";
};
using BtreeTypes = testing::Types< FixedLenBtree /*, VarKeySizeBtree, VarValueSizeBtree, VarObjSizeBtree */ >;

TYPED_TEST_SUITE(BtreeRecoveryTest, BtreeTypes);
TYPED_TEST(BtreeRecoveryTest, Test1) {
    uint32_t i = 0;
    auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    //   auto num_entries = 30;
    //    uint32_t part1 = num_entries - 1000;
    //    uint32_t part2 = num_entries;
    uint32_t part1 = num_entries - 5;
    uint32_t part2 = num_entries;
    LOGINFO("\n\n\n \t\t\t\t\t\t\t\t\t\t\t\t\t\t  1- Do Forward sequential insert for [0, {}] entries", part1);
    for (; i < part1; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("\n\n\n\n\n \t\t\t\t\t\t\t\t\t\t\t\t\t\t  1- flushing {} entries", part1);
    //   this->visualize_keys("tree1.dot");

    test_common::HSTestHelper::trigger_cp(true /* wait */);
    LOGINFO("\n\n\n \t\t\t\t\t\t\t\t\t\t\t\t\t\t  1 - flushing part 1 done");
    this->print_keys();

    if (SISL_OPTIONS.count("enable_crash")) {
#ifdef _PRERELEASE
        if (SISL_OPTIONS.count("flip_list")) {
            auto flips = SISL_OPTIONS["flip_list"].as< std::vector< std::string > >();
            for (const auto& flip : flips) {
                this->set_flip_point(flip);
            }
        }
        LOGINFO(" enabled flips {}", this->m_bt->flip_list());
#endif
    }
    //   LOGINFO( "\n print before crash ")
    //   this->print_keys();
    LOGINFO("\n\n\n\n   \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t 2- enable crash");
    LOGINFO(
        "\n\n\n\n\n \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t 2- Do Forward sequential insert [{}, {}) entries - size {}",
        part1, part2, this->m_bt->count_keys(this->m_bt->root_node_id()));
    for (i = part1; i < part2; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("\n\n\n\n PART2 \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t  insert done\n \t\t trigger cp flush\n\n");
    LOGINFO("\n\n\n\n   \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t 2- print keys before flushing crashes");
    this->print_keys();
    //   this->visualize_keys("tree2.dot");
    test_common::HSTestHelper::trigger_cp(true /* wait */);
    //
    //    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    //    this->do_query(0, num_entries - 1, 75);
    //
    //    this->print(std::string("before_recovery.txt"));
    //
    //    this->destroy_btree();
    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
#ifdef _PRERELEASE
    if (SISL_OPTIONS.count("flip_list")) {
        auto flips = SISL_OPTIONS["flip_list"].as< std::vector< std::string > >();
        for (const auto& flip : flips) {
            this->reset_flip_point(flip);
        }
    }
    LOGINFO(" reseted flips {}", this->m_bt->flip_list());
#endif
    this->restart_homestore();
    LOGINFO("\n\n\n\n  \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t PART3 RETRY put {} - {} entries", part1, part2);
    LOGINFO("\n\n\n\n\n \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t 3-Root bnode_id {} version {} ",
            this->m_bt->root_node_id(), this->m_bt->root_link_version());
    LOGINFO("\n\n\n\n   \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t 3- print keys BEFORE recovery");
    //   LOGINFO("Query {} entries", num_entries);
    //   this->do_query(0, num_entries - 1, 1000);
    this->print_keys();
    //    this->print(std::string("after_recovery.txt"));

    //    LOGINFO("Query {} entries", num_entries);
    //    this->do_query(0, num_entries - 1, 1000);

    //    this->compare_files("before_recovery.txt", "after_recovery.txt");
    //    LOGINFO("CpFlush test end");
    //   this->print_keys(true,0 );
    //   this->visualize_keys("tree3.dot");

    LOGINFO("\n\n\n\n\n  \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t retry Do Forward sequential insert [{}, {}) entries",
            part1, part2);
    for (i = part1; i < part2; ++i) {
        LOGINFO("\n put retry {}", i);
        //       this->visualize_keys("tree3_"+std::to_string(i)+".dot");
        this->put(i, btree_put_type::INSERT, false);
    }

    //   this->print_keys(false,0);
    LOGINFO("test done")
}

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, test_index_recovery, logging, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_index_recovery");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");
    change_cp_time(90000000000);
    if (SISL_OPTIONS.count("seed")) {
        auto seed = SISL_OPTIONS["seed"].as< uint64_t >();
        LOGINFO("Using seed {} to sow the random generation", seed);
        g_re.seed(seed);
    }
    auto ret = RUN_ALL_TESTS();
    return ret;
}
