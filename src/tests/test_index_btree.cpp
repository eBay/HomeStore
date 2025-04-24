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

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_index_btree, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_btree)

// TODO Add tests to do write,remove after recovery.
// TODO Test with var len key with io mgr page size is 512.

SISL_OPTION_GROUP(
    test_index_btree,
    (num_iters, "", "num_iters", "number of iterations for rand ops",
     ::cxxopts::value< uint32_t >()->default_value("500"), "number"),
    (num_entries, "", "num_entries", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("7000"), "number"),
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("360000"), "seconds"),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    (preload_size, "", "preload_size", "number of entries to preload tree with",
     ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
    (init_device, "", "init_device", "init device", ::cxxopts::value< bool >()->default_value("1"), ""),
    (cleanup_after_shutdown, "", "cleanup_after_shutdown", "cleanup after shutdown",
     ::cxxopts::value< bool >()->default_value("1"), ""),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

void log_obj_life_counter() {
    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);
}

template < typename TestType >
struct BtreeTest : public BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeTest* test) : m_test(test) {}
        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("Root bnode_id {} version {}", sb->root_node, sb->root_link_version);
            m_test->m_bt = std::make_shared< typename T::BtreeType >(std::move(sb), m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        BtreeTest* m_test;
    };

    BtreeTest() : testing::Test() {}

    void SetUp() override {
        m_helper.start_homestore(
            "test_index_btree",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}});

        LOGINFO("Node size {} ", hs()->index_service().node_size());
        this->m_cfg = BtreeConfig(hs()->index_service().node_size());

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        // Test cp flush of write back.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        BtreeTestHelper< TestType >::SetUp();
        this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        hs()->index_service().add_index_table(this->m_bt);
        LOGINFO("Added index table to index service");
    }

    void TearDown() override {
        BtreeTestHelper< TestType >::TearDown();
        m_helper.shutdown_homestore(false);
        this->m_bt.reset();
        log_obj_life_counter();
    }

    void restart_homestore() {
        m_helper.params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        m_helper.restart_homestore();
    }

    void destroy_btree() {
        auto cpg = hs()->cp_mgr().cp_guard();
        auto op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
        const auto [ret, free_node_cnt] = this->m_bt->destroy_btree(op_context);
        ASSERT_EQ(ret, btree_status_t::success) << "btree destroy failed";
        this->m_bt.reset();
    }

    test_common::HSTestHelper m_helper;
};

using BtreeTypes = testing::Types< FixedLenBtree, VarKeySizeBtree, VarValueSizeBtree, VarObjSizeBtree >;

TYPED_TEST_SUITE(BtreeTest, BtreeTypes);

TYPED_TEST(BtreeTest, SequentialInsert) {
    LOGINFO("SequentialInsert test start");
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->put(i, btree_put_type::INSERT);
        // this->print();
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->do_query(0, entries_iter1 - 1, 75);

    // Reverse sequential insert
    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 3: Do Reverse sequential insert of remaining {} entries", entries_iter2);
    for (uint32_t i{num_entries - 1}; i >= entries_iter1; --i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 90 entries", entries_iter2);
    this->do_query(entries_iter1, num_entries - 1, 90);

    // Do validate all of them
    LOGINFO("Step 5: Query all entries and validate with no pagination");
    this->query_all();

    LOGINFO("Step 6: Query all entries and validate with pagination of 80 entries");
    this->query_all_paginate(80);

    LOGINFO("Step 7: Get all entries 1-by-1 and validate them");
    this->get_all();
    this->get_any(num_entries - 3, num_entries + 1);

    // Negative cases
    LOGINFO("Step 8: Do incorrect input and validate errors");
    this->do_query(num_entries + 100, num_entries + 500, 5);
    this->get_any(num_entries + 1, num_entries + 2);
    //    this->print();

    LOGINFO("SequentialInsert test end");
}

TYPED_TEST(BtreeTest, RandomInsert) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    std::vector< uint32_t > vec(num_entries);
    // make keys [0, num_entries)
    iota(vec.begin(), vec.end(), 0);
    // shuffle keys
    std::random_shuffle(vec.begin(), vec.end());
    LOGINFO("Step 1: Do forward random insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(vec[i], btree_put_type::INSERT);
    }
    this->get_all();
}

TYPED_TEST(BtreeTest, TriggerCacheEviction) {
    // restart homestore with smaller cache %
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.resource_limits.cache_size_percent = 1u;
        HS_SETTINGS_FACTORY().save();
    });
    
    this->restart_homestore();

    LOGINFO("TriggerCacheEviction test start");
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
        // this->print();
    }

    this->get_all();

    // reset cache pct
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.resource_limits.cache_size_percent = 65u;
        HS_SETTINGS_FACTORY().save();
    });

    LOGINFO("TriggerCacheEviction test end");
}

TYPED_TEST(BtreeTest, SequentialRemove) {
    LOGINFO("SequentialRemove test start");
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);

    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 3: Do Forward sequential remove for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->remove_one(i);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->do_query(0, entries_iter1 - 1, 75);
    this->do_query(entries_iter1, num_entries - 1, 75);

    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 5: Do Reverse sequential remove of remaining {} entries", entries_iter2);
    for (uint32_t i{num_entries - 1}; i >= entries_iter1; --i) {
        this->remove_one(i);
    }

    LOGINFO("Step 6: Query the empty tree");
    this->do_query(0, num_entries - 1, 75);
    this->get_any(0, 1);
    this->get_specific(0);
    LOGINFO("SequentialRemove test end");
}

TYPED_TEST(BtreeTest, RandomRemove) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();

    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    std::vector< uint32_t > vec(num_entries);
    iota(vec.begin(), vec.end(), 0);

    // shuffle keys in [0, num_entries)
    std::random_shuffle(vec.begin(), vec.end());
    LOGINFO("Step 2: Do remove one by one for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->remove_one(vec[i]);
    }
    this->get_all();
}

TYPED_TEST(BtreeTest, RangeUpdate) {
    LOGINFO("RangeUpdate test start");
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    LOGINFO("Step 2: Do Range Update of random intervals between [1-50] for 100 times with random key ranges");
    for (uint32_t i{0}; i < 100; ++i) {
        this->range_put_random();
    }

    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);
    LOGINFO("RangeUpdate test end");
}

TYPED_TEST(BtreeTest, CpFlush) {
    LOGINFO("CpFlush test start");

    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Do Forward sequential insert for {} entries", num_entries / 2);
    for (uint32_t i = 0; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    // Remove some of the entries.
    for (uint32_t i = 0; i < num_entries; i += 10) {
        this->remove_one(i);
    }

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries / 2);
    this->do_query(0, num_entries / 2 - 1, 75);

    LOGINFO("Trigger checkpoint flush.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);

    this->dump_to_file(std::string("before.txt"));

    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO("Restarted homestore with index recovered");

    this->dump_to_file(std::string("after.txt"));

    LOGINFO("Query {} entries", num_entries);
    this->do_query(0, num_entries - 1, 1000);

    this->compare_files("before.txt", "after.txt");
    LOGINFO("CpFlush test end");
}

TYPED_TEST(BtreeTest, MultipleCpFlush) {
    LOGINFO("MultipleCpFlush test start");

    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Do Forward sequential insert for {} entries", num_entries / 2);
    for (uint32_t i = 0; i < num_entries / 2; ++i) {
        this->put(i, btree_put_type::INSERT);
        if (i % 500 == 0) {
            LOGINFO("Trigger checkpoint flush wait=false.");
            test_common::HSTestHelper::trigger_cp(false /* wait */);
        }
    }

    LOGINFO("Trigger checkpoint flush wait=false.");
    test_common::HSTestHelper::trigger_cp(false /* wait */);

    for (uint32_t i = num_entries / 2; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    LOGINFO("Trigger checkpoint flush wait=false.");
    test_common::HSTestHelper::trigger_cp(false /* wait */);

    LOGINFO("Trigger checkpoint flush wait=true.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);

    this->dump_to_file(std::string("before.txt"));

    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO(" Restarted homestore with index recovered");
    this->dump_to_file(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", num_entries);
    this->do_query(0, num_entries - 1, 1000);
    LOGINFO("MultipleCpFlush test end");
}

TYPED_TEST(BtreeTest, ThreadedCpFlush) {
    LOGINFO("ThreadedCpFlush test start");

    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    bool stop = false;
    std::atomic< uint32_t > last_index{0};
    auto insert_io_thread = std::thread([this, num_entries, &last_index] {
        LOGINFO("Do Forward sequential insert for {} entries", num_entries);
        uint32_t j = 0;
        for (uint32_t i = 0; i < num_entries; ++i) {
            this->put(i, btree_put_type::INSERT);
            last_index = i;
        }
    });

    auto remove_io_thread = std::thread([this, &stop, num_entries, &last_index] {
        LOGINFO("Do random removes for {} entries", num_entries);
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            // Remove a random entry.
            std::uniform_int_distribution< uint32_t > rand{0, last_index.load()};
            auto rm_idx = rand(g_re);
            this->remove_one(rm_idx);
        }
    });

    auto cp_flush_thread = std::thread([this, &stop] {
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::seconds{1});
            LOGINFO("Trigger checkpoint flush wait=true.");
            test_common::HSTestHelper::trigger_cp(false /* wait */);
            LOGINFO("Trigger checkpoint flush wait=true done.");
        }
    });

    insert_io_thread.join();
    stop = true;
    remove_io_thread.join();
    cp_flush_thread.join();

    LOGINFO("Trigger checkpoint flush wait=true.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);

    this->dump_to_file(std::string("before.txt"));
    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO(" Restarted homestore with index recovered");
    this->dump_to_file(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", num_entries);
    this->do_query(0, num_entries - 1, 1000);
    LOGINFO("ThreadedCpFlush test end");
}

template < typename TestType >
struct BtreeConcurrentTest : public BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeConcurrentTest* test) : m_test(test) {}

        std::shared_ptr< IndexTableBase > on_index_table_found(superblk< index_table_sb >&& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("Root bnode_id {} version {}", sb->root_node, sb->root_link_version);
            m_test->m_cfg = BtreeConfig(hs()->index_service().node_size());
            m_test->m_cfg.m_leaf_node_type = T::leaf_node_type;
            m_test->m_cfg.m_int_node_type = T::interior_node_type;
            m_test->m_bt = std::make_shared< typename T::BtreeType >(std::move(sb), m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        BtreeConcurrentTest* m_test;
    };

    BtreeConcurrentTest() : testing::Test() { this->m_is_multi_threaded = true; }

    void restart_homestore() {
        m_helper.params(HS_SERVICE::INDEX).index_svc_cbs = new TestIndexServiceCallbacks(this);
        m_helper.restart_homestore();
    }

    void SetUp() override {
        m_helper.start_homestore(
            "test_index_btree",
            {{HS_SERVICE::META, {.size_pct = 10.0}},
             {HS_SERVICE::INDEX, {.size_pct = 70.0, .index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, {}, SISL_OPTIONS["init_device"].as< bool >());

        LOGINFO("Node size {} ", hs()->index_service().node_size());
        this->m_cfg = BtreeConfig(hs()->index_service().node_size());

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        // Test cp flush of write back.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        BtreeTestHelper< TestType >::SetUp();
        if (this->m_bt == nullptr || SISL_OPTIONS["init_device"].as< bool >()) {
            this->m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, this->m_cfg);
        } else {
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
        m_helper.shutdown_homestore(false);
    }

private:
    const std::string m_shadow_filename = "/tmp/shadow_map.txt";
    test_common::HSTestHelper m_helper;
};

TYPED_TEST_SUITE(BtreeConcurrentTest, BtreeTypes);
TYPED_TEST(BtreeConcurrentTest, ConcurrentAllOps) {
    // range put is not supported for non-extent keys
    std::vector< std::string > input_ops = {"put:18", "remove:14", "range_put:20", "range_remove:2", "query:10"};
    if (SISL_OPTIONS.count("operation_list")) {
        input_ops = SISL_OPTIONS["operation_list"].as< std::vector< std::string > >();
    }
    auto ops = this->build_op_list(input_ops);

    this->multi_op_execute(ops, !SISL_OPTIONS["init_device"].as< bool >());
}

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_index_btree, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_index_btree");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");

    if (SISL_OPTIONS.count("seed")) {
        auto seed = SISL_OPTIONS["seed"].as< uint64_t >();
        LOGINFO("Using seed {} to sow the random generation", seed);
        g_re.seed(seed);
    }
    auto ret = RUN_ALL_TESTS();
    return ret;
}
