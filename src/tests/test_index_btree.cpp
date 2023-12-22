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

#include <random>
#include <map>
#include <memory>
#include <gtest/gtest.h>
#include <boost/uuid/random_generator.hpp>

#include <iomgr/io_environment.hpp>
#include <sisl/options/options.h>
#include <sisl/logging/logging.h>
#include <sisl/utility/enum.hpp>
#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/homestore.hpp>
#include <homestore/index/index_table.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_test_helper.hpp"

using namespace homestore;

SISL_LOGGING_DEF(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_index_btree, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_btree)

std::vector< std::string > test_common::HSTestHelper::s_dev_names;

// TODO Add tests to do write,remove after recovery.
// TODO Test with var len key with io mgr page size is 512.

SISL_OPTION_GROUP(test_index_btree,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("500"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                   ::cxxopts::value< uint32_t >()->default_value("5000"), "number"),
                  (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("360000"), "seconds"),
                  (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
                  (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
                   ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
                  (preload_size, "", "preload_size", "number of entries to preload tree with",
                   ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
                  (seed, "", "seed", "random engine seed, use random if not defined",
                   ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

struct FixedLenBtreeTest {
    using BtreeType = IndexTable< TestFixedKey, TestFixedValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestFixedValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::FIXED;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
};

struct VarKeySizeBtreeTest {
    using BtreeType = IndexTable< TestVarLenKey, TestFixedValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestFixedValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_KEY;
    static constexpr btree_node_type interior_node_type = btree_node_type::VAR_KEY;
};

struct VarValueSizeBtreeTest {
    using BtreeType = IndexTable< TestFixedKey, TestVarLenValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestVarLenValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_VALUE;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
};

struct VarObjSizeBtreeTest {
    using BtreeType = IndexTable< TestVarLenKey, TestVarLenValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestVarLenValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_OBJECT;
    static constexpr btree_node_type interior_node_type = btree_node_type::VAR_OBJECT;
};

struct PrefixIntervalBtreeTest {
    using BtreeType = IndexTable< TestIntervalKey, TestIntervalValue >;
    using KeyType = TestIntervalKey;
    using ValueType = TestIntervalValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::PREFIX;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
};

template < typename TestType >
struct BtreeTest : public BtreeTestHelper< TestType > {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeTest* test) : m_test(test) {}
        std::shared_ptr< IndexTableBase > on_index_table_found(const superblk< index_table_sb >& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("Root bnode_id {} version {}", sb->root_node, sb->link_version);
            m_test->m_bt = std::make_shared< typename T::BtreeType >(sb, m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        BtreeTest* m_test;
    };

    void SetUp() override {
        test_common::HSTestHelper::start_homestore(
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
        test_common::HSTestHelper::shutdown_homestore();
    }

    void restart_homestore() {
        test_common::HSTestHelper::start_homestore(
            "test_index_btree",
            {{HS_SERVICE::META, {}}, {HS_SERVICE::INDEX, {.index_svc_cbs = new TestIndexServiceCallbacks(this)}}},
            nullptr, true /* restart */);
    }

    void destroy_btree() {
        auto cpg = hs()->cp_mgr().cp_guard();
        auto op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
        const auto [ret, free_node_cnt] = this->m_bt->destroy_btree(op_context);
        ASSERT_EQ(ret, btree_status_t::success) << "btree destroy failed";
        this->m_bt.reset();
    }
};

using BtreeTypes = testing::Types< FixedLenBtreeTest, VarKeySizeBtreeTest, VarValueSizeBtreeTest, VarObjSizeBtreeTest >;

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
    const auto num_iters = SISL_OPTIONS["num_iters"].as< uint32_t >();

    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    std::vector< uint32_t > vec(num_entries);
    iota(vec.begin(), vec.end(), 0);

    // shuffle keys in [0, num_entries)
    std::random_shuffle(vec.begin(), vec.end());
    LOGINFO("Step 2: Do remove one by one for {} iterations", num_iters);
    for (uint32_t i{0}; i < num_iters; ++i) {
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

    this->print(std::string("before.txt"));

    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO("Restarted homestore with index recovered");

    this->print(std::string("after.txt"));

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

    this->print(std::string("before.txt"));

    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO(" Restarted homestore with index recovered");
    this->print(std::string("after.txt"));

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
            LOGINFO("Removing entry {}", rm_idx);
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

    this->print(std::string("before.txt"));
    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    this->restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{1});
    LOGINFO(" Restarted homestore with index recovered");
    this->print(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", num_entries);
    this->do_query(0, num_entries - 1, 1000);
    LOGINFO("ThreadedCpFlush test end");
}

template < typename TestType >
struct BtreeConcurrentTest : public BtreeTestHelper< TestType > {

    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;
    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeConcurrentTest* test) : m_test(test) {}
        std::shared_ptr< IndexTableBase > on_index_table_found(const superblk< index_table_sb >& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("Root bnode_id {} version {}", sb->root_node, sb->link_version);
            m_test->m_bt = std::make_shared< typename T::BtreeType >(sb, m_test->m_cfg);
            return m_test->m_bt;
        }

    private:
        BtreeConcurrentTest* m_test;
    };

    BtreeConcurrentTest() { this->m_is_multi_threaded = true; }

    void SetUp() override {
        test_common::HSTestHelper::start_homestore(
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
        test_common::HSTestHelper::shutdown_homestore();
    }
};

TYPED_TEST_SUITE(BtreeConcurrentTest, BtreeTypes);
TYPED_TEST(BtreeConcurrentTest, ConcurrentAllOps) {
    // range put is not supported for non-extent keys
    std::vector< std::string > input_ops = {"put:20", "remove:20", "range_put:20", "range_remove:20", "query:20"};
    std::vector< std::pair< std::string, int > > ops;
    if (SISL_OPTIONS.count("operation_list")) {
        input_ops = SISL_OPTIONS["operation_list"].as< std::vector< std::string > >();
    }
    int total = std::accumulate(input_ops.begin(), input_ops.end(), 0, [](int sum, const auto& str) {
        std::vector< std::string > tokens;
        boost::split(tokens, str, boost::is_any_of(":"));
        if (tokens.size() == 2) {
            try {
                return sum + std::stoi(tokens[1]);
            } catch (const std::exception&) {
                // Invalid frequency, ignore this element
            }
        }
        return sum; // Ignore malformed strings
    });

    std::transform(input_ops.begin(), input_ops.end(), std::back_inserter(ops), [total](const auto& str) {
        std::vector< std::string > tokens;
        boost::split(tokens, str, boost::is_any_of(":"));
        if (tokens.size() == 2) {
            try {
                return std::make_pair(tokens[0], (int)(100.0 * std::stoi(tokens[1]) / total));
            } catch (const std::exception&) {
                // Invalid frequency, ignore this element
            }
        }
        return std::make_pair(std::string(), 0);
    });

    this->multi_op_execute(ops);
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
