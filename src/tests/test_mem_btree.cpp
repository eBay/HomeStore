/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#include <iomgr/io_environment.hpp>
#include <sisl/options/options.h>
#include <sisl/logging/logging.h>
#include <sisl/utility/enum.hpp>
#include <boost/algorithm/string.hpp>

#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/btree/detail/prefix_node.hpp>
#include <homestore/btree/mem_btree.hpp>
#include "test_common/range_scheduler.hpp"
#include "btree_helpers/btree_test_kvs.hpp"
#include "btree_helpers/btree_test_helper.hpp"

using namespace homestore;
SISL_LOGGING_INIT(btree, iomgr, io_wd, flip)

SISL_OPTIONS_ENABLE(logging, test_mem_btree)
SISL_OPTION_GROUP(
    test_mem_btree,
    (num_iters, "", "num_iters", "number of iterations for rand ops",
     ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
    (num_entries, "", "num_entries", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("10000"), "number"),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (n_threads, "", "n_threads", "number of threads", ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
    (n_fibers, "", "n_fibers", "number of fibers", ::cxxopts::value< uint32_t >()->default_value("10"), "number"),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    (preload_size, "", "preload_size", "number of entries to preload tree with",
     ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"))

struct FixedLenBtreeTest {
    using BtreeType = MemBtree< TestFixedKey, TestFixedValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestFixedValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::FIXED;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
};

struct VarKeySizeBtreeTest {
    using BtreeType = MemBtree< TestVarLenKey, TestFixedValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestFixedValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_KEY;
    static constexpr btree_node_type interior_node_type = btree_node_type::VAR_KEY;
};

struct VarValueSizeBtreeTest {
    using BtreeType = MemBtree< TestFixedKey, TestVarLenValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestVarLenValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_VALUE;
    static constexpr btree_node_type interior_node_type = btree_node_type::FIXED;
};

struct VarObjSizeBtreeTest {
    using BtreeType = MemBtree< TestVarLenKey, TestVarLenValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestVarLenValue;
    static constexpr btree_node_type leaf_node_type = btree_node_type::VAR_OBJECT;
    static constexpr btree_node_type interior_node_type = btree_node_type::VAR_OBJECT;
};

struct PrefixIntervalBtreeTest {
    using BtreeType = MemBtree< TestIntervalKey, TestIntervalValue >;
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

    void SetUp() override {
        BtreeTestHelper< TestType >::SetUp();
        this->m_bt = std::make_shared< typename T::BtreeType >(this->m_cfg);
        this->m_bt->init(nullptr);
    }
};

using BtreeTypes = testing::Types< PrefixIntervalBtreeTest, FixedLenBtreeTest, VarKeySizeBtreeTest,
                                   VarValueSizeBtreeTest, VarObjSizeBtreeTest >;
TYPED_TEST_SUITE(BtreeTest, BtreeTypes);

TYPED_TEST(BtreeTest, SequentialInsert) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 1: Do forward sequential insert for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->do_query(0, entries_iter1 - 1, 75);

    // Reverse sequential insert
    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 3: Do reverse sequential insert of remaining {} entries", entries_iter2);
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
}

TYPED_TEST(BtreeTest, SequentialRemove) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);

    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 3: Do forward sequential remove for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->remove_one(i);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->do_query(0, entries_iter1 - 1, 75);

    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 5: Do reverse sequential remove of remaining {} entries", entries_iter2);
    for (uint32_t i{num_entries - 1}; i >= entries_iter1; --i) {
        this->remove_one(i);
    }

    LOGINFO("Step 6: Query the empty tree");
    this->do_query(0, num_entries, 75);
    this->get_any(0, 1);
    this->get_specific(0);
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

TYPED_TEST(BtreeTest, RangeUpdate) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    LOGINFO("Step 2: Do range update of random intervals between [1-50] for 100 times with random key ranges");
    for (uint32_t i{0}; i < 100; ++i) {
        this->range_put_random();
    }

    LOGINFO("Step 3: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->do_query(0, num_entries - 1, 75);
}

TYPED_TEST(BtreeTest, SimpleRemoveRange) {
    // Forward sequential insert
    const auto num_entries = 20;
    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    LOGINFO("Step 2: Do range remove for {} entries", num_entries);
    //    this->print_keys(); // EXPECT size = 20 : 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
    this->range_remove_any(5, 10);
    //    this->print_keys(); // EXPECT size = 14 : 0 1 2 3 4 [5 6 7 8 9 10] 11 12 13 14 15 16 17 18 19
    this->range_remove_any(0, 2);
    //    this->print_keys(); // EXPECT size = 11 : [0 1 2] 3 4 11 12 13 14 15 16 17 18 19
    this->range_remove_any(18, 19);
    //    this->print_keys(); // EXPECT size = 9 : 3 4 11 12 13 14 15 16 17 [18 19]
    this->range_remove_any(17, 17);
    //    this->print_keys(); // EXPECT size = 8 : 3 4 11 12 13 14 15 16 [17]
    this->range_remove_any(1, 5);
    //    this->print_keys(); // EXPECT size = 6 : [3 4] 11 12 13 14 15 16
    this->range_remove_any(1, 20);
    //    this->print_keys(); // EXPECT size = 0 : [11 12 13 14 15 16]

    this->query_all();
    //    this->query_validate(0, num_entries , 75);
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

TYPED_TEST(BtreeTest, RandomRemoveRange) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    const auto num_iters = SISL_OPTIONS["num_iters"].as< uint32_t >();

    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    // generate keys including out of bound
    static thread_local std::uniform_int_distribution< uint32_t > s_rand_key_generator{0, 2 * num_entries};
    //    this->print_keys();
    LOGINFO("Step 2: Do range remove for maximum of {} iterations", num_iters);
    for (uint32_t i{0}; (i < num_iters) && this->m_shadow_map.size(); ++i) {
        uint32_t key1 = s_rand_key_generator(g_re);
        uint32_t key2 = s_rand_key_generator(g_re);

        //        LOGINFO("Step 2 - {}: Do Range Remove of maximum [{},{}] keys ", i, start_key, end_key);
        this->range_remove_any(std::min(key1, key2), std::max(key1, key2));
        //        this->print_keys();
    }

    this->query_all();
}

template < typename TestType >
struct BtreeConcurrentTest : public BtreeTestHelper< TestType > {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    BtreeConcurrentTest() { this->m_is_multi_threaded = true; }

    void SetUp() override {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_max_range_input = SISL_OPTIONS["num_entries"].as< uint32_t >();
        if (SISL_OPTIONS.count("disable_merge")) m_cfg.m_merge_turned_on = false;
        m_fibers.clear();
        m_bt = std::make_unique< typename T::BtreeType >(m_cfg);
        m_bt->init(nullptr);
    }

    void TearDown() override { iomanager.stop(); }

    void print() const { m_bt->print_tree(); }
    void print_keys() const { m_bt->print_tree_keys(); }

    void execute(const std::vector< std::pair< std::string, int > >& op_list) {

        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_max_range_input = SISL_OPTIONS["num_entries"].as< uint32_t >();
        if (SISL_OPTIONS.count("disable_merge")) m_cfg.m_merge_turned_on = false;
        m_fibers.clear();
        m_bt = std::make_unique< typename T::BtreeType >(m_cfg);
        m_bt->init(nullptr);
    }

    void TearDown() override { iomanager.stop(); }

    void print() const { m_bt->print_tree(); }
    void print_keys() const { m_bt->print_tree_keys(); }

    void execute(const std::vector< std::pair< std::string, int > >& op_list) {
        LOGINFO("Starting iomgr with {} threads", SISL_OPTIONS["n_threads"].as< uint32_t >());
        ioenvironment.with_iomgr(iomgr::iomgr_params{.num_threads = SISL_OPTIONS["n_threads"].as< uint32_t >(),
                                                     .is_spdk = false,
                                                     .is_spdk = false,
                                                     .num_fibers = 1 + SISL_OPTIONS["n_fibers"].as< uint32_t >(),
                                                     .app_mem_size_mb = 0,
                                                     0});

        BtreeTestHelper< TestType >::SetUp();
        this->m_bt = std::make_shared< typename T::BtreeType >(this->m_cfg);
        this->m_bt->init(nullptr);
    }

    void TearDown() override {
        BtreeTestHelper< TestType >::TearDown();
        iomanager.stop();
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
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, logging, test_mem_btree)
    sisl::logging::SetLogger("test_mem_btree");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");

    if (SISL_OPTIONS.count("seed")) {
        auto seed = SISL_OPTIONS["seed"].as< uint64_t >();
        LOGINFO("Using seed {} to sow the random generation", seed);
        g_re.seed(seed);
    }
    auto ret = RUN_ALL_TESTS();
    return ret;
}
