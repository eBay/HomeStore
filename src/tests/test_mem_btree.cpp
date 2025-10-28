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

#include <homestore/btree/mem_btree.hpp>
#include "test_common/range_scheduler.hpp"
#include <homestore/btree/mem_btree.hpp>
#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/btree/detail/prefix_node.hpp>
#include "btree_helpers/btree_test_helper.hpp"

using namespace homestore;
SISL_LOGGING_DEF(btree)
SISL_LOGGING_INIT(btree)

SISL_OPTIONS_ENABLE(logging, test_mem_btree)
SISL_OPTION_GROUP(
    test_mem_btree,
    (num_iters, "", "num_iters", "number of iterations for rand ops",
     ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
    (num_entries, "", "num_entries", "number of entries to test with",
     ::cxxopts::value< uint32_t >()->default_value("10000"), "number"),
    (disable_merge, "", "disable_merge", "disable_merge", ::cxxopts::value< bool >()->default_value("0"), ""),
    (max_merge_level, "", "max_merge_level", "max merge level", ::cxxopts::value< uint8_t >()->default_value("127"),
     ""),
    (num_threads, "", "num_threads", "number of threads", ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
    (num_fibers, "", "num_fibers", "number of fibers", ::cxxopts::value< uint32_t >()->default_value("10"), "number"),
    (operation_list, "", "operation_list", "operation list instead of default created following by percentage",
     ::cxxopts::value< std::vector< std::string > >(), "operations [...]"),
    (preload_size, "", "preload_size", "number of entries to preload tree with",
     ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
    (max_keys_in_node, "", "max_keys_in_node", "max_keys_in_node", ::cxxopts::value< uint32_t >()->default_value("0"),
     ""),
    (seed, "", "seed", "random engine seed, use random if not defined",
     ::cxxopts::value< uint64_t >()->default_value("0"), "number"),
    (run_time, "", "run_time", "run time for io", ::cxxopts::value< uint32_t >()->default_value("360000"), "seconds"))

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
struct BtreeTest : public BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    BtreeTest() : testing::Test() {}

    void SetUp() override {
        BtreeTestHelper< TestType >::SetUp();
#ifdef _PRERELEASE
        this->m_cfg.m_max_keys_in_node = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
#endif
        this->m_cfg.m_max_merge_level = SISL_OPTIONS["max_merge_level"].as< uint8_t >();
        this->m_cfg.m_merge_turned_on = !SISL_OPTIONS["disable_merge"].as< bool >();
        this->m_bt = std::make_shared< typename T::BtreeType >(this->m_cfg);
    }
};

using BtreeTypes = testing::Types< FixedLenBtreeTest, PrefixIntervalBtreeTest, VarKeySizeBtreeTest,
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
    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(vec.begin(), vec.end(), g);
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

    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT);
    }

    std::vector< uint32_t > vec(num_entries);
    iota(vec.begin(), vec.end(), 0);

    // shuffle keys in [0, num_entries)
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(vec.begin(), vec.end(), g);
    LOGINFO("Step 2: Do remove one by one for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
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
    static thread_local std::uniform_int_distribution< uint32_t > s_rand_key_generator{0, num_entries};
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

TYPED_TEST(BtreeTest, SimpleTombstone) {
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < 20; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    this->move_to_tombstone(10, btree_status_t::success);
    this->move_to_tombstone(10, btree_status_t::filtered_out);
    this->move_to_tombstone(40, btree_status_t::not_found);
}

TYPED_TEST(BtreeTest, SimpleMultiTombstone) {
    if constexpr (std::is_same_v< TypeParam, PrefixIntervalBtreeTest >) { return; }
    uint32_t start_key = 500;
    uint32_t end_key = 1000;
    LOGDEBUG("Step 1: Do forward sequential insert for [{},{}] entries", start_key, end_key);
    for (uint32_t i{start_key}; i <= end_key; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    std::vector< std::pair< typename TypeParam::KeyType, typename TypeParam::ValueType > > out;
    auto format_tombstoned = [](const auto& out) {
        std::stringstream ss;
        for (const auto& [k, v] : out) {
            ss << "[" << k.to_string() << "] =" << v.to_string() << std::endl;
        }
        return ss.str();
    };
    auto run_and_validate_tombstone = [&](auto s, auto e, auto expect_status, auto expected_size) {
        this->move_to_tombstone(s, e, out, expect_status);
        LOGDEBUG("Tombstoned {} keys:\n{}", out.size(), format_tombstoned(out));
        ASSERT_EQ(out.size(), expected_size) << "Tombstoned keys should be " << expected_size << ", but got "
                                             << out.size() << " keys in range [" << s << ", " << e << "]";
    };
    auto sum_tombstoned = 0;
    {
        run_and_validate_tombstone(0, start_key - 100, btree_status_t::not_found, 0);
        run_and_validate_tombstone(end_key + 100, end_key + 2000, btree_status_t::not_found, 0);
    }
    {
        run_and_validate_tombstone(start_key - 100, start_key, btree_status_t::success, 1);
        run_and_validate_tombstone(start_key - 100, start_key, btree_status_t::success, 0);
        sum_tombstoned += 1;
    }
    {
        run_and_validate_tombstone(start_key + 20, start_key + 40, btree_status_t::success, 21);
        run_and_validate_tombstone(start_key + 20, start_key + 40, btree_status_t::success, 0);
        run_and_validate_tombstone(start_key + 20, start_key + 41, btree_status_t::success, 1);
        run_and_validate_tombstone(start_key + 45, start_key + 50, btree_status_t::success, 6);
        run_and_validate_tombstone(start_key + 20, start_key + 60, btree_status_t::success, 41 - 28);
        sum_tombstoned += 21 + 1 + 6 + (41 - 28);
    }

    {
        run_and_validate_tombstone(end_key, end_key + 1000, btree_status_t::success, 1);
        run_and_validate_tombstone(end_key, end_key + 1000, btree_status_t::success, 0);
        sum_tombstoned += 1;
    }
    {
        run_and_validate_tombstone(0, end_key + 1000, btree_status_t::success,
                                   end_key - start_key - sum_tombstoned + 1);
        run_and_validate_tombstone(0, end_key + 1000, btree_status_t::success, 0);
    }
    this->range_remove_existing(start_key, end_key - start_key + 1);
    ASSERT_EQ(this->m_bt->count_keys(), 0);
    // creating two intervals
    uint32_t start_key1 = 1000;
    uint32_t end_key1 = 1999;
    uint32_t start_key2 = 3000;
    uint32_t end_key2 = 3999;
    sum_tombstoned = 0;
    for (uint32_t i{start_key1}; i <= end_key1; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    for (uint32_t i{start_key2}; i <= end_key2; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    {
        run_and_validate_tombstone(start_key1 + 100, end_key2 + 100, btree_status_t::success, 1900);
        run_and_validate_tombstone(start_key1 + 100, end_key2 + 100, btree_status_t::success, 0);
    }
}

TYPED_TEST(BtreeTest, SimpleGC) {
    if constexpr (std::is_same_v< TypeParam, PrefixIntervalBtreeTest >) { return; }
    uint32_t start_key1 = 1000;
    uint32_t end_key1 = 1999;
    uint32_t start_key2 = 3000;
    uint32_t end_key2 = 3999;
    std::vector< std::pair< typename TypeParam::KeyType, typename TypeParam::ValueType > > out;
    for (uint32_t i{start_key1}; i <= end_key1; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    for (uint32_t i{start_key2}; i <= end_key2; ++i) {
        this->put(i, btree_put_type::INSERT);
    }
    this->print_keys(" Before tombstone ");
    auto start_tombstone = start_key1 + 100;
    auto end_tombstone = end_key1 - 100;
    auto expected_size = end_key1 - 200 - start_key1 + 1;
    this->move_to_tombstone(start_tombstone, end_tombstone, out, btree_status_t::success);
    ASSERT_EQ(out.size(), expected_size) << "Tombstoned keys should be " << expected_size << ", but got " << out.size()
                                         << " keys in range [" << start_tombstone << ", " << end_tombstone << "]";

    this->print_keys(fmt::format(" After tombstone [{},{}] ", start_tombstone, end_tombstone));
    LOGINFO("Step 2: Do GC on the tree for keys in range [{}, {}]", start_key1, end_key2);
    this->remove_tombstone(start_key1, end_key2, out, btree_status_t::success);
    expected_size = end_key2 - start_key1 + 1 - 1000 - expected_size;
    ASSERT_EQ(out.size(), expected_size) << "# of keys after GCs hould be " << expected_size << ", but got "
                                         << out.size() << " keys in range [" << start_key1 << ", " << end_key2 << "]";
    auto format_tombstoned = [](const auto& out) {
        std::stringstream ss;
        for (const auto& [k, v] : out) {
            ss << "[" << k.to_string() << "] =" << v.to_string() << std::endl;
        }
        return ss.str();
    };

    this->print_keys(fmt::format(" After GC {} entries are still in range [{},{}] ", out.size(), start_key1, end_key2));
    LOGDEBUG("GC {} keys:\n{}", out.size(), format_tombstoned(out));
    this->remove_tombstone(start_key1, end_key2, out, btree_status_t::not_found);
    ASSERT_EQ(out.size(), expected_size) << "After GC, no keys should be left in range [" << start_key1 << ", "
                                         << end_key2 << "] but got " << out.size();
    LOGDEBUG("GC {} keys:\n{}", out.size(), format_tombstoned(out));
}

template < typename TestType >
struct BtreeConcurrentTest : public BtreeTestHelper< TestType >, public ::testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    BtreeConcurrentTest() : testing::Test() { this->m_is_multi_threaded = true; }

    void SetUp() override {
        LOGINFO("Starting iomgr with {} threads", SISL_OPTIONS["num_threads"].as< uint32_t >());
        ioenvironment.with_iomgr(iomgr::iomgr_params{.num_threads = SISL_OPTIONS["num_threads"].as< uint32_t >(),
                                                     .is_spdk = false,
                                                     .num_fibers = 1 + SISL_OPTIONS["num_fibers"].as< uint32_t >(),
                                                     .app_mem_size_mb = 0,
                                                     .hugepage_size_mb = 0});

        BtreeTestHelper< TestType >::SetUp();
#ifdef _PRERELEASE
        this->m_cfg.m_max_keys_in_node = SISL_OPTIONS["max_keys_in_node"].as< uint32_t >();
#endif
        this->m_cfg.m_max_merge_level = SISL_OPTIONS["max_merge_level"].as< uint8_t >();
        this->m_cfg.m_merge_turned_on = !SISL_OPTIONS["disable_merge"].as< bool >();
        this->m_bt = std::make_shared< typename T::BtreeType >(this->m_cfg);
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
    if (SISL_OPTIONS.count("operation_list")) {
        input_ops = SISL_OPTIONS["operation_list"].as< std::vector< std::string > >();
    }
    auto ops = this->build_op_list(input_ops);

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
    } else {
        auto seed = std::chrono::system_clock::now().time_since_epoch().count();
        LOGINFO("No seed provided. Using randomly generated seed: {}", seed);
        g_re.seed(seed);
    }
    auto ret = RUN_ALL_TESTS();
    return ret;
}
