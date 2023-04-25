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

#include <sisl/options/options.h>
#include <sisl/logging/logging.h>
#include <sisl/utility/enum.hpp>
#include "btree_test_kvs.hpp"
#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/btree/mem_btree.hpp>
#include <ranges>
#include "test_common/range_scheduler.hpp"

static constexpr uint32_t g_node_size{4096};
using namespace homestore;
SISL_LOGGING_INIT(btree)

SISL_OPTIONS_ENABLE(logging, test_mem_btree)
SISL_OPTION_GROUP(test_mem_btree,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("100"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                   ::cxxopts::value< uint32_t >()->default_value("10000"), "number"),
                  (merge_activate, "", "merge_activate", "merge_activate",
                   ::cxxopts::value< bool >()->default_value("0"), ""),
                  (n_threads, "", "n_threads", "number of threads", ::cxxopts::value< uint32_t >()->default_value("10"),
                   "number"),
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

template < typename TestType >
struct BtreeTest : public testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    std::unique_ptr< typename T::BtreeType > m_bt;
    std::map< K, V > m_shadow_map;
    BtreeConfig m_cfg{g_node_size};

    void SetUp() override {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        if (SISL_OPTIONS.count("merge_activate")) m_cfg.m_merge_turned_on = true;
        m_bt = std::make_unique< typename T::BtreeType >(m_cfg);
        m_bt->init(nullptr);
    }

    void put(uint32_t k, btree_put_type put_type) {
        std::unique_ptr< V > existing_v = std::make_unique< V >();

        auto sreq = BtreeSinglePutRequest{std::make_unique< K >(k), std::make_unique< V >(V::generate_rand()), put_type,
                                          std::move(existing_v)};
        bool done = (m_bt->put(sreq) == btree_status_t::success);

        // auto& sreq = to_single_put_req(req);
        bool expected_done{true};
        if (m_shadow_map.find(*sreq.m_k) != m_shadow_map.end()) {
            expected_done = (put_type != btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        }
        ASSERT_EQ(done, expected_done) << "Expected put of key " << k << " of put_type " << enum_name(put_type)
                                       << " to be " << expected_done;
        if (expected_done) {
            m_shadow_map.insert(std::make_pair((const K&)*sreq.m_k, (const V&)*sreq.m_v));
        } else {
            const auto r = m_shadow_map.find(*sreq.m_k);
            ASSERT_NE(r, m_shadow_map.end()) << "Testcase issue, expected inserted slots to be in shadow map";
            ASSERT_EQ((const V&)*sreq.m_existing_val, r->second)
                << "Insert existing value doesn't return correct data for key " << r->first;
        }
    }

    void range_put(uint32_t max_count) {
        const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
        static std::uniform_int_distribution< uint32_t > s_randkey_start_generator{1, num_entries};
        auto val = std::make_unique< V >(V::generate_rand());

    retry:
        auto const start_it = m_shadow_map.lower_bound(K{s_randkey_start_generator(g_re)});
        auto end_it = start_it;
        auto it = start_it;
        uint32_t count = 0;
        while ((it != m_shadow_map.end()) && (count++ < max_count)) {
            it->second = *val;
            end_it = it++;
        }
        if (count == 0) { goto retry; }

        auto mreq = BtreeRangePutRequest< K >{BtreeKeyRange< K >{start_it->first, true, end_it->first, true},
                                              btree_put_type::REPLACE_ONLY_IF_EXISTS, std::move(val)};
        ASSERT_EQ(m_bt->put(mreq), btree_status_t::success);
    }

    void remove_one(uint32_t k) {
        std::unique_ptr< V > existing_v = std::make_unique< V >();
        auto rreq = BtreeSingleRemoveRequest{std::make_unique< K >(k), std::move(existing_v)};
        bool removed = (m_bt->remove(rreq) == btree_status_t::success);

        bool expected_removed = (m_shadow_map.find(rreq.key()) != m_shadow_map.end());
        ASSERT_EQ(removed, expected_removed) << "Expected remove of key " << k << " to be " << expected_removed;

        if (removed) {
            validate_data(rreq.key(), (const V&)rreq.value());
            m_shadow_map.erase(rreq.key());
        }
    }

    void range_remove(uint32_t start_key, uint32_t end_key) {

        auto start_it = m_shadow_map.lower_bound(K{start_key});
        auto end_it = m_shadow_map.lower_bound(K{end_key});
        auto fount_it = m_shadow_map.find(K{end_key});
        bool expected = (start_it != m_shadow_map.end()) && (std::distance(start_it, end_it) >= 0);
        if (start_it == end_it && fount_it == m_shadow_map.end()) { expected = false; }
        auto range = BtreeKeyRange< K >{K{start_key}, true, K{end_key}, true};
        LOGINFO("range : {}", range.to_string());
        auto mreq = BtreeRangeRemoveRequest< K >{std::move(range)};

        size_t original_ts = get_tree_size();
        size_t original_ms = m_shadow_map.size();

        auto ret = m_bt->remove(mreq);
        ASSERT_EQ(expected, ret == btree_status_t::success)
            << " not a successful remove op for range " << range.to_string()
            << "start_it!=m_shadow_map.end(): " << (start_it != m_shadow_map.end())
            << " and std::distance(start_it,end_it) >= 0 : " << (std::distance(start_it, end_it) >= 0);

        K out_key;
        V out_value;
        auto qret = get_num_elements_in_tree(start_key, end_key, out_key, out_value);
        ASSERT_EQ(qret, btree_status_t::not_found)
            << "  At least one element found! [" << out_key << "] = " << out_value;

        if (expected) { m_shadow_map.erase(start_it, fount_it != m_shadow_map.end() ? ++end_it : end_it); }
        size_t ms = m_shadow_map.size();
        size_t ts = get_tree_size();
        ASSERT_EQ(original_ms - ms, original_ts - ts) << " number of removed from map is " << original_ms - ms
                                                      << " whereas number of existing keys is " << original_ts - ts;

        ASSERT_EQ(ts, ms) << " size of tree is " << ts << " vs number of existing keys are " << ms;
    }

    void query_all_validate() const {
        query_validate(0u, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1, UINT32_MAX);
    }

    void query_all_paginate_validate(uint32_t batch_size) const {
        query_validate(0u, SISL_OPTIONS["num_entries"].as< uint32_t >() - 1, batch_size);
    }

    void query_validate(uint32_t start_k, uint32_t end_k, uint32_t batch_size) const {
        std::vector< std::pair< K, V > > out_vector;
        uint32_t remaining = num_elems_in_range(start_k, end_k);
        auto it = m_shadow_map.lower_bound(K{start_k});

        BtreeQueryRequest< K > qreq{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true},
                                    BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, batch_size};
        while (remaining > 0) {
            out_vector.clear();
            auto const ret = m_bt->query(qreq, out_vector);
            auto const expected_count = std::min(remaining, batch_size);

            ASSERT_EQ(out_vector.size(), expected_count) << "Received incorrect value on query pagination";
            remaining -= expected_count;

            if (remaining == 0) {
                ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
            } else {
                ASSERT_EQ(ret, btree_status_t::has_more) << "Expected query to return has_more";
            }

            for (size_t idx{0}; idx < out_vector.size(); ++idx) {
                ASSERT_EQ(out_vector[idx].second, it->second)
                    << "Range get doesn't return correct data for key=" << it->first << " idx=" << idx;
                ++it;
            }
        }
        out_vector.clear();
        auto ret = m_bt->query(qreq, out_vector);
        ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
        ASSERT_EQ(out_vector.size(), 0) << "Received incorrect value on empty query pagination";
    }

    void get_all_validate() const {
        for (const auto& [key, value] : m_shadow_map) {
            auto copy_key = std::make_unique< K >();
            *copy_key = key;
            auto req = BtreeSingleGetRequest{std::move(copy_key), std::make_unique< V >()};
            // BtreeSingleGetRequest& greq = to_single_get_req(req);
            const auto ret = m_bt->get(req);
            ASSERT_EQ(ret, btree_status_t::success) << "Missing key " << key << " in btree but present in shadow map";
            ASSERT_EQ((const V&)req.value(), value)
                << "Found value in btree doesn't return correct data for key=" << key;
        }
    }

    void get_specific_validate(uint32_t k) const {
        auto req = BtreeSingleGetRequest{std::make_unique< K >(k), std::make_unique< V >()};
        // BtreeSingleGetRequest& greq = to_single_get_req(req);
        const auto status = m_bt->get(req);
        if (status == btree_status_t::success) {
            validate_data(req.key(), (const V&)req.value());
        } else {
            ASSERT_EQ((m_shadow_map.find(req.key()) == m_shadow_map.end()), true)
                << "Node key " << k << " is missing in the btree";
        }
    }

    void get_any_validate(uint32_t start_k, uint32_t end_k) const {
        auto req = BtreeGetAnyRequest< K >{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true},
                                           std::make_unique< K >(), std::make_unique< V >()};
        const auto status = m_bt->get(req);
        if (status == btree_status_t::success) {
            ASSERT_EQ(found_in_range(*(K*)req.m_outkey.get(), start_k, end_k), true)
                << "Get Any returned key=" << *(K*)req.m_outkey.get() << " which is not in range " << start_k << "-"
                << end_k << "according to shadow map";
            validate_data(*(K*)req.m_outkey.get(), *(V*)req.m_outval.get());
        } else {
            ASSERT_EQ(found_in_range(*(K*)req.m_outkey.get(), start_k, end_k), false)
                << "Get Any couldn't find key in the range " << start_k << "-" << end_k
                << " but it present in shadow map";
        }
    }

    void print() const { m_bt->print_tree(); }

    void print_keys() const { m_bt->print_tree_keys(); }

    size_t get_tree_size() {
        BtreeQueryRequest< K > qreq{
            BtreeKeyRange< K >{K{0}, true, K{SISL_OPTIONS["num_entries"].as< uint32_t >()}, true},
            BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, UINT32_MAX};
        std::vector< std::pair< K, V > > out_vector;
        auto const ret = m_bt->query(qreq, out_vector);
        return out_vector.size();
    }

    btree_status_t get_num_elements_in_tree(uint32_t start_k, uint32_t end_k, K& out_key, V& out_value) const {
        auto req = BtreeGetAnyRequest< K >{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true},
                                           std::make_unique< K >(), std::make_unique< V >()};
        auto ret = m_bt->get(req);
        out_key = *((K*)req.m_outkey.get());
        out_value = *((V*)req.m_outval.get());
        return ret;
    }

private:
    void validate_data(const K& key, const V& btree_val) const {
        const auto r = m_shadow_map.find(key);
        ASSERT_NE(r, m_shadow_map.end()) << "Node key is not present in shadow map";
        ASSERT_EQ(btree_val, r->second) << "Found value in btree doesn't return correct data for key=" << r->first;
    }

    bool found_in_range(const K& key, uint32_t start_k, uint32_t end_k) const {
        const auto itlower = m_shadow_map.lower_bound(K{start_k});
        const auto itupper = m_shadow_map.upper_bound(K{end_k});
        auto it = itlower;
        while (it != itupper) {
            if (it->first == key) { return true; }
            ++it;
        }
        return false;
    }

    uint32_t num_elems_in_range(uint32_t start_k, uint32_t end_k) const {
        const auto itlower = m_shadow_map.lower_bound(K{start_k});
        const auto itupper = m_shadow_map.upper_bound(K{end_k});
        return std::distance(itlower, itupper);
    }
};

using BtreeTypes = testing::Types< FixedLenBtreeTest, VarKeySizeBtreeTest, VarValueSizeBtreeTest, VarObjSizeBtreeTest >;
TYPED_TEST_SUITE(BtreeTest, BtreeTypes);

TYPED_TEST(BtreeTest, SequentialInsert) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->query_validate(0, entries_iter1, 75);

    // Reverse sequential insert
    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 3: Do Reverse sequential insert of remaining {} entries", entries_iter2);
    for (uint32_t i{num_entries - 1}; i >= entries_iter1; --i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 90 entries", entries_iter2);
    this->query_validate(entries_iter1, num_entries - 1, 90);

    // Do validate all of them
    LOGINFO("Step 5: Query all entries and validate with no pagination");
    this->query_all_validate();

    LOGINFO("Step 6: Query all entries and validate with pagination of 80 entries");
    this->query_all_paginate_validate(80);

    LOGINFO("Step 7: Get all entries 1-by-1 and validate them");
    this->get_all_validate();
    this->get_any_validate(num_entries - 3, num_entries + 1);

    // Negative cases
    LOGINFO("Step 8: Do incorrect input and validate errors");
    this->query_validate(num_entries + 100, num_entries + 500, 5);
    this->get_any_validate(num_entries + 1, num_entries + 2);
}

TYPED_TEST(BtreeTest, SequentialRemove) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->query_validate(0, num_entries, 75);

    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 3: Do Forward sequential remove for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->remove_one(i);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->query_validate(0, entries_iter1, 75);

    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 5: Do Reverse sequential remove of remaining {} entries", entries_iter2);
    for (uint32_t i{num_entries - 1}; i >= entries_iter1; --i) {
        this->remove_one(i);
    }

    LOGINFO("Step 6: Query the empty tree");
    this->query_validate(0, num_entries, 75);
    this->get_any_validate(0, 1);
    this->get_specific_validate(0);
}

TYPED_TEST(BtreeTest, RangeUpdate) {
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }

    LOGINFO("Step 2: Do Range Update of random intervals between [1-50] for 100 times with random key ranges");
    static std::uniform_int_distribution< uint32_t > s_rand_key_count_generator{1, 50};
    for (uint32_t i{0}; i < 100; ++i) {
        this->range_put(s_rand_key_count_generator(g_re));
    }

    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->query_validate(0, num_entries, 75);
}

TYPED_TEST(BtreeTest, SimpleRemoveRange) {
    // Forward sequential insert
    const auto num_entries = 20;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }

    //    this->print_keys(); // EXPECT size = 20 : 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
    this->range_remove(5, 10);
    //    this->print_keys(); // EXPECT size = 14 : 0 1 2 3 4 [5 6 7 8 9 10] 11 12 13 14 15 16 17 18 19
    this->range_remove(0, 2);
    //    this->print_keys(); // EXPECT size = 11 : [0 1 2] 3 4 11 12 13 14 15 16 17 18 19
    this->range_remove(18, 19);
    //    this->print_keys(); // EXPECT size = 9 : 3 4 11 12 13 14 15 16 17 [18 19]
    this->range_remove(17, 17);
    //    this->print_keys(); // EXPECT size = 8 : 3 4 11 12 13 14 15 16 [17]
    this->range_remove(1, 5);
    //    this->print_keys(); // EXPECT size = 6 : [3 4] 11 12 13 14 15 16
    this->range_remove(1, 20);
    //    this->print_keys(); // EXPECT size = 0 : [11 12 13 14 15 16]

    this->query_all_validate();
    //    this->query_validate(0, num_entries , 75);
}

TYPED_TEST(BtreeTest, removeAllEntriesReverse) {
    // Forward sequential insert
    const auto num_entries = 1000;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    //    this->print_keys();
    this->range_remove(681, 999);
    //    this->print_keys();
    this->range_remove(454, 680);
    //    this->print_keys();
    this->range_remove(227, 453);
    //    this->print_keys();
    this->range_remove(0, 226);
    //    this->print_keys();
    this->query_all_validate();
}

TYPED_TEST(BtreeTest, removeAllEntries) {
    // Forward sequential insert
    const auto num_entries = 1000;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    //    this->print_keys();
    this->range_remove(0, 226);
    //    this->print_keys();
    this->range_remove(227, 453);
    //    this->print_keys();
    this->range_remove(454, 680);
    //    this->print_keys();
    this->range_remove(681, 999);
    //    this->print_keys();
    this->query_all_validate();
}

TYPED_TEST(BtreeTest, RandomRemoveRange) {

    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }

    static std::uniform_int_distribution< uint32_t > s_rand_key_generator{0, 2 * num_entries};
    //    this->print_keys();
    for (uint32_t i{0}; i < SISL_OPTIONS["num_iters"].as< uint32_t >() && this->m_shadow_map.size() > 0; ++i) {
        uint32_t key1 = s_rand_key_generator(g_re);
        uint32_t key2 = s_rand_key_generator(g_re);
        uint32_t start_key = std::min(key1, key2);
        uint32_t end_key = std::max(key1, key2);

        LOGINFO("Step 2 - {}: Do Range Remove of maximum [{},{}] keys ", i, start_key, end_key);
        this->range_remove(std::min(key1, key2), std::max(key1, key2));
        //        this->print_keys();
    }

    this->query_all_validate();
}

template < typename TestType >
class BtreeConcurrentTest : public testing::Test {
    typedef void (BtreeConcurrentTest::*pt2func)(void);
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    std::unique_ptr< typename T::BtreeType > m_bt;
    struct ShadowMap {
    public:
        bool put(uint32_t key, std::string value, bool replace = false) {
            auto it = data.find(key);
            if ((it == data.end() && replace) || (it != data.end() && !replace)) { return false; }
            data[key] = value;
            return true;
        }
        bool range_put(uint32_t key, uint32_t nkeys, std::string value, bool replace = false) {
            if (replace) {
                if (!all_existed(key, nkeys)) { return false; }
            } else {
                if (!non_of_them_existed(key, nkeys)) { return false; }
            }
            for (auto cur = key; cur < key + nkeys; cur++)
                data[cur] = value;
            return true;
        }

        bool remove(uint32_t key) {
            if (non_of_them_existed(key, 1)) return false;
            auto it = data.find(key);
            if (it == data.end()) return false;
            data.erase(it);
            return true;
        }
        bool remove(uint32_t key, std::string value) {
            if (non_of_them_existed(key, 1)) return false;
            auto it = data.find(key);
            if (it == data.end()) return false;
            if (it->second != value) return false;
            data.erase(it);
            return true;
        }

        bool range_remove(uint32_t key, uint32_t nkeys) {
            if (non_of_them_existed(key, nkeys)) return false;
            auto first_it = data.find(key);
            auto last_it = data.upper_bound(key + nkeys - 1);
            data.erase(first_it, last_it);
            return true;
        }
        bool range_remove(uint32_t key, uint32_t nkeys, std::unordered_map< uint32_t, std::string > val_map) {
            if (non_of_them_existed(key, nkeys)) return false;
            for (auto cur = key; cur < key + nkeys; cur++)
                if (data.find(cur) != data.end() && val_map[cur] != data[cur]) return false;
            auto first_it = data.find(key);
            auto last_it = data.upper_bound(key + nkeys - 1);
            data.erase(first_it, last_it);
            return true;
        }

        bool non_of_them_existed(uint32_t key, uint32_t nkeys) {
            for (auto cur = key; cur < key + nkeys; cur++)
                if (data.find(cur) != data.end()) return false;
            return true;
        }

        bool all_existed(uint32_t key, uint32_t nkeys) {
            for (auto cur = key; cur < key + nkeys; cur++)
                if (data.find(cur) == data.end()) return false;
            return true;
        }

    private:
        std::map< uint32_t, std::string > data;
    };
    ShadowMap m_shadow_map;
    RangeScheduler m_range_scheduler;
    std::vector< std::thread > m_threads;
    uint32_t m_max_range_input = 10000;
    BtreeConfig m_cfg{g_node_size};
    std::map< std::string, pt2func > m_operations;
    std::vector< std::string > m_op_list;
    bool m_mock = false;

    //    tree_ tree;
    void preload(uint32_t start, uint32_t end) {
        for (uint32_t i = start; i <= end; i++) {
            auto value = V::generate_rand();
            if (!m_mock) { put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS, value); }
            m_range_scheduler.add_to_existing(i);
        }
        LOGINFO(" PRELOAD DONE FOR [{},{}]", start, end);
    }
    void RunInParallel(size_t n_threads = 10) {
        for (size_t i = 0; i < n_threads; ++i)
            m_threads.push_back(std::thread(&BtreeConcurrentTest::doSomething, this));
        for (auto& th : m_threads) {
            th.join();
        }
    }
    void set_operations(std::vector< std::string > op_list) { this->m_op_list = op_list; }

    void doSomething() {
        std::random_device g_rd{};
        std::default_random_engine g_re{g_rd()};
        const auto num_iters_per_thread = SISL_OPTIONS["num_iters"].as< uint32_t >();
        std::uniform_int_distribution< uint32_t > s_rand_op_generator{0, static_cast< uint32_t >(m_op_list.size() - 1)};
        for (uint32_t i = 0; i < num_iters_per_thread; i++) {
            uint32_t operation = s_rand_op_generator(g_re);
            run_one_iteration(m_op_list[operation]);
        }
    }
    void SetUp() override {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_bt = std::make_unique< typename T::BtreeType >(m_cfg);
        m_bt->init(nullptr);
        m_operations["put"] = &BtreeConcurrentTest::random_put;
        m_operations["remove"] = &BtreeConcurrentTest::random_remove;
        m_operations["range_put"] = &BtreeConcurrentTest::random_range_put;
        m_operations["range_update"] = &BtreeConcurrentTest::random_range_update;
        m_operations["range_remove"] = &BtreeConcurrentTest::random_range_remove;
    }
    void run_one_iteration(std::string operation_name) {
        auto op = m_operations[operation_name];
        (*this.*op)();
    }
    void random_range_put() { random_range_put_update(false); }
    void random_range_update() { random_range_put_update(true); }
    void put(uint32_t k, btree_put_type put_type, V value) {
        std::unique_ptr< V > existing_v = std::make_unique< V >();

        auto sreq = BtreeSinglePutRequest{std::make_unique< K >(k), std::make_unique< V >(value), put_type,
                                          std::move(existing_v)};
        bool done = (m_bt->put(sreq) == btree_status_t::success);
        auto expected_done = m_shadow_map.put(k, value.to_string());
        ASSERT_EQ(done, expected_done) << "Expected put of key " << k << " of put_type " << enum_name(put_type)
                                       << " to be " << expected_done;
    }
    void range_put(uint32_t start_key, uint32_t end_key, V value, bool replace) {
        auto mreq = BtreeRangePutRequest< K >{BtreeKeyRange< K >{start_key, true, end_key, true},
                                              replace ? btree_put_type::REPLACE_ONLY_IF_EXISTS
                                                      : btree_put_type::INSERT_ONLY_IF_NOT_EXISTS,
                                              std::make_unique< V >(value)};
        bool done = (m_bt->put(mreq) == btree_status_t::success);
        auto expected_done = m_shadow_map.range_put(start_key, end_key - start_key + 1, value.to_string(), replace);
        ASSERT_EQ(done, expected_done);
        //        << "Expected put of key " << k << " of put_type " << enum_name(put_type)
        //                                       << " to be " << expected_done;
    }
    void remove(uint32_t key) {
        std::unique_ptr< V > existing_v = std::make_unique< V >();
        auto rreq = BtreeSingleRemoveRequest{std::make_unique< K >(key), std::move(existing_v)};
        bool removed = (m_bt->remove(rreq) == btree_status_t::success);
        auto expected_removed = m_shadow_map.remove(key, ((const V&)rreq.value()).to_string());
        ASSERT_EQ(removed, expected_removed) << "Expected remove of key " << key << " to be " << expected_removed;
    }
    void range_remove(uint32_t start_key, uint32_t end_key) {
        auto range = BtreeKeyRange< K >{K{start_key}, true, K{end_key}, true};
        auto out_vector = query(start_key, end_key);
        auto mreq = BtreeRangeRemoveRequest< K >{std::move(range)};
        bool removed = (m_bt->remove(mreq) == btree_status_t::success);
        bool expected_removed = m_shadow_map.range_remove(start_key, end_key - start_key + 1, out_vector);
        ASSERT_EQ(removed, expected_removed) << "not a successful remove op for range " << range.to_string();
    }

    void random_put() {
        int key = m_range_scheduler.pick_random_non_existing_keys(1, m_max_range_input);
        if (key == -1) { return; }
        LOGINFO("Adding the new key {}", key);
        auto value = V::generate_rand();
        if (!m_mock) { put(key, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS, value); }
        m_range_scheduler.lock();
        m_range_scheduler.add_to_existing(static_cast< uint32_t >(key));
        m_range_scheduler.remove_from_working(static_cast< uint32_t >(key));
        m_range_scheduler.unlock();
    }

    void random_range_put_update(bool replace = false) {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 5};

        std::random_device g_re{};
        uint32_t nkeys = s_rand_range_generator(g_re);
        int key = -1;

        if (replace) {
            key = m_range_scheduler.pick_random_existing_keys(nkeys, m_max_range_input);
        } else {
            key = m_range_scheduler.pick_random_non_existing_keys(nkeys, m_max_range_input);
        }

        if (key == -1) { return; }
        LOGINFO("{} range keys [{},{}]", replace ? "RANGE_UPDATE existing" : "RANGE_PUT non-existing", key,
                key + nkeys - 1);
        auto value = V::generate_rand();
        if (!m_mock) { range_put(key, key + nkeys - 1, value, replace); }
        m_range_scheduler.lock();
        if (!replace)
            m_range_scheduler.add_to_existing(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        m_range_scheduler.remove_from_working(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        m_range_scheduler.unlock();
    }

    void random_remove() {
        int key = m_range_scheduler.pick_random_existing_keys(1, m_max_range_input);
        if (key == -1) { return; }
        LOGINFO("Removing the key {}", key);
        if (!m_mock) { remove(key); }
        m_range_scheduler.lock();
        m_range_scheduler.remove_from_existing(static_cast< uint32_t >(key));
        m_range_scheduler.remove_from_working(static_cast< uint32_t >(key));
        m_range_scheduler.unlock();
    }

    void random_range_remove() {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 5};
        std::random_device g_re{};
        uint32_t nkeys = s_rand_range_generator(g_re);
        int key = m_range_scheduler.pick_random_existing_keys(nkeys, m_max_range_input);
        if (key == -1) { return; }
        LOGINFO("RANGE_REMOVE range keys [{},{}]", key, key + nkeys - 1);
        if (!m_mock) { range_remove(key, key + nkeys - 1); }

        m_range_scheduler.lock();
        m_range_scheduler.remove_from_existing(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        m_range_scheduler.remove_from_working(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        m_range_scheduler.unlock();
    }
    std::unordered_map< uint32_t, std::string > query(uint32_t start_k, uint32_t end_k) const {
        std::vector< std::pair< K, V > > out_vector;
        BtreeQueryRequest< K > qreq{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true},
                                    BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY, UINT32_MAX};
        auto const ret = m_bt->query(qreq, out_vector);
        std::unordered_map< uint32_t, std::string > result;
        for (auto const& pair : out_vector) {
            result[pair.first.key()] = pair.second.to_string();
        }
        //        std::vector< uint32_t , std::string > values;
        //        std::transform(out_vector.begin(), out_vector.end(),
        //                       std::back_inserter(values),
        //                       [](auto const& pair){ return pair.second.to_string(); });
        return result;
    }

public:
    void execute(std::vector< std::string > op_list, bool mock = false) {
        const auto preload_size = SISL_OPTIONS["preload_size"].as< uint32_t >();
        const auto n_threads = SISL_OPTIONS["n_threads"].as< uint32_t >();
        set_operations(op_list);
        this->m_mock = mock;
        preload(0, preload_size);
        RunInParallel(n_threads);
    }
};

TYPED_TEST_SUITE(BtreeConcurrentTest, BtreeTypes);

TYPED_TEST(BtreeConcurrentTest, PutNoTree) {
    std::vector< std::string > ops = {"put"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, RemoveNoTree) {
    std::vector< std::string > ops = {"remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, PutRemoveNoTree) {
    std::vector< std::string > ops = {"put", "remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, RangeNoTree) {
    std::vector< std::string > ops = {"range_put", "range_update", "range_remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, AllNoTree) {
    std::vector< std::string > ops = {"put", "remove", "range_put", "range_update", "range_remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, PutTree) {
    std::vector< std::string > ops = {"put"};
    this->execute(ops, false);
}

TYPED_TEST(BtreeConcurrentTest, RemoveTree) {
    std::vector< std::string > ops = {"remove"};
    this->execute(ops, false);
}

TYPED_TEST(BtreeConcurrentTest, PutRemoveTree) {
    std::vector< std::string > ops = {"put", "remove"};
    this->execute(ops, false);
}

TYPED_TEST(BtreeConcurrentTest, RangeUpdateRemoveTree) {
    // range put is not supported for non-extent keys
    std::vector< std::string > ops = {"range_update", "range_remove"};
    this->execute(ops, false);
}
TYPED_TEST(BtreeConcurrentTest, AllTree) {
    // range put is not supported for non-extent keys
    std::vector< std::string > ops = {"put", "remove", "range_update", "range_remove"};
    this->execute(ops, false);
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
