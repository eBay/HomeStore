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
#include "test_common/range_scheduler.hpp"

static constexpr uint32_t g_node_size{4096};
using namespace homestore;
SISL_LOGGING_INIT(btree)

SISL_OPTIONS_ENABLE(logging, test_mem_btree)
SISL_OPTION_GROUP(test_mem_btree,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                   ::cxxopts::value< uint32_t >()->default_value("10000"), "number"),
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

template < typename TestType >
class BtreeConcurrentTest : public testing::Test {
    typedef void (BtreeConcurrentTest::*pt2func)(void);
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    std::unique_ptr< typename T::BtreeType > m_bt;
    RangeScheduler range_scheduler;
    std::vector< std::thread > threads;
    uint32_t max_range_input = 10000;
    BtreeConfig m_cfg{g_node_size};
    std::map< std::string, pt2func > operations;
    std::vector< std::string > op_list;
    bool mock = false;

    //    tree_ tree;
    void preload(uint32_t start, uint32_t end) {
        for (uint32_t i = start; i <= end; i++) {
            if (!mock) { put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS); }
            range_scheduler.add_to_existing(i);
        }
        LOGINFO(" PRELOAD DONE FOR [{},{}]", start, end);
    }
    void RunInParallel(size_t n_threads = 10) {
        for (size_t i = 0; i < n_threads; ++i)
            threads.push_back(std::thread(&BtreeConcurrentTest::doSomething, this));
        for (auto& th : threads) {
            th.join();
        }
    }
    void set_operations(std::vector< std::string > op_list) { this->op_list = op_list; }

    void doSomething() {
        std::random_device g_rd{};
        std::default_random_engine g_re{g_rd()};
        const auto num_iters_per_thread = SISL_OPTIONS["num_iters"].as< uint32_t >();
        std::uniform_int_distribution< uint32_t > s_rand_op_generator{0, static_cast< uint32_t >(op_list.size() - 1)};
        for (uint32_t i = 0; i < num_iters_per_thread; i++) {
            uint32_t operation = s_rand_op_generator(g_re);
            run_one_iteration(op_list[operation]);
        }
    }
    void SetUp() override {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_bt = std::make_unique< typename T::BtreeType >(m_cfg);
        m_bt->init(nullptr);
        operations["put"] = &BtreeConcurrentTest::random_put;
        operations["remove"] = &BtreeConcurrentTest::random_remove;
        operations["range_put"] = &BtreeConcurrentTest::random_range_put;
        operations["range_update"] = &BtreeConcurrentTest::random_range_update;
        operations["range_remove"] = &BtreeConcurrentTest::random_range_remove;
    }
    void run_one_iteration(std::string operation_name) {
        auto op = operations[operation_name];
        (*this.*op)();
    }
    void random_range_put() { random_range_put_update(false); }
    void random_range_update() { random_range_put_update(true); }
    void put(uint32_t k, btree_put_type put_type) {
        std::unique_ptr< V > existing_v = std::make_unique< V >();

        auto sreq = BtreeSinglePutRequest{std::make_unique< K >(k), std::make_unique< V >(V::generate_rand()), put_type,
                                          std::move(existing_v)};
        bool done = (m_bt->put(sreq) == btree_status_t::success);
        bool expected_done{true};
        //        if (m_shadow_map.find(*sreq.m_k) != m_shadow_map.end()) {
        //            expected_done = (put_type != btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        //        }
        ASSERT_EQ(done, expected_done) << "Expected put of key " << k << " of put_type " << enum_name(put_type)
                                       << " to be " << expected_done;
    }
    void range_put(uint32_t start_key, uint32_t end_key, bool replace) {
        auto val = std::make_unique< V >(V::generate_rand());
        auto mreq = BtreeRangePutRequest< K >{BtreeKeyRange< K >{start_key, true, end_key, true},
                                              replace ? btree_put_type::REPLACE_ONLY_IF_EXISTS
                                                      : btree_put_type::INSERT_ONLY_IF_NOT_EXISTS,
                                              std::move(val)};
        ASSERT_EQ(m_bt->put(mreq), btree_status_t::success);
    }
    void remove(uint32_t key) {
        std::unique_ptr< V > existing_v = std::make_unique< V >();
        auto rreq = BtreeSingleRemoveRequest{std::make_unique< K >(key), std::move(existing_v)};
        bool removed = (m_bt->remove(rreq) == btree_status_t::success);

        bool expected_removed = true; //(m_shadow_map.find(rreq.key()) != m_shadow_map.end());
        ASSERT_EQ(removed, expected_removed) << "Expected remove of key " << key << " to be " << expected_removed;

        //        if (removed) {
        //            validate_data(rreq.key(), (const V&)rreq.value());
        //            m_shadow_map.erase(rreq.key());
        //        }
    }
    void range_remove(uint32_t start_key, uint32_t end_key) {
#if 0
        auto range = BtreeKeyRange< K >{K{start_key}, true, K{end_key}, true};
        auto mreq = BtreeRangeRemoveRequest< K >{std::move(range)};
        auto ret = m_bt->remove(mreq);
        ASSERT_EQ(ret, btree_status_t::success)
            << " not a successful remove op for range " << range.to_string();
#endif
    }

    void random_put() {
        int key = range_scheduler.pick_random_non_existing_keys(1, max_range_input);
        if (key == -1) { return; }
        LOGINFO("Adding the new key {}", key);
        if (!mock) { put(key, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS); }
        range_scheduler.lock();
        range_scheduler.add_to_existing(static_cast< uint32_t >(key));
        range_scheduler.remove_from_working(static_cast< uint32_t >(key));
        range_scheduler.unlock();
    }

    void random_range_put_update(bool replace = false) {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 5};

        std::random_device g_re{};
        uint32_t nkeys = s_rand_range_generator(g_re);
        int key = -1;
        if (replace) {
            key = range_scheduler.pick_random_existing_keys(nkeys, max_range_input);
        } else {
            key = range_scheduler.pick_random_non_existing_keys(nkeys, max_range_input);
        }

        if (key == -1) { return; }
        LOGINFO("{} range keys [{},{}]", replace ? "RANGE_UPDATE existing" : "RANGE_PUT non-existing", key,
                key + nkeys - 1);
        if (!mock) { range_put(key, key + nkeys - 1, replace); }
        range_scheduler.lock();
        if (!replace)
            range_scheduler.add_to_existing(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        range_scheduler.remove_from_working(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        range_scheduler.unlock();
    }

    void random_remove() {
        int key = range_scheduler.pick_random_existing_keys(1, max_range_input);
        if (key == -1) { return; }
        LOGINFO("Removing the key {}", key);
        if (!mock) { remove(key); }
        range_scheduler.lock();
        range_scheduler.remove_from_existing(static_cast< uint32_t >(key));
        range_scheduler.remove_from_working(static_cast< uint32_t >(key));
        range_scheduler.unlock();
    }

    void random_range_remove() {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 5};
        std::random_device g_re{};
        uint32_t nkeys = s_rand_range_generator(g_re);
        int key = range_scheduler.pick_random_existing_keys(nkeys, max_range_input);
        if (key == -1) { return; }
        LOGINFO("RANGE_REMOVE range keys [{},{}]", key, key + nkeys - 1);
        if (!mock) { range_remove(key, key + nkeys - 1); }

        range_scheduler.lock();
        range_scheduler.remove_from_existing(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        range_scheduler.remove_from_working(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        range_scheduler.unlock();
    }

public:
    void execute(std::vector< std::string > op_list, bool mock = false) {
        const auto preload_size = SISL_OPTIONS["preload_size"].as< uint32_t >();
        const auto n_threads = SISL_OPTIONS["n_threads"].as< uint32_t >();
        set_operations(op_list);
        this->mock = mock;
        preload(0, preload_size);
        RunInParallel(n_threads);
    }
};

TYPED_TEST_SUITE(BtreeConcurrentTest, BtreeTypes);

TYPED_TEST(BtreeConcurrentTest, put_no_tree) {
    std::vector< std::string > ops = {"put"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, remove_no_tree) {
    std::vector< std::string > ops = {"remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, put_remove_no_tree) {
    std::vector< std::string > ops = {"put", "remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, range_no_tree) {
    std::vector< std::string > ops = {"range_put", "range_update", "range_remove"};
    this->execute(ops, true);
}

TYPED_TEST(BtreeConcurrentTest, all_noTree) {
    std::vector< std::string > ops = {"put", "remove", "range_put", "range_update", "range_remove"};
    this->execute(ops, true);
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
