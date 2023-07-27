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
#include <iomgr/io_environment.hpp>
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

SISL_LOGGING_INIT(btree, IOMGR_LOG_MODS, flip)

SISL_OPTIONS_ENABLE(logging, test_mem_btree)
SISL_OPTION_GROUP(test_mem_btree,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("1000"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                   ::cxxopts::value< uint32_t >()->default_value("65536"), "number"),
                  (n_threads, "", "n_threads", "number of threads", ::cxxopts::value< uint32_t >()->default_value("1"),
                   "number"),
                  (n_fibers, "", "n_fibers", "number of fibers", ::cxxopts::value< uint32_t >()->default_value("100"),
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
        auto existing_v = std::make_unique< V >();
        auto pk = std::make_unique< K >(k);
        auto pv = std::make_unique< V >(V::generate_rand());
        auto sreq{BtreeSinglePutRequest{pk.get(), pv.get(), put_type, existing_v.get()}};
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
                                              btree_put_type::REPLACE_ONLY_IF_EXISTS, val.get()};
        ASSERT_EQ(m_bt->put(mreq), btree_status_t::success);
    }

    void remove_one(uint32_t k) {
        auto existing_v = std::make_unique< V >();
        auto pk = std::make_unique< K >(k);

        auto rreq = BtreeSingleRemoveRequest{pk.get(), existing_v.get()};
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
            auto out_v = std::make_unique< V >();
            auto req = BtreeSingleGetRequest{copy_key.get(), out_v.get()};

            const auto ret = m_bt->get(req);
            ASSERT_EQ(ret, btree_status_t::success) << "Missing key " << key << " in btree but present in shadow map";
            ASSERT_EQ((const V&)req.value(), value)
                << "Found value in btree doesn't return correct data for key=" << key;
        }
    }

    void get_specific_validate(uint32_t k) const {
        auto pk = std::make_unique< K >(k);
        auto out_v = std::make_unique< V >();
        auto req = BtreeSingleGetRequest{pk.get(), out_v.get()};

        const auto status = m_bt->get(req);
        if (status == btree_status_t::success) {
            validate_data(req.key(), (const V&)req.value());
        } else {
            ASSERT_EQ((m_shadow_map.find(req.key()) == m_shadow_map.end()), true)
                << "Node key " << k << " is missing in the btree";
        }
    }

    void get_any_validate(uint32_t start_k, uint32_t end_k) const {
        auto out_k = std::make_unique< K >();
        auto out_v = std::make_unique< V >();
        auto req =
            BtreeGetAnyRequest< K >{BtreeKeyRange< K >{K{start_k}, true, K{end_k}, true}, out_k.get(), out_v.get()};
        const auto status = m_bt->get(req);
        if (status == btree_status_t::success) {
            ASSERT_EQ(found_in_range(*(K*)req.m_outkey, start_k, end_k), true)
                << "Get Any returned key=" << *(K*)req.m_outkey << " which is not in range " << start_k << "-" << end_k
                << "according to shadow map";
            validate_data(*(K*)req.m_outkey, *(V*)req.m_outval);
        } else {
            ASSERT_EQ(found_in_range(*(K*)req.m_outkey, start_k, end_k), false)
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
    using mutex = iomgr::FiberManagerLib::shared_mutex;

public:
    void SetUp() override {
        m_cfg.m_leaf_node_type = T::leaf_node_type;
        m_cfg.m_int_node_type = T::interior_node_type;
        m_max_range_input = SISL_OPTIONS["num_entries"].as< uint32_t >();
        m_bt = std::make_unique< typename T::BtreeType >(m_cfg);
        m_bt->init(nullptr);
        m_max_range_input = SISL_OPTIONS["num_entries"].as< uint32_t >();
        m_operations["put"] = &BtreeConcurrentTest::random_put;
        m_operations["remove"] = &BtreeConcurrentTest::random_remove;
        //        m_operations["range_put"] = &BtreeConcurrentTest::random_range_put;
        m_operations["range_update"] = &BtreeConcurrentTest::random_range_update;
        m_operations["range_remove"] = &BtreeConcurrentTest::random_range_remove;
        m_operations["query"] = &BtreeConcurrentTest::random_get;
    }

    void TearDown() override { iomanager.stop(); }

    void print() const { m_bt->print_tree(); }

    void execute(std::vector< std::string > op_list) {
        auto n_threads = SISL_OPTIONS["n_threads"].as< uint32_t >();
        auto nfibers = SISL_OPTIONS["n_fibers"].as< uint32_t >();
        const auto preload_size = SISL_OPTIONS["preload_size"].as< uint32_t >();
        set_operations(op_list);

        LOGINFO("Starting iomgr with {} threads", n_threads);
        ioenvironment.with_iomgr(iomgr::iomgr_params{.num_threads = n_threads, false, .num_fibers = 1 + nfibers, 0, 0});
        std::mutex mtx;
        iomanager.run_on_wait(iomgr::reactor_regex::all_io, [this, &mtx]() {
            auto fv = iomanager.sync_io_capable_fibers();
            std::unique_lock lg(mtx);
            m_fibers.insert(m_fibers.end(), fv.begin(), fv.end());
        });
        m_test_count = m_fibers.size();
        iomanager.run_on_wait(m_fibers[0], [preload_size, this]() { preload(0, preload_size); });
        LOGINFO("PRELOAD DONE");
        RunInParallel();
    }

private:
    void set_operations(std::vector< std::string > op_list) { this->m_op_list = op_list; }

    void run_one_iteration(std::string operation_name) {
        auto op = m_operations[operation_name];
        (*this.*op)();
    }

    void doSomething() {
        std::random_device g_rd{};
        std::default_random_engine re{g_rd()};
        const auto num_iters_per_thread = SISL_OPTIONS["num_iters"].as< uint32_t >();
        std::uniform_int_distribution< uint32_t > s_rand_op_generator{0, static_cast< uint32_t >(m_op_list.size() - 1)};

        for (uint32_t i = 0; i < num_iters_per_thread; i++) {
            uint32_t operation = s_rand_op_generator(re);
            run_one_iteration(m_op_list[operation]);
        }
        {
            std::unique_lock lg(m_test_done_mtx);
            if (--m_test_count == 0) { m_test_done_cv.notify_one(); }
        }
    }

    void random_range_remove() {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{2, 5};
        std::random_device g_re{};
        uint32_t nkeys = s_rand_range_generator(g_re);
        int key = m_range_scheduler.pick_random_existing_keys(nkeys, m_max_range_input);
        if (key == -1) { return; }
        range_remove(key, key + nkeys - 1);
        m_range_scheduler.remove_keys(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
    }

    void range_remove(uint32_t start_key, uint32_t end_key) {
        auto range = BtreeKeyRange< K >{K{start_key}, true, K{end_key}, true};
        auto out_vector = query(start_key, end_key);
        auto rreq = BtreeRangeRemoveRequest< K >{std::move(range)};
        bool removed = (m_bt->remove(rreq) == btree_status_t::success);
        bool expected_removed = m_shadow_map.range_remove(start_key, end_key - start_key + 1, out_vector);
        ASSERT_EQ(removed, expected_removed) << "not a successful remove op for range " << range.to_string();
    }

    void random_query(uint32_t start_key, uint32_t end_key) {
        auto range = BtreeKeyRange< K >{K{start_key}, true, K{end_key}, true};
        auto out_map = query(start_key, end_key);
        bool expected = m_shadow_map.range_get(start_key, end_key - start_key + 1, out_map);
        ASSERT_TRUE(expected) << "not a successful query op for range " << range.to_string();
    }

    std::unordered_map< uint32_t, std::string > query(uint32_t start_k, uint32_t end_k) const {
        std::unordered_map< uint32_t, std::string > result;
        for (auto cur = start_k; cur <= end_k; cur++) {
            auto key = std::make_unique< K >(cur);
            auto value = std::make_unique< V >();
            auto req = BtreeSingleGetRequest{key.get(), value.get()};
            const auto status = m_bt->get(req);
            if (status == btree_status_t::success) { result[cur] = ((const V&)req.value()).to_string(); }
        }
        return result;
    }

    void random_get() {
        static std::uniform_int_distribution< uint32_t > s_rand_range_generator{1, 100};
        std::random_device g_re{};
        uint32_t nkeys = s_rand_range_generator(g_re);
        int key = -1;
        key = m_range_scheduler.pick_random_non_working_keys(nkeys, m_max_range_input);
        if (key == -1) { return; }
        random_query(key, key + nkeys - 1);
        m_range_scheduler.remove_keys_from_working(static_cast< uint32_t >(key),
                                                   static_cast< uint32_t >(key + nkeys - 1));
    }

    void random_put() {
        int key = m_range_scheduler.pick_random_non_existing_keys(1, m_max_range_input);
        if (key == -1) { return; }
        auto value = V::generate_rand();
        put(key, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS, value);
        m_range_scheduler.put_key(static_cast< uint32_t >(key));
    }

    void put(uint32_t key, btree_put_type put_type, V value) {
        auto existing_v = std::make_unique< V >();
        auto v = std::make_unique< V >(value);
        auto k = std::make_unique< K >(key);
        auto sreq{BtreeSinglePutRequest{k.get(), v.get(), put_type, existing_v.get()}};
        bool done = (m_bt->put(sreq) == btree_status_t::success);
        auto expected_done = m_shadow_map.put(key, value.to_string());
        ASSERT_EQ(done, expected_done) << "Expected put of key " << key << " of put_type " << enum_name(put_type)
                                       << " to be " << expected_done;
    }

    void remove(uint32_t key) {
        auto existing_v = std::make_unique< V >();
        auto k = std::make_unique< K >(key);
        auto rreq = BtreeSingleRemoveRequest{k.get(), existing_v.get()};
        bool removed = (m_bt->remove(rreq) == btree_status_t::success);
        auto expected_done = m_shadow_map.remove(key, ((const V&)rreq.value()).to_string());
        ASSERT_EQ(removed, expected_done) << "Expected remove of key " << key << " to be " << expected_done;
    }

    void random_remove() {
        int key = m_range_scheduler.pick_random_existing_keys(1, m_max_range_input);
        if (key == -1) { return; }
        remove(key);
        m_range_scheduler.remove_key(static_cast< uint32_t >(key));
    }

    void random_range_put() { random_range_put_update(false); }

    void random_range_update() { random_range_put_update(true); }

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
        auto value = V::generate_rand();
        range_put(key, key + nkeys - 1, value, replace);
        if (replace) {
            m_range_scheduler.remove_keys_from_working(static_cast< uint32_t >(key),
                                                       static_cast< uint32_t >(key + nkeys - 1));
        } else {
            m_range_scheduler.put_keys(static_cast< uint32_t >(key), static_cast< uint32_t >(key + nkeys - 1));
        }
    }

    void range_put(uint32_t start_key, uint32_t end_key, V value, bool update) {
        auto val = std::make_unique< V >(value);
        auto preq = BtreeRangePutRequest< K >{
            BtreeKeyRange< K >{start_key, true, end_key, true},
            update ? btree_put_type::REPLACE_ONLY_IF_EXISTS : btree_put_type::INSERT_ONLY_IF_NOT_EXISTS, val.get()};
        bool done = (m_bt->put(preq) == btree_status_t::success);
        auto expected_done = m_shadow_map.range_put(start_key, end_key - start_key + 1, value.to_string(), update);
        ASSERT_EQ(done, expected_done);
    }

    void preload(uint32_t start, uint32_t end) {
        for (uint32_t i = start; i <= end; i++) {
            auto value = V::generate_rand();
            put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS, value);
            m_range_scheduler.put_key(i);
        }
    }

    void RunInParallel() {
        for (auto it = m_fibers.begin(); it < m_fibers.end(); ++it) {
            iomanager.run_on_forget(*it, [this]() { doSomething(); });
        }

        {
            std::unique_lock< std::mutex > lk(m_test_done_mtx);
            m_test_done_cv.wait(lk, [&]() { return m_test_count == 0; });
        }
        LOGINFO("ALL parallel jobs joined");
    }

private:
    std::unique_ptr< typename T::BtreeType > m_bt;
    bool m_fire = false;
    struct ShadowMap {
    public:
        bool put(uint32_t key, std::string value, bool update = false) {
            std::unique_lock< mutex > lk(map_lock);
            auto it = data.find(key);
            if ((it == data.end() && update) || (it != data.end() && !update)) { return false; }
            data[key] = value;
            return true;
        }

        bool range_put(uint32_t key, uint32_t nkeys, std::string value, bool update = false) {
            std::unique_lock< mutex > lk(map_lock);
            if (update) {
                if (!all_existed(key, nkeys)) { return false; }
            } else {
                if (!non_of_them_existed(key, nkeys)) { return false; }
            }
            for (auto cur = key; cur < key + nkeys; cur++) {
                data[cur] = value;
            }
            return true;
        }

        bool remove(uint32_t key) {
            std::unique_lock< mutex > lk(map_lock);
            if (non_of_them_existed(key, 1)) { return false; }
            auto it = data.find(key);
            if (it == data.end()) { return false; }
            data.erase(it);
            return true;
        }

        bool remove(uint32_t key, std::string value) {
            std::unique_lock< mutex > lk(map_lock);
            if (non_of_them_existed(key, 1)) { return false; }
            auto it = data.find(key);
            if (it == data.end()) { return false; }
            if (it->second != value) { return false; }
            data.erase(it);
            return true;
        }

        bool range_remove(uint32_t key, uint32_t nkeys) {
            std::unique_lock< mutex > lk(map_lock);
            if (non_of_them_existed(key, nkeys)) { return false; }
            auto first_it = data.find(key);
            auto last_it = data.upper_bound(key + nkeys - 1);
            data.erase(first_it, last_it);
            return true;
        }

        bool range_get(uint32_t key, uint32_t nkeys, std::unordered_map< uint32_t, std::string > val_map) {
            std::unique_lock< mutex > lk(map_lock);
            if (non_of_them_existed(key, nkeys) && val_map.size()) { return false; }
            if (non_of_them_existed(key, nkeys) && val_map.size() == 0) { return true; }
            uint32_t count = 0;
            for (auto cur = key; cur < key + nkeys; cur++) {
                if (data.find(cur) != data.end()) {
                    if (val_map[cur] != data[cur]) { return false; }
                    if (val_map[cur] == data[cur]) { count++; }
                }
            }
            if (count != val_map.size()) { return false; }
            return true;
        }
        bool range_remove(uint32_t key, uint32_t nkeys, std::unordered_map< uint32_t, std::string > val_map) {
            std::unique_lock< mutex > lk(map_lock);
            if (non_of_them_existed(key, nkeys)) { return false; }
            for (auto cur = key; cur < key + nkeys; cur++)
                if (data.find(cur) != data.end() && val_map[cur] != data[cur]) { return false; }
            auto first_it = data.find(key);
            auto last_it = data.upper_bound(key + nkeys - 1);
            data.erase(first_it, last_it);
            return true;
        }
        std::string to_string(uint32_t key, uint32_t nkeys) {
            std::unique_lock< mutex > lk(map_lock);
            std::string x = "";
            for (auto cur = key; cur < key + nkeys; cur++) {
                if (data.find(cur) != data.end()) x += fmt::format("[{}]={}\n", cur, data[cur]);
            }
            return x;
        }

    private:
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

        std::map< uint32_t, std::string > data;
        mutex map_lock;
    };
    ShadowMap m_shadow_map;
    RangeScheduler m_range_scheduler;
    uint32_t m_max_range_input = 1000;
    BtreeConfig m_cfg{g_node_size};
    std::map< std::string, pt2func > m_operations;
    std::vector< std::string > m_op_list;
    std::vector< iomgr::io_fiber_t > m_fibers;
    mutex m_cb_mtx;
    std::mutex m_test_done_mtx;
    std::condition_variable m_test_done_cv;
    uint32_t m_test_count{0};
};
TYPED_TEST_SUITE(BtreeConcurrentTest, BtreeTypes);

TYPED_TEST(BtreeConcurrentTest, AllTree) {
    // range put is not supported for non-extent keys
    std::vector< std::string > ops = {"put", "remove", "range_update", "range_remove", "query"};
    this->execute(ops);
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
