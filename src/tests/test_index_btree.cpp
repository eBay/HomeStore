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
#include "btree_test_kvs.hpp"
#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/homestore.hpp>
#include <homestore/index/index_table.hpp>
#include "common/homestore_config.hpp"
#include "common/resource_mgr.hpp"
#include "test_common/homestore_test_common.hpp"

using namespace homestore;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_index_btree, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_index_btree)

std::vector< std::string > test_common::HSTestHelper::s_dev_names;
// TODO increase num_entries to 65k as io mgr page size is 512 and its slow.
blk_allocator_type_t test_common::HSTestHelper::s_ds_alloc_type;
chunk_selector_type_t test_common::HSTestHelper::s_ds_chunk_sel_type;

SISL_OPTION_GROUP(test_index_btree,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("65536"), "number"),
                  (num_entries, "", "num_entries", "number of entries to test with",
                   ::cxxopts::value< uint32_t >()->default_value("15000"), "number"),
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

template < typename TestType >
struct BtreeTest : public testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    class TestIndexServiceCallbacks : public IndexServiceCallbacks {
    public:
        TestIndexServiceCallbacks(BtreeTest* test, BtreeConfig cfg) : m_test(test), m_bt_cfg(cfg) {}
        std::shared_ptr< IndexTableBase > on_index_table_found(const superblk< index_table_sb >& sb) override {
            LOGINFO("Index table recovered");
            LOGINFO("Root bnode_id {} version {}", sb->root_node, sb->link_version);
            m_test->m_bt = std::make_shared< typename T::BtreeType >(sb, this->m_bt_cfg);
            return m_test->m_bt;
        }

    private:
        BtreeTest* m_test;
        BtreeConfig m_bt_cfg;
    };

    std::shared_ptr< typename T::BtreeType > m_bt;
    std::map< K, V > m_shadow_map;
    std::unique_ptr< BtreeConfig > m_bt_cfg;

    void SetUp() override {
        test_common::HSTestHelper::start_homestore("test_index_btree", 10 /* meta */, 0 /* data log */, 0 /* ctrl log*/,
                                                   0 /* data */, 70 /* index */, nullptr, false /* restart */);

        LOGINFO("Node size {} ", hs()->index_service().node_size());
        m_bt_cfg = std::make_unique< BtreeConfig >(hs()->index_service().node_size());
        m_bt_cfg->m_leaf_node_type = T::leaf_node_type;
        m_bt_cfg->m_int_node_type = T::interior_node_type;
        // TODO fix. SequentialRemove failing in case of VarObj test.
        m_bt_cfg->m_merge_turned_on = false;

        auto uuid = boost::uuids::random_generator()();
        auto parent_uuid = boost::uuids::random_generator()();

        // Test cp flush of write back.
        HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
            s.generic.cache_max_throttle_cnt = 10000;
            HS_SETTINGS_FACTORY().save();
        });
        homestore::hs()->resource_mgr().reset_dirty_buf_qd();

        // Create index table and attach to index service.
        m_bt = std::make_shared< typename T::BtreeType >(uuid, parent_uuid, 0, *m_bt_cfg);
        hs()->index_service().add_index_table(m_bt);
        LOGINFO("Added index table to index service");
    }

    void TearDown() override {
        this->destroy_btree();
        test_common::HSTestHelper::shutdown_homestore();
    }

    void put(uint32_t k, btree_put_type put_type) {
        auto existing_v = std::make_unique< V >();
        auto pk = std::make_unique< K >(k);
        auto pv = std::make_unique< V >(V::generate_rand());
        auto sreq{BtreeSinglePutRequest{pk.get(), pv.get(), put_type, existing_v.get()}};
        sreq.enable_route_tracing();
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
        mreq.enable_route_tracing();
        ASSERT_EQ(m_bt->put(mreq), btree_status_t::success);
    }

    void remove_one(uint32_t k) {
        auto existing_v = std::make_unique< V >();
        auto pk = std::make_unique< K >(k);

        auto rreq = BtreeSingleRemoveRequest{pk.get(), existing_v.get()};
        rreq.enable_route_tracing();
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
        qreq.enable_route_tracing();

        do {
            out_vector.clear();
            auto const ret = m_bt->query(qreq, out_vector);
            auto const expected_count = std::min(remaining, batch_size);

            remaining -= expected_count;
            if (remaining == 0) {
                ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
            } else {
                ASSERT_EQ(ret, btree_status_t::has_more) << "Expected query to return has_more";
            }
            ASSERT_EQ(out_vector.size(), expected_count) << "Received incorrect value on query pagination";

            for (size_t idx{0}; idx < out_vector.size(); ++idx) {
                ASSERT_EQ(out_vector[idx].second, it->second)
                    << "Range get doesn't return correct data for key=" << it->first << " idx=" << idx;
                ++it;
            }
        } while (remaining > 0);
#if 0
        out_vector.clear();
        auto ret = m_bt->query(qreq, out_vector);
        ASSERT_EQ(ret, btree_status_t::success) << "Expected success on query";
        ASSERT_EQ(out_vector.size(), 0) << "Received incorrect value on empty query pagination";
#endif
    }

    void get_all_validate() const {
        for (const auto& [key, value] : m_shadow_map) {
            auto copy_key = std::make_unique< K >();
            *copy_key = key;
            auto out_v = std::make_unique< V >();
            auto req = BtreeSingleGetRequest{copy_key.get(), out_v.get()};
            req.enable_route_tracing();
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

    void print(const std::string& file = "") const { m_bt->print_tree(file); }

    void destroy_btree() {
        auto cpg = hs()->cp_mgr().cp_guard();
        auto op_context = (void*)cpg->context(cp_consumer_t::INDEX_SVC);
        const auto [ret, free_node_cnt] = m_bt->destroy_btree(op_context);
        ASSERT_EQ(ret, btree_status_t::success) << "btree destroy failed";
        m_bt.reset();
    }

    void compare_files(const std::string& before, const std::string& after) {
        std::ifstream b(before);
        std::ifstream a(after);
        std::ostringstream ss_before, ss_after;
        ss_before << b.rdbuf();
        ss_after << a.rdbuf();
        std::string s1 = ss_before.str();
        std::string s2 = ss_after.str();
        ASSERT_EQ(s1, s2) << "Mismatch in btree structure";
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

// TODO sanal fix the varkey issue.
// using BtreeTypes = testing::Types< FixedLenBtreeTest, VarKeySizeBtreeTest, VarValueSizeBtreeTest, VarObjSizeBtreeTest
// >;

using BtreeTypes = testing::Types< FixedLenBtreeTest >;

TYPED_TEST_SUITE(BtreeTest, BtreeTypes);

TYPED_TEST(BtreeTest, SequentialInsert) {
    LOGINFO("SequentialInsert test start");
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        // this->print();
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->query_validate(0, entries_iter1 - 1, 75);

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
    this->print();

    LOGINFO("SequentialInsert test end");
}

// TODO fix var key lenght has some issue.
#if 0
TYPED_TEST(BtreeTest, SequentialRemove) {
    LOGINFO("SequentialRemove test start");
    // Forward sequential insert
    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Step 1: Do Forward sequential insert for {} entries", num_entries);
    for (uint32_t i{0}; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    LOGINFO("Step 2: Query {} entries and validate with pagination of 75 entries", num_entries);
    this->query_validate(0, num_entries - 1, 75);

    const auto entries_iter1 = num_entries / 2;
    LOGINFO("Step 3: Do Forward sequential remove for {} entries", entries_iter1);
    for (uint32_t i{0}; i < entries_iter1; ++i) {
        this->remove_one(i);
    }
    LOGINFO("Step 4: Query {} entries and validate with pagination of 75 entries", entries_iter1);
    this->query_validate(0, entries_iter1 - 1, 75);
    this->query_validate(entries_iter1, num_entries - 1, 75);

    const auto entries_iter2 = num_entries - entries_iter1;
    LOGINFO("Step 5: Do Reverse sequential remove of remaining {} entries", entries_iter2);
    for (uint32_t i{num_entries - 1}; i >= entries_iter1; --i) {
        this->remove_one(i);
    }

    LOGINFO("Step 6: Query the empty tree");
    this->query_validate(0, num_entries - 1, 75);
    this->get_any_validate(0, 1);
    this->get_specific_validate(0);
    LOGINFO("SequentialRemove test end");
}
#endif

TYPED_TEST(BtreeTest, RangeUpdate) {
    LOGINFO("RangeUpdate test start");
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
    this->query_validate(0, num_entries - 1, 75);
    LOGINFO("RangeUpdate test end");
}

TYPED_TEST(BtreeTest, CpFlush) {
    LOGINFO("CpFlush test start");

    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Do Forward sequential insert for {} entries", num_entries / 2);
    for (uint32_t i = 0; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries / 2);
    this->query_validate(0, num_entries / 2 - 1, 75);

    this->print(std::string("before.txt"));

    LOGINFO("Trigger checkpoint flush.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    this->query_validate(0, num_entries - 1, 75);

    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    auto index_svc_cb = std::make_unique< typename TestFixture::TestIndexServiceCallbacks >(this, *this->m_bt_cfg);
    test_common::HSTestHelper::start_homestore("test_index_btree", 10 /* meta */, 0 /* data log */, 0 /* ctrl log*/,
                                               0 /* data */, 70 /* index */, nullptr, true /* restart */,
                                               std::move(index_svc_cb) /* index service callbacks */);
    std::this_thread::sleep_for(std::chrono::seconds{3});
    LOGINFO("Restarted homestore with index recovered");

    this->print(std::string("after.txt"));

    LOGINFO("Query {} entries", num_entries);
    this->query_validate(0, num_entries - 1, 1000);

    this->compare_files("before.txt", "after.txt");
    LOGINFO("CpFlush test end");
}

TYPED_TEST(BtreeTest, MultipleCpFlush) {
    LOGINFO("MultipleCpFlush test start");

    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    LOGINFO("Do Forward sequential insert for {} entries", num_entries / 2);
    for (uint32_t i = 0; i < num_entries / 2; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        if (i % 500 == 0) {
            LOGINFO("Trigger checkpoint flush wait=false.");
            test_common::HSTestHelper::trigger_cp(false /* wait */);
        }
    }

    LOGINFO("Trigger checkpoint flush wait=false.");
    test_common::HSTestHelper::trigger_cp(false /* wait */);

    for (uint32_t i = num_entries / 2; i < num_entries; ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }

    LOGINFO("Trigger checkpoint flush wait=false.");
    test_common::HSTestHelper::trigger_cp(false /* wait */);

    LOGINFO("Trigger checkpoint flush wait=true.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    this->query_validate(0, num_entries - 1, 75);

    this->print(std::string("before.txt"));

    this->destroy_btree();
    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    auto index_svc_cb = std::make_unique< typename TestFixture::TestIndexServiceCallbacks >(this, *this->m_bt_cfg);
    test_common::HSTestHelper::start_homestore("test_index_btree", 10 /* meta */, 0 /* data log */, 0 /* ctrl log*/,
                                               0 /* data */, 70 /* index */, nullptr, true /* restart */,
                                               std::move(index_svc_cb) /* index service callbacks */);
    std::this_thread::sleep_for(std::chrono::seconds{3});
    LOGINFO(" Restarted homestore with index recovered");
    this->print(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", num_entries);
    this->query_validate(0, num_entries - 1, 1000);
    LOGINFO("MultipleCpFlush test end");
}

TYPED_TEST(BtreeTest, ThreadedCpFlush) {
    LOGINFO("ThreadedCpFlush test start");

    const auto num_entries = SISL_OPTIONS["num_entries"].as< uint32_t >();
    bool stop_cp_flush = false;
    auto io_thread = std::thread([this, num_entries] {
        LOGINFO("Do Forward sequential insert for {} entries", num_entries);
        for (uint32_t i = 0; i < num_entries; ++i) {
            this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        }
    });

    auto cp_flush_thread = std::thread([this, &stop_cp_flush] {
        while (!stop_cp_flush) {
            LOGINFO("Trigger checkpoint flush wait=false.");
            test_common::HSTestHelper::trigger_cp(false /* wait */);
            std::this_thread::sleep_for(std::chrono::seconds{1});
        }
    });

    io_thread.join();
    stop_cp_flush = true;
    cp_flush_thread.join();

    LOGINFO("Trigger checkpoint flush wait=true.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Query {} entries and validate with pagination of 75 entries", num_entries);
    this->query_validate(0, num_entries - 1, 75);

    this->print(std::string("before.txt"));
    this->destroy_btree();

    // Restart homestore. m_bt is updated by the TestIndexServiceCallback.
    auto index_svc_cb = std::make_unique< typename TestFixture::TestIndexServiceCallbacks >(this, *this->m_bt_cfg);
    test_common::HSTestHelper::start_homestore("test_index_btree", 10 /* meta */, 0 /* data log */, 0 /* ctrl log*/,
                                               0 /* data */, 70 /* index */, nullptr, true /* restart */,
                                               std::move(index_svc_cb) /* index service callbacks */);
    std::this_thread::sleep_for(std::chrono::seconds{3});
    LOGINFO(" Restarted homestore with index recovered");
    this->print(std::string("after.txt"));

    this->compare_files("before.txt", "after.txt");

    LOGINFO("Query {} entries and validate with pagination of 1000 entries", num_entries);
    this->query_validate(0, num_entries - 1, 1000);
    LOGINFO("ThreadedCpFlush test end");
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
