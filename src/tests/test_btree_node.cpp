/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#include <random>
#include <map>
#include <memory>

#include <sisl/options/options.h>
#include <sisl/logging/logging.h>
#include <sisl/utility/enum.hpp>
#include "btree/detail/simple_node.hpp"
#include "btree/detail/varlen_node.hpp"
#include "btree_test_kvs.hpp"

static constexpr uint32_t g_node_size{4096};
static constexpr uint32_t g_max_keys{6000};
static std::uniform_int_distribution< uint32_t > g_randkey_generator{0, g_max_keys};

using namespace homestore;
SISL_LOGGING_INIT(btree)

struct FixedLenNodeTest {
    using NodeType = SimpleNode< TestFixedKey, TestFixedValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestFixedValue;
};

struct VarKeySizeNodeTest {
    using NodeType = VarKeySizeNode< TestVarLenKey, TestFixedValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestFixedValue;
};

struct VarValueSizeNodeTest {
    using NodeType = VarValueSizeNode< TestFixedKey, TestVarLenValue >;
    using KeyType = TestFixedKey;
    using ValueType = TestVarLenValue;
};

struct VarObjSizeNodeTest {
    using NodeType = VarObjSizeNode< TestVarLenKey, TestVarLenValue >;
    using KeyType = TestVarLenKey;
    using ValueType = TestVarLenValue;
};

template < typename TestType >
struct NodeTest : public testing::Test {
    using T = TestType;
    using K = typename TestType::KeyType;
    using V = typename TestType::ValueType;

    std::unique_ptr< typename T::NodeType > m_node1;
    std::unique_ptr< typename T::NodeType > m_node2;
    std::map< K, V > m_shadow_map;
    BtreeConfig m_cfg{g_node_size};

    void SetUp() override {
        m_cfg.set_node_data_size(m_cfg.node_size() - sizeof(persistent_hdr_t));
        m_node1 = std::make_unique< typename T::NodeType >(new uint8_t[g_node_size], 1ul, true, true, m_cfg);
        m_node2 = std::make_unique< typename T::NodeType >(new uint8_t[g_node_size], 2ul, true, true, m_cfg);
    }

    void put(uint32_t k, btree_put_type put_type) {
        K key{k};
        V value{V::generate_rand()};
        V existing_v;
        bool done = m_node1->put(key, value, put_type, &existing_v);

        bool expected_done{true};
        if (m_shadow_map.find(key) != m_shadow_map.end()) {
            expected_done = (put_type != btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        }
        ASSERT_EQ(done, expected_done) << "Expected put of key " << k << " of put_type " << enum_name(put_type)
                                       << " to be " << expected_done;
        if (expected_done) {
            m_shadow_map.insert(std::make_pair(key, value));
        } else {
            const auto r = m_shadow_map.find(key);
            ASSERT_NE(r, m_shadow_map.end()) << "Testcase issue, expected inserted slots to be in shadow map";
            ASSERT_EQ(existing_v, r->second)
                << "Insert existing value doesn't return correct data for key " << r->first;
        }
    }

    void update(uint32_t k, bool validate_update = true) {
        K key{k};
        V value{V::generate_rand()};
        V existing_v;
        const bool done = m_node1->update_one(key, value, &existing_v);
        const auto expected_done = (m_shadow_map.find(key) != m_shadow_map.end());
        ASSERT_EQ(done, expected_done) << "Not updated for key=" << k << " where it is expected to";

        if (done) {
            validate_data(key, existing_v);
            m_shadow_map[key] = value;
        }

        if (validate_update) { validate_specific(k); }
    }

    void remove(uint32_t k, bool validate_remove = true) {
        K key{k};
        K existing_key;
        V existing_value;
        const bool shadow_found = (m_shadow_map.find(key) != m_shadow_map.end());
        auto removed_1 = m_node1->remove_one(K{key}, &existing_key, &existing_value);
        if (removed_1) {
            ASSERT_EQ(key.key(), k) << "Whats removed is different than whats asked for";
            validate_data(key, existing_value);
            m_shadow_map.erase(key);
        }

        auto removed_2 = m_node2->remove_one(K{key}, &existing_key, &existing_value);
        if (removed_2) {
            ASSERT_EQ(key.key(), k) << "Whats removed is different than whats asked for";
            validate_data(key, existing_value);
            m_shadow_map.erase(key);
        }

        ASSERT_EQ(removed_1 || removed_2, shadow_found) << "To remove key=" << k << " is not present in the nodes";

        if (validate_remove) { validate_specific(k); }
    }

    void validate_get_all() const {
        uint32_t start_ind{0};
        uint32_t end_ind{0};
        std::vector< std::pair< K, V > > out_vector;
        auto ret = m_node1->get_all(BtreeKeyRange< K >{K{0u}, true, K{g_max_keys}, false}, g_max_keys, start_ind,
                                    end_ind, &out_vector);
        ret += m_node2->get_all(BtreeKeyRange< K >{K{0u}, true, K{g_max_keys}, false}, g_max_keys, start_ind, end_ind,
                                &out_vector);

        ASSERT_EQ(ret, m_shadow_map.size()) << "Expected number of entries to be same with shadow_map size";
        ASSERT_EQ(out_vector.size(), m_shadow_map.size())
            << "Expected number of entries to be same with shadow_map size";

        uint64_t idx{0};
        for (auto& [key, value] : m_shadow_map) {
            ASSERT_EQ(out_vector[idx].second, value)
                << "Range get doesn't return correct data for key=" << key << " idx=" << idx;
            ++idx;
        }
    }

    void validate_get_any(uint32_t start, uint32_t end) const {
        K start_key{start};
        K end_key{end};
        K out_k;
        V out_v;
        auto result = m_node1->get_any(BtreeKeyRange< K >{start_key, true, end_key, true}, &out_k, &out_v, true, true);
        if (result.first) {
            validate_data(out_k, out_v);
        } else {
            result = m_node2->get_any(BtreeKeyRange< K >{start_key, true, end_key, true}, &out_k, &out_v, true, true);
            if (result.first) {
                validate_data(out_k, out_v);
            } else {
                const auto r = m_shadow_map.lower_bound(start_key);
                const bool found = ((r != m_shadow_map.end()) && (r->first.key() <= end));
                ASSERT_EQ(found, false) << "Node key range=" << start << "-" << end
                                        << " missing, Its present in shadow map at " << r->first;
            }
        }
    }

    void validate_specific(uint32_t k) const {
        K key{k};
        V val;
        const auto ret1 = m_node1->find(key, &val, true);
        if (ret1.first) {
            ASSERT_NE(m_shadow_map.find(key), m_shadow_map.end())
                << "Node key " << k << " is present when its expected not to be";
            validate_data(key, val);
        }

        const auto ret2 = m_node2->find(key, &val, true);
        if (ret2.first) {
            ASSERT_NE(m_shadow_map.find(key), m_shadow_map.end())
                << "Node key " << k << " is present when its expected not to be";
            validate_data(key, val);
        }

        ASSERT_EQ(ret1.first || ret2.first, m_shadow_map.find(key) != m_shadow_map.end())
            << "Node key " << k << " is incorrect presence compared to shadow map";
    }

protected:
    void put_list(const std::vector< uint32_t >& keys) {
        for (const auto& k : keys) {
            if (!this->has_room()) { break; }
            put(k, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        }
    }

    void print() const {
        LOGDEBUG("Node1:\n {}", m_node1->to_string(true));
        LOGDEBUG("Node2:\n {}", m_node2->to_string(true));
    }

    uint32_t remaining_space() const { return m_node1->available_size(m_cfg); }
    bool has_room() const { return remaining_space() > (g_max_keysize + g_max_valsize + 32); }

private:
    void validate_data(const K& key, const V& node_val) const {
        const auto r = m_shadow_map.find(key);
        ASSERT_NE(r, m_shadow_map.end()) << "Node key is not present in shadow map";
        ASSERT_EQ(node_val, r->second) << "Found value in node doesn't return correct data for key=" << r->first;
    }
};

using NodeTypes = testing::Types< FixedLenNodeTest, VarKeySizeNodeTest, VarValueSizeNodeTest, VarObjSizeNodeTest >;
TYPED_TEST_SUITE(NodeTest, NodeTypes);

TYPED_TEST(NodeTest, SequentialInsert) {
    for (uint32_t i{0}; (i < 100 && this->has_room()); ++i) {
        this->put(i, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    this->print();
    this->validate_get_all();
    this->validate_get_any(0, 2);
    this->validate_get_any(3, 3);
    this->validate_get_any(98, 102);
}

TYPED_TEST(NodeTest, ReverseInsert) {
    for (uint32_t i{100}; (i > 0 && this->has_room()); --i) {
        this->put(i - 1, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
    }
    this->print();
    this->validate_get_all();
    this->validate_get_any(0, 2);
    this->validate_get_any(3, 3);
    this->validate_get_any(98, 102);
}

TYPED_TEST(NodeTest, Remove) {
    this->put_list({0, 1, 2, g_max_keys / 2, g_max_keys / 2 + 1, g_max_keys / 2 - 1});
    this->remove(0);
    this->remove(0); // Remove non-existing
    this->remove(1);
    this->remove(2);
    this->remove(g_max_keys / 2 - 1);
    this->print();
    this->validate_get_all();
    this->validate_get_any(0, 2);
    this->validate_get_any(3, 3);
    this->validate_get_any(g_max_keys / 2, g_max_keys - 1);
}

TYPED_TEST(NodeTest, Update) {
    this->put_list({0, 1, 2, g_max_keys / 2, g_max_keys / 2 + 1, g_max_keys / 2 - 1});
    this->update(1);
    this->update(g_max_keys / 2);
    this->update(2);
    this->remove(0);
    this->update(0); // Update non-existing
    this->print();
    this->validate_get_all();
}

TYPED_TEST(NodeTest, RandomInsertRemoveUpdate) {
    uint32_t num_inserted{0};
    while (this->has_room()) {
        this->put(g_randkey_generator(g_re), btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
        ++num_inserted;
    }
    LOGDEBUG("After random insertion of {} objects", num_inserted);
    this->print();
    this->validate_get_all();

    for (uint32_t i{0}; i < num_inserted / 2; ++i) {
        const auto k = g_randkey_generator(g_re) % this->m_shadow_map.rbegin()->first.key();
        const auto r = this->m_shadow_map.lower_bound(typename TestFixture::K{k});
        this->remove(r->first.key());
    }
    LOGDEBUG("After random removal of {} objects", num_inserted / 2);
    this->print();
    this->validate_get_all();

    uint32_t num_updated{0};
    for (uint32_t i{0}; i < num_inserted / 2 && this->has_room(); ++i) {
        const auto k = g_randkey_generator(g_re) % this->m_shadow_map.rbegin()->first.key();
        const auto r = this->m_shadow_map.lower_bound(typename TestFixture::K{k});
        this->update(r->first.key());
        ++num_updated;
    }
    LOGDEBUG("After update of {} entries", num_updated);
    this->print();
    this->validate_get_all();
}

TYPED_TEST(NodeTest, Move) {
    std::vector< uint32_t > list{0, 1, 2, g_max_keys / 2 - 1};
    this->put_list(list);
    this->print();

    this->m_node1->move_out_to_right_by_entries(this->m_cfg, *this->m_node2, list.size());
    this->m_node1->move_out_to_right_by_entries(this->m_cfg, *this->m_node2, list.size()); // Empty move
    ASSERT_EQ(this->m_node1->total_entries(), 0u) << "Move out to right has failed";
    ASSERT_EQ(this->m_node2->total_entries(), list.size()) << "Move out to right has failed";
    this->validate_get_all();

    auto first_half = list.size() / 2;
    auto second_half = list.size() - first_half;
    this->m_node1->copy_by_entries(this->m_cfg, *this->m_node2, 0, first_half);           // Copy half entries
    this->m_node1->copy_by_entries(this->m_cfg, *this->m_node2, first_half, second_half); // Copy half entries
    this->m_node2->remove_all(this->m_cfg);
    ASSERT_EQ(this->m_node2->total_entries(), 0u) << "Remove all on right has failed";
    ASSERT_EQ(this->m_node1->total_entries(), list.size()) << "Move in from right has failed";
    this->validate_get_all();

    this->m_node1->move_out_to_right_by_entries(this->m_cfg, *this->m_node2, list.size() / 2);
    ASSERT_EQ(this->m_node1->total_entries(), list.size() / 2) << "Move out half entries to right has failed";
    ASSERT_EQ(this->m_node2->total_entries(), list.size() - list.size() / 2)
        << "Move out half entries to right has failed";
    this->validate_get_all();
    this->print();

    ASSERT_EQ(this->m_node1->validate_key_order(), true) << "Key order validation of node1 has failed";
    ASSERT_EQ(this->m_node2->validate_key_order(), true) << "Key order validation of node2 has failed";
}

SISL_OPTIONS_ENABLE(logging, test_btree_node)
SISL_OPTION_GROUP(test_btree_node,
                  (num_iters, "", "num_iters", "number of iterations for rand ops",
                   ::cxxopts::value< uint32_t >()->default_value("65536"), "number"))

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, logging, test_btree_node)
    sisl::logging::SetLogger("test_btree_node");
    spdlog::set_pattern("[%D %T%z] [%^%L%$] [%t] %v");

    auto ret = RUN_ALL_TESTS();
    return ret;
}