#include <map>
#include <gtest/gtest.h>

#include "btree_test_kvs.hpp"

template < typename K, typename V >
class ShadowMap {
private:
    std::map< K, V > m_map;

public:
    void put_and_check(const K& key, const V& val, const V& old_val, bool expected_success) {
        auto const [it, happened] = m_map.insert(std::make_pair(key, val));
        ASSERT_EQ(happened, expected_success) << "Testcase issue, expected inserted slots to be in shadow map";
        if (!happened) {
            ASSERT_EQ(old_val, it->second) << "Put: Existing value doesn't return correct data for key: " << it->first;
        }
    }

    void range_upsert(uint64_t start_k, uint32_t count, const V& val) {
        for (uint32_t i{0}; i < count; ++i) {
            K key{start_k + i};
            V range_value{val};
            if constexpr (std::is_same_v< V, TestIntervalValue >) { range_value.shift(i); }
            m_map.insert_or_assign(key, range_value);
        }
    }

    void range_update(const K& start_key, uint32_t count, const V& new_val) {
        auto const start_it = m_map.lower_bound(start_key);
        auto it = start_it;
        uint32_t c = 0;
        while ((it != m_map.end()) && (++c <= count)) {
            it->second = new_val;
            ++it;
        }
    }

    std::pair< K, K > pick_existing_range(const K& start_key, uint32_t max_count) const {
        auto const start_it = m_map.lower_bound(start_key);
        auto it = start_it;
        uint32_t count = 0;
        while ((it != m_map.cend()) && (++count < max_count)) {
            ++it;
        }
        return std::pair(start_it->first, it->first);
    }

    bool exists(const K& key) const { return m_map.find(key) != m_map.end(); }

    bool exists_in_range(const K& key, uint64_t start_k, uint64_t end_k) const {
        const auto itlower = m_map.lower_bound(K{start_k});
        const auto itupper = m_map.upper_bound(K{end_k});
        auto it = itlower;
        while (it != itupper) {
            if (it->first == key) { return true; }
            ++it;
        }
        return false;
    }

    uint64_t size() const { return m_map.size(); }

    uint32_t num_elems_in_range(uint64_t start_k, uint64_t end_k) const {
        const auto itlower = m_map.lower_bound(K{start_k});
        const auto itupper = m_map.upper_bound(K{end_k});
        return std::distance(itlower, itupper);
    }

    void validate_data(const K& key, const V& btree_val) const {
        const auto r = m_map.find(key);
        ASSERT_NE(r, m_map.end()) << "Key " << key.to_string() << " is not present in shadow map";
        ASSERT_EQ(btree_val, r->second) << "Found value in btree doesn't return correct data for key=" << r->first;
    }

    void erase(const K& key) { m_map.erase(key); }

    void range_erase(const K& start_key, uint32_t count) {
        auto const it = m_map.lower_bound(start_key);
        uint32_t i{0};
        while ((it != m_map.cend()) && (i++ < count)) {
            it = m_map.erase(it);
        }
    }

    void range_erase(const K& start_key, const K& end_key) {
        auto it = m_map.lower_bound(start_key);
        auto const end_it = m_map.upper_bound(end_key);
        while ((it != m_map.cend()) && (it != end_it)) {
            it = m_map.erase(it);
        }
    }

    std::map< K, V >& map() { return m_map; }
    const std::map< K, V >& map_const() const { return m_map; }
};
