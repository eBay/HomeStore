#include <map>
#include <gtest/gtest.h>

#include "btree_test_kvs.hpp"


template < typename K, typename V >
class ShadowMap {
private:
    std::map< K, V > m_map;
    RangeScheduler m_range_scheduler;
    uint32_t m_max_keys;
    using mutex = iomgr::FiberManagerLib::shared_mutex;
    mutex m_mutex;
//#define SHOWM(X) cout << #X " = " << (X) << endl
//    void testPrint(std::map< uint32_t, std::string >& m_map, int i) {
//        SHOWM(m[i]);
//        SHOWM(m.find(i)->first);
//    }
public:
    ShadowMap(uint32_t num_keys) : m_range_scheduler(num_keys), m_max_keys{num_keys} {}

    void put_and_check(const K& key, const V& val, const V& old_val, bool expected_success) {
        std::lock_guard lock{m_mutex};
        auto const [it, happened] = m_map.insert(std::make_pair(key, val));
        ASSERT_EQ(happened, expected_success) << "Testcase issue, expected inserted slots to be in shadow map";
        if (!happened) {
            ASSERT_EQ(old_val, it->second) << "Put: Existing value doesn't return correct data for key: " << it->first;
        }
        m_range_scheduler.put_key(key.key());
    }

    void force_put(const K& key, const V& val) {
        std::lock_guard lock{m_mutex};
        m_map.insert_or_assign(key, val);
        m_range_scheduler.put_key(key.key());
    }

    void range_upsert(uint64_t start_k, uint32_t count, const V& val) {
        std::lock_guard lock{m_mutex};
        for (uint32_t i{0}; i < count; ++i) {
            K key{start_k + i};
            V range_value{val};
            if constexpr (std::is_same_v< V, TestIntervalValue >) { range_value.shift(i); }
            m_map.insert_or_assign(key, range_value);
        }
        m_range_scheduler.put_keys(start_k, start_k + count - 1);
    }

    void range_update(const K& start_key, uint32_t count, const V& new_val) {
        std::lock_guard lock{m_mutex};
        auto const start_it = m_map.lower_bound(start_key);
        auto it = start_it;
        uint32_t c = 0;
        while ((it != m_map.end()) && (++c <= count)) {
            it->second = new_val;
            ++it;
        }
        m_range_scheduler.remove_keys_from_working(start_key.key(), start_key.key() + count - 1);
    }

    std::pair< K, K > pick_existing_range(const K& start_key, uint32_t max_count) const {
        std::lock_guard lock{m_mutex};
        auto const start_it = m_map.lower_bound(start_key);
        auto it = start_it;
        uint32_t count = 0;
        while ((it != m_map.cend()) && (++count < max_count)) {
            ++it;
        }
        return std::pair(start_it->first, it->first);
    }

    uint32_t max_keys() const { return m_max_keys; }

    bool exists(const K& key) const {
        std::lock_guard lock{m_mutex};
        return m_map.find(key) != m_map.end();
    }

    bool exists_in_range(const K& key, uint64_t start_k, uint64_t end_k) const {
        std::lock_guard lock{m_mutex};
        const auto itlower = m_map.lower_bound(K{start_k});
        const auto itupper = m_map.upper_bound(K{end_k});
        auto it = itlower;
        while (it != itupper) {
            if (it->first == key) { return true; }
            ++it;
        }
        return false;
    }

    uint64_t size() const {
        std::lock_guard lock{m_mutex};
        return m_map.size();
    }

    uint32_t num_elems_in_range(uint64_t start_k, uint64_t end_k) const {
        const auto itlower = m_map.lower_bound(K{start_k});
        const auto itupper = m_map.upper_bound(K{end_k});
        return std::distance(itlower, itupper);
    }

    void validate_data(const K& key, const V& btree_val) const {
        std::lock_guard lock{m_mutex};
        const auto r = m_map.find(key);
        ASSERT_NE(r, m_map.end()) << "Key " << key.to_string() << " is not present in shadow map";
        ASSERT_EQ(btree_val, r->second) << "Found value in btree doesn't return correct data for key=" << r->first;
    }

    void remove_and_check(const K& key, const V& btree_val) {
        std::lock_guard lock{m_mutex};
        const auto r = m_map.find(key);
        ASSERT_NE(r, m_map.end()) << "Key " << key.to_string() << " is not present in shadow map";
        ASSERT_EQ(btree_val, r->second) << "Found value in btree doesn't return correct data for key=" << r->first;
        m_map.erase(key);
        m_range_scheduler.remove_key(key.key());
    }

    void erase(const K& key) {
        std::lock_guard lock{m_mutex};
        m_map.erase(key);
        m_range_scheduler.remove_key(key.key());
    }

    void range_erase(const K& start_key, uint32_t count) {
        std::lock_guard lock{m_mutex};
        auto it = m_map.lower_bound(start_key);
        uint32_t i{0};
        while ((it != m_map.cend()) && (i++ < count)) {
            it = m_map.erase(it);
        }
        m_range_scheduler.remove_keys(start_key.key(), start_key.key() + count);
    }

    void range_erase(const K& start_key, const K& end_key) {
        std::lock_guard lock{m_mutex};
        auto it = m_map.lower_bound(start_key);
        auto const end_it = m_map.upper_bound(end_key);
        while ((it != m_map.cend()) && (it != end_it)) {
            it = m_map.erase(it);
        }
        m_range_scheduler.remove_keys(start_key.key(), end_key.key());
    }

    std::vector< std::pair< K, bool > > diff(ShadowMap< K, V > const& other) {
        auto it1 = m_map.begin();
        auto it2 = other.m_map.begin();
        std::vector< std::pair< K, bool > > ret_diff;

        while ((it1 != m_map.end()) && (it2 != other.m_map.end())) {
            auto const x = it1->first.compare(it2->first);
            if (x == 0) {
                ++it1;
                ++it2;
            } else if (x < 0) {
                // Has in current map, add it to addition
                ret_diff.emplace_back(it1->first, true /* addition */);
                ++it1;
            } else {
                ret_diff.emplace_back(it2->first, false /* addition */);
                ++it2;
            }
        }

        while (it1 != m_map.end()) {
            ret_diff.emplace_back(it1->first, true /* addition */);
            ++it1;
        }

        while (it2 != other.m_map.end()) {
            ret_diff.emplace_back(it2->first, false /* addition */);
            ++it2;
        }
        return ret_diff;
    }

    mutex& guard() { return m_mutex; }
    std::map< K, V >& map() { return m_map; }
    const std::map< K, V >& map_const() const { return m_map; }

    void foreach (std::function< void(K, V) > func) const {
        std::lock_guard lock{m_mutex};
        for (const auto& [key, value] : m_map) {
            func(key, value);
        }
    }
    std::string to_string() const {
        std::string result;
        std::stringstream ss;
        const int key_width = 20;

        // Format the key-value pairs and insert them into the result string
        ss << std::left << std::setw(key_width) << "KEY" << " " << "VaLUE" << '\n';
        foreach ([&](const auto& key, const auto& value) {
            ss << std::left << std::setw(key_width) << key.to_string() << " " << value.to_string() << '\n';
        })
            ;
        result = ss.str();
        return result;
    }

    std::pair< uint32_t, uint32_t > pick_random_non_existing_keys(uint32_t max_keys) {
        do {
            std::lock_guard lock{m_mutex};
            auto ret = m_range_scheduler.pick_random_non_existing_keys(max_keys);
            if (ret.first != UINT32_MAX) { return ret; }
        } while (true);
    }

    std::pair< uint32_t, uint32_t > pick_random_existing_keys(uint32_t max_keys) {
        do {
            std::lock_guard lock{m_mutex};
            auto ret = m_range_scheduler.pick_random_existing_keys(max_keys);
            if (ret.first != UINT32_MAX) { return ret; }
        } while (true);
    }

    std::pair< uint32_t, uint32_t > pick_random_non_working_keys(uint32_t max_keys) {
        do {
            std::lock_guard lock{m_mutex};
            auto ret = m_range_scheduler.pick_random_non_working_keys(max_keys);
            if (ret.first != UINT32_MAX) { return ret; }
        } while (true);
    }

    void remove_keys_from_working(uint32_t s, uint32_t e) {
        std::lock_guard lock{m_mutex};
        m_range_scheduler.remove_keys_from_working(s, e);
    }

    void remove_keys(uint32_t start_key, uint32_t end_key) {
        std::lock_guard lock{m_mutex};
        m_range_scheduler.remove_keys(start_key, end_key);
    }

    void save(const std::string& filename) {
        std::lock_guard lock{m_mutex};
        std::ofstream file(filename);
        for (const auto& [key, value] : m_map) {
            file << key << " " << value << '\n';
        }
        file.close();
        LOGINFO("Saved shadow map to file: {}", filename);
    }

    void load(const std::string& filename) {
        std::lock_guard lock{m_mutex};
        std::ifstream file(filename);
        if (file.is_open()) {
            m_map.clear();
            K key;
            V value;
            while (file >> key >> value) {
                m_map.emplace(key, std::move(value));
                m_range_scheduler.put_key(key.key());
            }
            file.close();
        }
    }
};
