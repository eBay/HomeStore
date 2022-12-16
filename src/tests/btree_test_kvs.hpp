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
#pragma once
#include <string>
#include <random>
#include <map>
#include <memory>
#include <array>
#include <homestore/btree/btree_kv.hpp>

static constexpr uint32_t g_max_keysize{120};
static constexpr uint32_t g_max_valsize{120};
static std::random_device g_rd{};
static std::default_random_engine g_re{g_rd()};
static std::uniform_int_distribution< uint32_t > g_randkeysize_generator{2, g_max_keysize};
static std::uniform_int_distribution< uint32_t > g_randval_generator{1, 30000};
static std::uniform_int_distribution< uint32_t > g_randvalsize_generator{2, g_max_valsize};

static std::map< uint32_t, std::shared_ptr< std::string > > g_key_pool;

static constexpr std::array< const char, 62 > alphanum{
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

static std::string gen_random_string(size_t len, uint32_t preamble = std::numeric_limits< uint32_t >::max()) {
    std::string str;
    if (preamble != std::numeric_limits< uint32_t >::max()) {
        std::stringstream ss;
        ss << std::setw(8) << std::setfill('0') << std::hex << preamble;
        str += ss.str();
    }

    static thread_local std::random_device rd{};
    static thread_local std::default_random_engine re{rd()};
    std::uniform_int_distribution< size_t > rand_char{0, alphanum.size() - 1};
    for (size_t i{0}; i < len; ++i) {
        str += alphanum[rand_char(re)];
    }
    str += '\0';
    return str;
}

using namespace homestore;

class TestFixedKey : public BtreeKey {
private:
    uint32_t m_key{0};

public:
    TestFixedKey() = default;
    TestFixedKey(uint32_t k) : m_key{k} {}
    TestFixedKey(const TestFixedKey& other) : TestFixedKey(other.serialize(), true) {}
    TestFixedKey(const BtreeKey& other) : TestFixedKey(other.serialize(), true) {}
    TestFixedKey(const sisl::blob& b, bool copy) : BtreeKey(), m_key{*(r_cast< const uint32_t* >(b.bytes))} {}
    TestFixedKey& operator=(const TestFixedKey& other) {
        clone(other);
        return *this;
    };
    virtual void clone(const BtreeKey& other) override { m_key = ((TestFixedKey&)other).m_key; }

    virtual ~TestFixedKey() = default;

    int compare(const BtreeKey& o) const override {
        const TestFixedKey& other = s_cast< const TestFixedKey& >(o);
        if (m_key < other.m_key) {
            return -1;
        } else if (m_key > other.m_key) {
            return 1;
        } else {
            return 0;
        }
    }

    /*int compare_range(const BtreeKeyRange& range) const override {
        if (m_key == start_key(range)) {
            return range.is_start_inclusive() ? 0 : -1;
        } else if (m_key < start_key(range)) {
            return -1;
        } else if (m_key == end_key(range)) {
            return range.is_end_inclusive() ? 0 : 1;
        } else if (m_key > end_key(range)) {
            return 1;
        } else {
            return 0;
        }
    }*/

    sisl::blob serialize() const override {
        return sisl::blob{uintptr_cast(const_cast< uint32_t* >(&m_key)), uint32_cast(sizeof(uint32_t))};
    }
    uint32_t serialized_size() const override { return get_fixed_size(); }
    static bool is_fixed_size() { return true; }
    static uint32_t get_fixed_size() { return (sizeof(uint32_t)); }
    std::string to_string() const { return fmt::format("{}", m_key); }

    void deserialize(const sisl::blob& b, bool copy) override { m_key = *(r_cast< const uint32_t* >(b.bytes)); }

    static uint32_t get_estimate_max_size() { return get_fixed_size(); }
    friend std::ostream& operator<<(std::ostream& os, const TestFixedKey& k) {
        os << k.to_string();
        return os;
    }

    bool operator<(const TestFixedKey& o) const { return (compare(o) < 0); }
    bool operator==(const TestFixedKey& other) const { return (compare(other) == 0); }

    uint32_t key() const { return m_key; }
    uint32_t start_key(const BtreeKeyRange< TestFixedKey >& range) const {
        const TestFixedKey& k = (const TestFixedKey&)(range.start_key());
        return k.m_key;
    }
    uint32_t end_key(const BtreeKeyRange< TestFixedKey >& range) const {
        const TestFixedKey& k = (const TestFixedKey&)(range.end_key());
        return k.m_key;
    }
};

class TestVarLenKey : public BtreeKey {
private:
    uint32_t m_key{0};

    static std::shared_ptr< std::string > idx_to_key(uint32_t idx) {
        auto it = g_key_pool.find(idx);
        if (it == g_key_pool.end()) {
            const auto& [it, happened] = g_key_pool.emplace(
                idx, std::make_shared< std::string >(gen_random_string(g_randkeysize_generator(g_re), idx)));
            assert(happened);
            return it->second;
        } else {
            return it->second;
        }
    }

public:
    TestVarLenKey() = default;
    TestVarLenKey(uint32_t k) : BtreeKey(), m_key{k} {}
    TestVarLenKey(const BtreeKey& other) : TestVarLenKey(other.serialize(), true) {}
    TestVarLenKey(const TestVarLenKey& other) = default;
    TestVarLenKey(TestVarLenKey&& other) = default;
    TestVarLenKey& operator=(const TestVarLenKey& other) = default;
    TestVarLenKey& operator=(TestVarLenKey&& other) = default;

    TestVarLenKey(const sisl::blob& b, bool copy) : BtreeKey() { deserialize(b, copy); }
    virtual ~TestVarLenKey() = default;

    virtual void clone(const BtreeKey& other) override { m_key = ((TestVarLenKey&)other).m_key; }

    sisl::blob serialize() const override {
        const auto& data = idx_to_key(m_key);
        return sisl::blob{(uint8_t*)(data->c_str()), (uint32_t)data->size()};
    }

    uint32_t serialized_size() const override { return idx_to_key(m_key)->size(); }
    static bool is_fixed_size() { return false; }
    static uint32_t get_fixed_size() {
        assert(0);
        return 0;
    }

    void deserialize(const sisl::blob& b, bool copy) {
        std::string data{r_cast< const char* >(b.bytes), b.size};
        std::stringstream ss;
        ss << std::hex << data.substr(0, 8);
        ss >> m_key;
        assert(data == *idx_to_key(m_key));
    }

    static uint32_t get_estimate_max_size() { return g_max_keysize; }

    int compare(const BtreeKey& o) const override {
        const TestVarLenKey& other = s_cast< const TestVarLenKey& >(o);
        if (m_key < other.m_key) {
            return -1;
        } else if (m_key > other.m_key) {
            return 1;
        } else {
            return 0;
        }
    }

    /*    int compare_range(const BtreeKeyRange& range) const override {
            if (m_key == start_key(range)) {
                return range.is_start_inclusive() ? 0 : -1;
            } else if (m_key < start_key(range)) {
                return -1;
            } else if (m_key == end_key(range)) {
                return range.is_end_inclusive() ? 0 : 1;
            } else if (m_key > end_key(range)) {
                return 1;
            } else {
                return 0;
            }
        } */

    std::string to_string() const { return fmt::format("{}-{}", m_key, idx_to_key(m_key)->substr(0, 8)); }

    friend std::ostream& operator<<(std::ostream& os, const TestVarLenKey& k) {
        os << k.to_string();
        return os;
    }

    bool operator<(const TestVarLenKey& o) const { return (compare(o) < 0); }
    bool operator==(const TestVarLenKey& other) const { return (compare(other) == 0); }

    uint32_t key() const { return m_key; }
    uint32_t start_key(const BtreeKeyRange< TestVarLenKey >& range) const {
        const TestVarLenKey& k = (const TestVarLenKey&)(range.start_key());
        return k.m_key;
    }
    uint32_t end_key(const BtreeKeyRange< TestVarLenKey >& range) const {
        const TestVarLenKey& k = (const TestVarLenKey&)(range.end_key());
        return k.m_key;
    }
};

class TestFixedValue : public BtreeValue {
private:
public:
    TestFixedValue(bnodeid_t val) { assert(0); }
    TestFixedValue(uint32_t val) : BtreeValue() { m_val = val; }
    TestFixedValue() : TestFixedValue((uint32_t)-1) {}
    TestFixedValue(const TestFixedValue& other) : BtreeValue() { m_val = other.m_val; };
    TestFixedValue(const sisl::blob& b, bool copy) : BtreeValue() { m_val = *(r_cast< uint32_t* >(b.bytes)); }
    virtual ~TestFixedValue() = default;

    static TestFixedValue generate_rand() { return TestFixedValue{g_randval_generator(g_re)}; }

    TestFixedValue& operator=(const TestFixedValue& other) {
        m_val = other.m_val;
        return *this;
    }

    sisl::blob serialize() const override {
        sisl::blob b;
        b.bytes = uintptr_cast(const_cast< uint32_t* >(&m_val));
        b.size = sizeof(m_val);
        return b;
    }

    uint32_t serialized_size() const override { return sizeof(m_val); }
    static uint32_t get_fixed_size() { return sizeof(m_val); }
    void deserialize(const sisl::blob& b, bool copy) { m_val = *(r_cast< uint32_t* >(b.bytes)); }

    std::string to_string() const override { return fmt::format("{}", m_val); }

    friend std::ostream& operator<<(std::ostream& os, const TestFixedValue& v) {
        os << v.to_string();
        return os;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const TestFixedValue& other) const { return (m_val == other.m_val); }

    uint32_t value() const { return m_val; }

private:
    uint32_t m_val;
};

class TestVarLenValue : public BtreeValue {
public:
    TestVarLenValue(bnodeid_t val) { assert(0); }
    TestVarLenValue(const std::string& val) : BtreeValue(), m_val{val} {}
    TestVarLenValue() = default;
    TestVarLenValue(const TestVarLenValue& other) : BtreeValue() { m_val = other.m_val; };
    TestVarLenValue(const sisl::blob& b, bool copy) : BtreeValue(), m_val{std::string((const char*)b.bytes, b.size)} {}
    virtual ~TestVarLenValue() = default;

    TestVarLenValue& operator=(const TestVarLenValue& other) {
        m_val = other.m_val;
        return *this;
    }

    static TestVarLenValue generate_rand() { return TestVarLenValue{gen_random_string(g_randvalsize_generator(g_re))}; }

    sisl::blob serialize() const override {
        sisl::blob b;
        b.bytes = uintptr_cast(const_cast< char* >(m_val.c_str()));
        b.size = m_val.size();
        return b;
    }

    uint32_t serialized_size() const override { return (uint32_t)m_val.size(); }
    static uint32_t get_fixed_size() { return 0; }

    void deserialize(const sisl::blob& b, bool copy) { m_val = std::string((const char*)b.bytes, b.size); }

    std::string to_string() const override { return fmt::format("{}", m_val); }

    friend std::ostream& operator<<(std::ostream& os, const TestVarLenValue& v) {
        os << v.to_string();
        return os;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const TestVarLenValue& other) const { return (m_val == other.m_val); }

    std::string value() const { return m_val; }

private:
    std::string m_val;
};
