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
#pragma once

#include <string>
#include <random>
#include <map>
#include <memory>
#include <array>

#include <homestore/btree/btree_kv.hpp>
#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/btree/detail/prefix_node.hpp>

static constexpr uint32_t g_max_keysize{100}; // for  node size = 512 : free space : 442 => 100+100+6(record size) = 46%
static constexpr uint32_t g_max_valsize{100};
static std::random_device g_rd{};
static std::default_random_engine g_re{g_rd()};
static std::normal_distribution<> g_randkeysize_generator{32, 24};
// static std::uniform_int_distribution< uint32_t > g_randkeysize_generator{2, g_max_keysize};
static std::uniform_int_distribution< uint32_t > g_randval_generator{1, 30000};
static std::normal_distribution<> g_randvalsize_generator{32, 24};
// static std::uniform_int_distribution< uint32_t > g_randvalsize_generator{2, g_max_valsize};
static std::mutex g_map_lk;
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
    if (len < str.size()) { len = str.size(); }
    for (size_t i{0}; i < len - str.size(); ++i) {
        str += alphanum[rand_char(re)];
    }
    return str;
}
template < typename T >
static bool willAdditionOverflow(T a, int b) {
    static_assert(std::is_integral< T >::value, "Template parameter must be an integral type.");

    if (b > 0) {
        return a > std::numeric_limits< T >::max() - b;
    } else if (b < 0) {
        return a < std::numeric_limits< T >::min() - b;
    }
    return false;
}

using namespace homestore;

class TestFixedKey : public BtreeKey {
private:
    uint64_t m_key{0};

public:
    TestFixedKey() = default;
    TestFixedKey(uint64_t k) : m_key{k} {}
    TestFixedKey(const TestFixedKey& other) : TestFixedKey(other.serialize(), true) {}
    TestFixedKey(const BtreeKey& other) : TestFixedKey(other.serialize(), true) {}
    TestFixedKey(const sisl::blob& b, bool copy) : BtreeKey(), m_key{*(r_cast< const uint64_t* >(b.cbytes()))} {}
    TestFixedKey& operator=(const TestFixedKey& other) = default;
    TestFixedKey& operator=(BtreeKey const& other) {
        m_key = s_cast< TestFixedKey const& >(other).m_key;
        return *this;
    }

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
        return sisl::blob{uintptr_cast(const_cast< uint64_t* >(&m_key)), uint32_cast(sizeof(uint64_t))};
    }
    uint32_t serialized_size() const override { return get_fixed_size(); }
    static bool is_fixed_size() { return true; }
    static uint32_t get_fixed_size() { return (sizeof(uint64_t)); }
    std::string to_string() const { return fmt::format("{}", m_key); }

    void deserialize(const sisl::blob& b, bool copy) override { m_key = *(r_cast< const uint64_t* >(b.cbytes())); }

    static uint32_t get_max_size() { return get_fixed_size(); }
    friend std::ostream& operator<<(std::ostream& os, const TestFixedKey& k) {
        os << k.to_string();
        return os;
    }

    friend std::istream& operator>>(std::istream& is, TestFixedKey& k) {
        uint64_t key;
        is >> key;
        k = TestFixedKey{key};
        return is;
    }

    bool operator<(const TestFixedKey& o) const { return (compare(o) < 0); }
    bool operator==(const TestFixedKey& other) const { return (compare(other) == 0); }

    uint64_t key() const { return m_key; }
    uint64_t start_key(const BtreeKeyRange< TestFixedKey >& range) const {
        const TestFixedKey& k = (const TestFixedKey&)(range.start_key());
        return k.m_key;
    }
    uint64_t end_key(const BtreeKeyRange< TestFixedKey >& range) const {
        const TestFixedKey& k = (const TestFixedKey&)(range.end_key());
        return k.m_key;
    }
};

class TestVarLenKey : public BtreeKey {
private:
    uint64_t m_key{0};

    static uint64_t rand_key_size() {
        return (uint64_cast(std::abs(std::round(g_randkeysize_generator(g_re)))) % g_max_keysize) + 1;
    }

    static std::shared_ptr< std::string > idx_to_key(uint32_t idx) {
        std::unique_lock< std::mutex > lk(g_map_lk);
        auto it = g_key_pool.find(idx);
        if (it == g_key_pool.end()) {
            const auto& [it, happened] =
                g_key_pool.emplace(idx, std::make_shared< std::string >(gen_random_string(rand_key_size(), idx)));
            assert(happened);
            return it->second;
        } else {
            return it->second;
        }
    }

public:
    TestVarLenKey() = default;
    TestVarLenKey(uint64_t k) : BtreeKey(), m_key{k} {}
    TestVarLenKey(const BtreeKey& other) : TestVarLenKey(other.serialize(), true) {}
    TestVarLenKey(const TestVarLenKey& other) = default;
    TestVarLenKey(TestVarLenKey&& other) = default;
    TestVarLenKey& operator=(const TestVarLenKey& other) = default;
    TestVarLenKey& operator=(TestVarLenKey&& other) = default;

    TestVarLenKey(const sisl::blob& b, bool copy) : BtreeKey() { deserialize(b, copy); }
    virtual ~TestVarLenKey() = default;

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
        std::string data{r_cast< const char* >(b.cbytes()), b.size()};
        std::stringstream ss;
        ss << std::hex << data.substr(0, 8);
        ss >> m_key;
        assert(data == *idx_to_key(m_key));
    }

    // Add 8 bytes for preamble.
    static uint32_t get_max_size() { return g_max_keysize + 8; }

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

    friend std::istream& operator>>(std::istream& is, TestVarLenKey& k) {
        uint64_t key;
        is >> key;
        k = TestVarLenKey{key};
        return is;
    }

    bool operator<(const TestVarLenKey& o) const { return (compare(o) < 0); }
    bool operator==(const TestVarLenKey& other) const { return (compare(other) == 0); }

    uint64_t key() const { return m_key; }
    uint64_t start_key(const BtreeKeyRange< TestVarLenKey >& range) const {
        const TestVarLenKey& k = (const TestVarLenKey&)(range.start_key());
        return k.m_key;
    }
    uint64_t end_key(const BtreeKeyRange< TestVarLenKey >& range) const {
        const TestVarLenKey& k = (const TestVarLenKey&)(range.end_key());
        return k.m_key;
    }
};

class TestIntervalKey : public BtreeIntervalKey {
private:
#pragma pack(1)
    uint32_t m_base{0};
    uint32_t m_offset{0};
#pragma pack()

public:
    TestIntervalKey() = default;
    TestIntervalKey(uint64_t k) {
        m_base = uint32_cast(k >> 32);
        m_offset = uint32_cast(k & 0xFFFFFFFF);
    }
    TestIntervalKey(uint32_t b, uint32_t o) : m_base{b}, m_offset{o} {}
    TestIntervalKey(const TestIntervalKey& other) = default;
    TestIntervalKey(const BtreeKey& other) : TestIntervalKey(other.serialize(), true) {}
    TestIntervalKey(const sisl::blob& b, bool copy) : BtreeIntervalKey() {
        TestIntervalKey const* other = r_cast< TestIntervalKey const* >(b.cbytes());
        m_base = other->m_base;
        m_offset = other->m_offset;
    }

    TestIntervalKey& operator=(TestIntervalKey const& other) {
        m_base = other.m_base;
        m_offset = other.m_offset;
        return *this;
    };
    virtual ~TestIntervalKey() = default;

    /////////////////// Overriding methods of BtreeKey /////////////////
    int compare(BtreeKey const& o) const override {
        TestIntervalKey const& other = s_cast< TestIntervalKey const& >(o);
        if (m_base < other.m_base) {
            return -1;
        } else if (m_base > other.m_base) {
            return 1;
        } else if (m_offset < other.m_offset) {
            return -1;
        } else if (m_offset > other.m_offset) {
            return 1;
        } else {
            return 0;
        }
    }

    sisl::blob serialize() const override {
        return sisl::blob{uintptr_cast(const_cast< TestIntervalKey* >(this)), uint32_cast(sizeof(TestIntervalKey))};
    }

    uint32_t serialized_size() const override { return sizeof(TestIntervalKey); }

    void deserialize(sisl::blob const& b, bool copy) override {
        assert(b.size() == sizeof(TestIntervalKey));
        TestIntervalKey const* other = r_cast< TestIntervalKey const* >(b.cbytes());
        m_base = other->m_base;
        m_offset = other->m_offset;
    }

    std::string to_string() const override { return fmt::format("{}", key()); }

    static uint32_t get_max_size() { return sizeof(TestIntervalKey); }

    static bool is_fixed_size() { return true; }

    static uint32_t get_fixed_size() { return sizeof(TestIntervalKey); }

    /////////////////// Overriding methods of BtreeIntervalKey /////////////////
    void shift(int n, void* app_ctx) override {
        if (willAdditionOverflow< uint32_t >(m_offset, n)) { m_base++; }
        m_offset += n;
    }

    int distance(BtreeKey const& f) const override {
        TestIntervalKey const& from = s_cast< TestIntervalKey const& >(f);
        uint64_t this_val = (uint64_cast(m_base) << 32) | m_offset;
        uint64_t from_val = (uint64_cast(from.m_base) << 32) | from.m_offset;
        DEBUG_ASSERT_GE(this_val, from_val, "Invalid from key for distance");
        return static_cast< int >(this_val - from_val);
    }

    bool is_interval_key() const override { return true; }

    sisl::blob serialize_prefix() const override {
        return sisl::blob{uintptr_cast(const_cast< uint32_t* >(&m_base)), uint32_cast(sizeof(uint32_t))};
    }

    sisl::blob serialize_suffix() const override {
        return sisl::blob{uintptr_cast(const_cast< uint32_t* >(&m_offset)), uint32_cast(sizeof(uint32_t))};
    }

    uint32_t serialized_prefix_size() const override { return uint32_cast(sizeof(uint32_t)); }

    uint32_t serialized_suffix_size() const override { return uint32_cast(sizeof(uint32_t)); };

    void deserialize(sisl::blob const& prefix, sisl::blob const& suffix, bool) {
        DEBUG_ASSERT_EQ(prefix.size(), sizeof(uint32_t), "Invalid prefix size on deserialize");
        DEBUG_ASSERT_EQ(suffix.size(), sizeof(uint32_t), "Invalid suffix size on deserialize");
        uint32_t const* other_p = r_cast< uint32_t const* >(prefix.cbytes());
        m_base = *other_p;

        uint32_t const* other_s = r_cast< uint32_t const* >(suffix.cbytes());
        m_offset = *other_s;
    }

    /////////////////// Local methods for helping tests //////////////////
    bool operator<(const TestIntervalKey& o) const { return (compare(o) < 0); }
    bool operator==(const TestIntervalKey& other) const { return (compare(other) == 0); }

    uint64_t key() const { return (uint64_cast(m_base) << 32) | m_offset; }
    uint64_t start_key(const BtreeKeyRange< TestIntervalKey >& range) const {
        const TestIntervalKey& k = (const TestIntervalKey&)(range.start_key());
        return k.key();
    }
    uint64_t end_key(const BtreeKeyRange< TestIntervalKey >& range) const {
        const TestIntervalKey& k = (const TestIntervalKey&)(range.end_key());
        return k.key();
    }
    friend std::ostream& operator<<(std::ostream& os, const TestIntervalKey& k) {
        os << k.to_string();
        return os;
    }

    friend std::istream& operator>>(std::istream& is, TestIntervalKey& k) {
        uint32_t m_base;
        uint32_t m_offset;
        char dummy;
        is >> m_base >> dummy >> m_offset;
        k = TestIntervalKey{m_base, m_offset};
        return is;
    }
};

class TestFixedValue : public BtreeValue {
private:
public:
    TestFixedValue(bnodeid_t val) { assert(0); }
    TestFixedValue(uint32_t val) : BtreeValue() { m_val = val; }
    TestFixedValue() : TestFixedValue((uint32_t)-1) {}
    TestFixedValue(const TestFixedValue& other) : BtreeValue() { m_val = other.m_val; };
    TestFixedValue(const sisl::blob& b, bool copy) : BtreeValue() { m_val = *(r_cast< uint32_t const* >(b.cbytes())); }
    virtual ~TestFixedValue() = default;

    static TestFixedValue generate_rand() { return TestFixedValue{g_randval_generator(g_re)}; }
    static TestFixedValue zero() { return TestFixedValue{uint32_t(0)}; }

    TestFixedValue& operator=(const TestFixedValue& other) {
        m_val = other.m_val;
        return *this;
    }

    sisl::blob serialize() const override {
        sisl::blob b{r_cast< uint8_t const* >(&m_val), uint32_cast(sizeof(m_val))};
        return b;
    }

    uint32_t serialized_size() const override { return sizeof(m_val); }
    static uint32_t get_fixed_size() { return sizeof(m_val); }
    void deserialize(const sisl::blob& b, bool copy) { m_val = *(r_cast< uint32_t const* >(b.cbytes())); }

    std::string to_string() const override { return fmt::format("{}", m_val); }

    friend std::ostream& operator<<(std::ostream& os, const TestFixedValue& v) {
        os << v.to_string();
        return os;
    }

    friend std::istream& operator>>(std::istream& is, TestFixedValue& v) {
        uint32_t value;
        is >> value;
        v = TestFixedValue{value};
        return is;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const TestFixedValue& other) const { return (m_val == other.m_val); }

    uint32_t value() const { return m_val; }

private:
    uint32_t m_val;
};

class TestVarLenValue : public BtreeValue {
private:
    static uint32_t rand_val_size() {
        return (uint32_cast(std::abs(std::round(g_randvalsize_generator(g_re)))) % g_max_valsize) + 1;
    }

public:
    TestVarLenValue(bnodeid_t val) { assert(0); }
    TestVarLenValue(const std::string& val) : BtreeValue(), m_val{val} {}
    TestVarLenValue() = default;
    TestVarLenValue(const TestVarLenValue& other) : BtreeValue() { m_val = other.m_val; };
    TestVarLenValue(const sisl::blob& b, bool copy) :
            BtreeValue(), m_val{std::string((const char*)b.cbytes(), b.size())} {}
    virtual ~TestVarLenValue() = default;

    TestVarLenValue& operator=(const TestVarLenValue& other) {
        m_val = other.m_val;
        return *this;
    }

    static TestVarLenValue generate_rand() { return TestVarLenValue{gen_random_string(rand_val_size())}; }
    static TestVarLenValue zero() { return TestVarLenValue{""}; }

    sisl::blob serialize() const override {
        sisl::blob b{r_cast< const uint8_t* >(m_val.c_str()), uint32_cast(m_val.size())};
        return b;
    }

    uint32_t serialized_size() const override { return (uint32_t)m_val.size(); }
    static uint32_t get_fixed_size() { return 0; }

    void deserialize(const sisl::blob& b, bool copy) { m_val = std::string((const char*)b.cbytes(), b.size()); }

    std::string to_string() const override { return fmt::format("{}", m_val); }

    friend std::ostream& operator<<(std::ostream& os, const TestVarLenValue& v) {
        os << v.to_string();
        return os;
    }

    friend std::istream& operator>>(std::istream& is, TestVarLenValue& v) {
        std::string value;
        is >> value;
        v = TestVarLenValue{value};
        return is;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const TestVarLenValue& other) const { return (m_val == other.m_val); }

    std::string value() const { return m_val; }

private:
    std::string m_val;
};

class TestIntervalValue : public BtreeIntervalValue {
private:
#pragma pack(1)
    uint32_t m_base_val{0};
    uint16_t m_offset{0};
#pragma pack()

public:
    TestIntervalValue(bnodeid_t val) { assert(0); }
    TestIntervalValue(uint32_t val, uint16_t o) : BtreeIntervalValue(), m_base_val{val}, m_offset{o} {}
    TestIntervalValue() = default;
    TestIntervalValue(const TestIntervalValue& other) :
            BtreeIntervalValue(), m_base_val{other.m_base_val}, m_offset{other.m_offset} {}
    TestIntervalValue(const sisl::blob& b, bool copy) : BtreeIntervalValue() { this->deserialize(b, copy); }
    virtual ~TestIntervalValue() = default;

    static TestIntervalValue generate_rand() {
        return TestIntervalValue{g_randval_generator(g_re), s_cast< uint16_t >(0)};
    }
    static TestIntervalValue zero() { return TestIntervalValue{0, 0}; }

    ///////////////////////////// Overriding methods of BtreeValue //////////////////////////
    TestIntervalValue& operator=(const TestIntervalValue& other) = default;
    sisl::blob serialize() const override {
        sisl::blob b{r_cast< uint8_t const* >(this), sizeof(TestIntervalValue)};
        return b;
    }

    uint32_t serialized_size() const override { return sizeof(TestIntervalValue); }
    static uint32_t get_fixed_size() { return sizeof(TestIntervalValue); }
    void deserialize(const sisl::blob& b, bool) {
        TestIntervalValue const* other = r_cast< TestIntervalValue const* >(b.cbytes());
        m_base_val = other->m_base_val;
        m_offset = other->m_offset;
    }

    std::string to_string() const override { return fmt::format("{}", value()); }
    uint64_t value() const { return (uint64_cast(m_base_val) << 16) | m_offset; }

    friend std::ostream& operator<<(std::ostream& os, const TestIntervalValue& v) {
        os << v.to_string();
        return os;
    }

    friend std::istream& operator>>(std::istream& is, TestIntervalValue& v) {
        uint32_t m_base_val;
        uint16_t m_offset;
        char dummy;
        is >> m_base_val >> dummy >> m_offset;
        v = TestIntervalValue{m_base_val, m_offset};
        return is;
    }

    ///////////////////////////// Overriding methods of BtreeIntervalValue //////////////////////////
    void shift(int n, void* app_ctx) override {
        if (willAdditionOverflow< uint32_t >(m_offset, n)) { m_base_val++; }
        m_offset += n;
    }

    sisl::blob serialize_prefix() const override {
        return sisl::blob{uintptr_cast(const_cast< uint32_t* >(&m_base_val)), uint32_cast(sizeof(uint32_t))};
    }
    sisl::blob serialize_suffix() const override {
        return sisl::blob{uintptr_cast(const_cast< uint16_t* >(&m_offset)), uint32_cast(sizeof(uint16_t))};
    }
    uint32_t serialized_prefix_size() const override { return uint32_cast(sizeof(uint32_t)); }
    uint32_t serialized_suffix_size() const override { return uint32_cast(sizeof(uint16_t)); }

    void deserialize(sisl::blob const& prefix, sisl::blob const& suffix, bool) override {
        DEBUG_ASSERT_EQ(prefix.size(), sizeof(uint32_t), "Invalid prefix size on deserialize");
        DEBUG_ASSERT_EQ(suffix.size(), sizeof(uint16_t), "Invalid suffix size on deserialize");
        m_base_val = *(r_cast< uint32_t const* >(prefix.cbytes()));
        m_offset = *(r_cast< uint16_t const* >(suffix.cbytes()));
    }

    bool operator==(TestIntervalValue const& other) const {
        return ((m_base_val == other.m_base_val) && (m_offset == other.m_offset));
    }
};
