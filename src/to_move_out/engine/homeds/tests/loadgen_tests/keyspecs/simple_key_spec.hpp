//
// Created by Kadayam, Hari on 3/28/19.
//

#ifndef HOMESTORE_BTREE_KEY_SPEC_HPP
#define HOMESTORE_BTREE_KEY_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <functional>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"

namespace homeds {
namespace loadgen {
class SimpleNumberKey : public homeds::btree::BtreeKey, public KeySpec {
    friend struct std::hash< SimpleNumberKey >;

private:
    uint64_t m_num;

public:
    static SimpleNumberKey generate_random_key() {
        /* Seed */
        static thread_local std::random_device rd{};

        /* Random number generator */
        static thread_local std::default_random_engine generator{rd()};

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution< uint64_t > distribution{0, KeySpec::MAX_KEYS};

        const auto num{distribution(generator)};
        return SimpleNumberKey{num};
    }

    static SimpleNumberKey gen_key(const KeyPattern spec, const SimpleNumberKey* const ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL:
            return ref_key ? SimpleNumberKey{ref_key->to_integer() + 1} : SimpleNumberKey{};

        case KeyPattern::UNI_RANDOM:
            return generate_random_key();

        case KeyPattern::OUT_OF_BOUND:
            return SimpleNumberKey{std::numeric_limits< uint64_t >::max()};

        default:
            // We do not support other gen spec yet
            assert(false);
            return SimpleNumberKey{};
        }
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return sizeof(uint64_t); }

    explicit SimpleNumberKey(const uint64_t num = 0) : m_num{num} {}

    SimpleNumberKey(const SimpleNumberKey& other) = default;
    SimpleNumberKey& operator=(const SimpleNumberKey& rhs) = default;
    SimpleNumberKey(SimpleNumberKey&& other) noexcept = default;
    SimpleNumberKey& operator=(SimpleNumberKey&& rhs) noexcept = default;

    virtual ~SimpleNumberKey() override = default;

    static constexpr size_t get_fixed_size() { return sizeof(uint64_t); }
    uint64_t to_integer() const { return m_num; }

    virtual bool operator==(const KeySpec& other) const override {
#ifdef NDEBUG
        const SimpleNumberKey& simple_key{reinterpret_cast< const SimpleNumberKey& >(other)};
#else
        const SimpleNumberKey& simple_key{dynamic_cast< const SimpleNumberKey& >(other)};
#endif
        return (compare(static_cast< const BtreeKey* >(&simple_key)) == 0);
    }

    int compare(const BtreeKey* const o) const override {
#ifdef NDEBUG
        const SimpleNumberKey* other{reinterpret_cast< const SimpleNumberKey* >(o)};
#else
        const SimpleNumberKey* other{dynamic_cast< const SimpleNumberKey* >(o)};
#endif
        if (m_num < other->m_num) {
            return -1;
        } else if (m_num > other->m_num) {
            return 1;
        } else {
            return 0;
        }
    }

    int compare_range(const homeds::btree::BtreeSearchRange& range) const override {
        const auto other_start{range.get_start_key()};
        const auto other_end{range.get_end_key()};

        assert(false); // Do not support it yet
        return 0;
    }

    virtual sisl::blob get_blob() const {
        // this assume that endian ordering is the same for all operations
        sisl::blob b{reinterpret_cast< uint8_t* >(const_cast< uint64_t* >(&m_num)), sizeof(uint64_t)};
        return b;
    };

    virtual void set_blob(const sisl::blob& b) {
        // this assume that endian ordering is the same for all operations
        const auto n{*(reinterpret_cast< const uint64_t* >(b.bytes))};
        m_num = n;
    }
    virtual void copy_blob(const sisl::blob& b) { set_blob(b); }

    virtual uint32_t get_blob_size() const { return sizeof(uint64_t); }
    virtual void set_blob_size(const uint32_t size) {}
    virtual std::string to_string() const { return std::to_string(m_num); }

    static void gen_keys_in_range(SimpleNumberKey& k1, uint32_t num_of_keys,
                                  std::vector< SimpleNumberKey > keys_inrange) {
        assert(false);
    }

    virtual bool is_consecutive(const KeySpec& k) const override {
#ifdef NDEBUG
        const SimpleNumberKey& simple_key{reinterpret_cast< const SimpleNumberKey& >(k)};
#else
        const SimpleNumberKey& simple_key{dynamic_cast< const SimpleNumberKey& >(k)};
#endif
        if (m_num + 1 == simple_key.m_num)
            return true;
        else
            return false;
    }
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const SimpleNumberKey& key) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << key.to_string();
    outStream << outStringStream.str();

    return outStream;
}

class CompositeNumberKey : public homeds::btree::BtreeKey, public KeySpec {
private:
    static constexpr uint64_t s_count_mask{(static_cast< uint64_t >(1) << 16) - 1};
    static constexpr uint64_t s_rank_mask{(static_cast< uint64_t >(1) << 10) - 1};
    static constexpr uint64_t s_blk_num_mask{(static_cast< uint64_t >(1) << 38) - 1};

#pragma pack(1)
    typedef struct {
        // if these did not add to 64 there would be issues with the use of blobs
        uint64_t m_count : 16;
        uint64_t m_rank : 10;
        uint64_t m_blk_num : 38;
    } attr_t;
#pragma pack()

    attr_t* m_attr;
    attr_t m_inplace_attr;

public:
    static CompositeNumberKey generate_random_key() {
        /* Seed */
        static thread_local std::random_device rd{};

        /* Random number generator */
        static thread_local std::default_random_engine generator{rd()};

        /* Distribution on which to apply the generator */
        std::uniform_int_distribution< uint64_t > distribution{0, KeySpec::MAX_KEYS};

        const auto num{distribution(generator)};
        return CompositeNumberKey{num};
    }

    static CompositeNumberKey gen_key(const KeyPattern spec, const CompositeNumberKey* const ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL:
            assert(ref_key != nullptr);
            return CompositeNumberKey{ref_key->to_integer() + 1};

        case KeyPattern::UNI_RANDOM:
            return generate_random_key();

        case KeyPattern::OUT_OF_BOUND:
            return CompositeNumberKey{std::numeric_limits< uint64_t >::max()};

        default:
            // We do not support other gen spec yet
            assert(false);
            return CompositeNumberKey{};
        }
    }

    virtual bool is_consecutive(const KeySpec& k) const override {
#ifdef NDEBUG
        [[maybe_unused]] const CompositeNumberKey& composite_key{reinterpret_cast< const CompositeNumberKey& >(k)};
#else
        [[maybe_unused]] const CompositeNumberKey& composite_key{dynamic_cast< const CompositeNumberKey& >(k)};
#endif
        assert(false); // to implement
        return false;
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return sizeof(attr_t); }

    CompositeNumberKey(const uint32_t count, const uint16_t rank, const uint64_t blk_num) {
        m_attr = &m_inplace_attr;
        set_count(count);
        set_rank(rank);
        set_blk_num(blk_num);
    }

    CompositeNumberKey() : CompositeNumberKey{0, 0, 0} {}

    CompositeNumberKey(const CompositeNumberKey& other) :
            CompositeNumberKey{other.get_count(), other.get_rank(), other.get_blk_num()} {}

    CompositeNumberKey& operator=(const CompositeNumberKey& rhs) {
        if (this != &rhs) {
            m_inplace_attr.m_count = rhs.m_inplace_attr.m_count;
            m_inplace_attr.m_rank = rhs.m_inplace_attr.m_rank;
            m_inplace_attr.m_blk_num = rhs.m_inplace_attr.m_blk_num;
            m_attr = &m_inplace_attr;
        }
        return *this;
    }

    CompositeNumberKey(CompositeNumberKey&& other) noexcept :
            CompositeNumberKey{other.get_count(), other.get_rank(), other.get_blk_num()} {}

    CompositeNumberKey& operator=(CompositeNumberKey&& rhs) noexcept {
        if (this != &rhs) {
            m_inplace_attr.m_count = rhs.m_inplace_attr.m_count;
            m_inplace_attr.m_rank = rhs.m_inplace_attr.m_rank;
            m_inplace_attr.m_blk_num = rhs.m_inplace_attr.m_blk_num;
            m_attr = &m_inplace_attr;
        }
        return *this;
    }

    explicit CompositeNumberKey(const uint64_t num) {
        m_attr = &m_inplace_attr;
        set_count(static_cast< uint32_t >(num & s_count_mask));
        set_rank(static_cast< uint16_t >((num >> 16) & s_rank_mask));
        set_blk_num((num >> (16 + 10)) & s_blk_num_mask);
    }

    virtual ~CompositeNumberKey() override = default;

    uint32_t get_count() const { return (m_attr->m_count); }
    uint16_t get_rank() const { return (m_attr->m_rank); }
    uint64_t get_blk_num() const { return (m_attr->m_blk_num); }
    void set_count(const uint32_t count) { m_attr->m_count = count; }
    void set_rank(const uint32_t rank) { m_attr->m_rank = rank; }
    void set_blk_num(const uint64_t blkNum) { m_attr->m_blk_num = blkNum; }
    uint64_t to_integer() const {
        const uint64_t val{m_inplace_attr.m_count | (m_inplace_attr.m_rank << 16) |
                           (m_inplace_attr.m_blk_num << (16 + 10))};
        return val;
    }

    virtual bool operator==(const KeySpec& rhs) const override {
#ifdef NDEBUG
        const CompositeNumberKey& composite_key{reinterpret_cast< const CompositeNumberKey& >(rhs)};
#else
        const CompositeNumberKey& composite_key{dynamic_cast< const CompositeNumberKey& >(rhs)};
#endif
        return (compare(static_cast< const BtreeKey* >(&composite_key)) == 0);
    }

    int compare(const BtreeKey* const o) const override {
        // this is hokey down casting
#ifdef NDEBUG
        const CompositeNumberKey* other{reinterpret_cast< const CompositeNumberKey* >(o)};
#else
        const CompositeNumberKey* other{dynamic_cast< const CompositeNumberKey* >(o)};
#endif
        if (get_count() < other->get_count()) {
            return -1;
        } else if (get_count() > other->get_count()) {
            return 1;
        } else if (get_rank() < other->get_rank()) {
            return -1;
        } else if (get_rank() > other->get_rank()) {
            return 1;
        } else if (get_blk_num() < other->get_blk_num()) {
            return -1;
        } else if (get_blk_num() > other->get_blk_num()) {
            return 1;
        } else {
            return 0;
        }
    }

    int compare_range(const homeds::btree::BtreeSearchRange& range) const override {
        const auto other_start{range.get_start_key()};
        const auto other_end{range.get_end_key()};

        assert(false); // Do not support it yet
        return 0;
    }

    int is_in_range(const uint64_t val, const uint64_t start, const bool start_incl, const uint64_t end,
                    const bool end_incl) const {
        if (val < start) {
            return 1;
        } else if ((val == start) && (!start_incl)) {
            return 1;
        } else if (val > end) {
            return -1;
        } else if ((val == end) && (!end_incl)) {
            return -1;
        } else {
            return 0;
        }
    }

    int compare_range(const BtreeKey* const s, const bool start_incl, const BtreeKey* const e, const bool end_incl) {
        // this is hokey down casting
#ifdef NDEBUG
        const CompositeNumberKey* start{reinterpret_cast< const CompositeNumberKey* >(s)};
        const CompositeNumberKey* end{reinterpret_cast< const CompositeNumberKey* >(e)};
#else
        const CompositeNumberKey* start{dynamic_cast< const CompositeNumberKey* >(e)};
        const CompositeNumberKey* end{dynamic_cast< const CompositeNumberKey* >(e)};
#endif

        int ret{is_in_range(this->get_count(), start->get_count(), start_incl, end->get_count(), end_incl)};
        if (ret != 0) { return ret; }

        ret = is_in_range(this->get_rank(), start->get_rank(), start_incl, end->get_rank(), end_incl);
        if (ret != 0) { return ret; }

        ret = is_in_range(this->get_blk_num(), start->get_blk_num(), start_incl, end->get_blk_num(), end_incl);
        if (ret != 0) { return ret; }

        return 0;
    }

    virtual sisl::blob get_blob() const override {
        // this assumes same endianess on all operations
        sisl::blob b{reinterpret_cast< uint8_t* >(m_attr), sizeof(attr_t)};
        return b;
    }

    virtual void set_blob(const sisl::blob& b) override {
        // this assumes same endianess on all operations
        m_inplace_attr = *reinterpret_cast< attr_t* >(b.bytes);
    }
    virtual void copy_blob(const sisl::blob& b) override {
        // this assumes same endianess on all operations
        set_blob(b);
    }
    virtual uint32_t get_blob_size() const override { return (sizeof(attr_t)); }

    static uint32_t get_fixed_size() { return (sizeof(attr_t)); }
    virtual void set_blob_size(const uint32_t size) override {}

    std::string to_string() const {
        std::ostringstream ss;
        ss << "count: " << get_count() << " rank: " << get_rank() << " blknum: " << get_blk_num();
        return ss.str();
    }

    bool operator<(const CompositeNumberKey& o) const { return (compare(&o) < 0); }
    bool operator==(const CompositeNumberKey& other) const { return (compare(&other) == 0); }
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const CompositeNumberKey& key) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << key.to_string();
    outStream << outStringStream.str();

    return outStream;
}

} // namespace loadgen
} // namespace homeds

// hash function definitions
namespace std {
template <>
struct hash< homeds::loadgen::SimpleNumberKey > {
    typedef homeds::loadgen::SimpleNumberKey argument_type;
    typedef size_t result_type;
    result_type operator()(const argument_type& simple_key) const noexcept {
        return std::hash< uint64_t >()(simple_key.m_num);
    }
};

template <>
struct hash< homeds::loadgen::CompositeNumberKey > {
    typedef homeds::loadgen::CompositeNumberKey argument_type;
    typedef size_t result_type;
    result_type operator()(const argument_type& composite_key) const noexcept {
        return std::hash< uint64_t >()(composite_key.to_integer());
    }
};

} // namespace std

#endif // HOMESTORE_BTREE_KEY_SPEC_HPP
