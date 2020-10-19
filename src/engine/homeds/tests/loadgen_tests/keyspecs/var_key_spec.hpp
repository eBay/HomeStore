#ifndef HOMESTORE_BTREE_VAR_KEY_SPEC_HPP
#define HOMESTORE_BTREE_VAR_KEY_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <functional>
#include <sstream>
#include <string>

#include <fmt/ostream.h>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"

namespace homeds {
namespace loadgen {
class VarBytesKey : public homeds::btree::BtreeKey, public KeySpec {
    friend struct std::hash< VarBytesKey >;

private:
    uint64_t m_num;

public:
    static VarBytesKey gen_key(KeyPattern spec, VarBytesKey* ref_key = nullptr) {
        switch (spec) {
        case KeyPattern::SEQUENTIAL:
            return ref_key ? VarBytesKey(ref_key->to_integer() + 1) : VarBytesKey();

        case KeyPattern::UNI_RANDOM:
            return VarBytesKey(rand());

        case KeyPattern::OUT_OF_BOUND:
            return VarBytesKey((uint64_t)-1);

        default:
            // We do not support other gen spec yet
            assert(0);
            return VarBytesKey();
        }
    }

    static constexpr bool is_fixed_size() { return false; }
    static constexpr uint32_t get_max_size() { return sizeof(uint64_t); }

    explicit VarBytesKey(uint64_t num = 0) : m_num(num) {}
    VarBytesKey(const VarBytesKey& other) = default;
    VarBytesKey& operator=(const VarBytesKey& other) = default;

    static constexpr size_t get_fixed_size() { return sizeof(uint64_t); }
    uint64_t to_integer() const { return m_num; }

    virtual bool operator==(const KeySpec& other) const override {
        // this is hokey down casting
#ifdef NDEBUG
        const VarBytesKey& var_key{reinterpret_cast< const VarBytesKey& >(other)};
#else
        const VarBytesKey& var_key{dynamic_cast< const VarBytesKey& >(other)};
#endif
        return (compare(static_cast<const BtreeKey*>(&var_key)) == 0);
    }

    int compare(const BtreeKey* o) const override {
        // this is hokey down casting
#ifdef NDEBUG
        const VarBytesKey* other{reinterpret_cast< const VarBytesKey* >(o)};
#else
        const VarBytesKey* other{dynamic_cast< const VarBytesKey* >(o)};
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
        auto other_start = range.get_start_key();
        auto other_end = range.get_end_key();

        assert(0); // Do not support it yet
        return 0;
    }

    virtual sisl::blob get_blob() const {
        // this assumes endianess is same on systems
        sisl::blob b{reinterpret_cast<uint8_t*>(const_cast<uint64_t*>(&m_num)), sizeof(uint64_t)};
        return b;
    };

    virtual void set_blob(const sisl::blob& b) {
        // this assumes endianess is same on systems
        const auto n{*reinterpret_cast<uint64_t*>(b.bytes)};
        m_num = n;
    }
    virtual void copy_blob(const sisl::blob& b) { set_blob(b); }

    virtual uint32_t get_blob_size() const { return sizeof(uint64_t); }
    virtual void set_blob_size(uint32_t size) {}
    virtual std::string to_string() const { return std::to_string(m_num); }

    static void gen_keys_in_range(VarBytesKey& k1, uint32_t num_of_keys, std::vector< VarBytesKey > keys_inrange) {
        assert(0);
    }

    virtual bool is_consecutive(KeySpec& k) override {
        // this is hokey downcasting
#ifdef NDEBUG
        const VarBytesKey& var_key{reinterpret_cast< const VarBytesKey& >(k)};
#else
        const VarBytesKey& var_key{dynamic_cast< const VarBytesKey& >(k)};
#endif
        if (m_num + 1 == var_key.m_num)
            return true;
        else
            return false;
    }
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const VarBytesKey& key) {
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
struct hash< homeds::loadgen::VarBytesKey > {
    typedef homeds::loadgen::VarBytesKey argument_type;
    typedef size_t result_type;
    result_type operator()(const argument_type& var_key) const noexcept {
        return std::hash< uint64_t >()(var_key.m_num);
    }
};
} // namespace std

#endif // HOMESTORE_BTREE_KEY_SPEC_HPP
