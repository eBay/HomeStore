#ifndef HOMESTORE_BTREE_VAR_KEY_SPEC_HPP
#define HOMESTORE_BTREE_VAR_KEY_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <sstream>
#include <string>

#include <fmt/ostream.h>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"

namespace homeds {
namespace loadgen {
class VarBytesKey : public homeds::btree::BtreeKey, public KeySpec {
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
        return (compare((const BtreeKey*)&(VarBytesKey&)other) == 0);
    }

    int compare(const BtreeKey* o) const override {
        VarBytesKey* other = (VarBytesKey*)o;
        if (m_num < other->m_num) {
            return -1;
        } else if (m_num > other->m_num) {
            return 1;
        } else {
            return 0;
        }
    }

    int compare_range(const homeds::btree::BtreeSearchRange& range) const override {
        auto other_start = (VarBytesKey*)range.get_start_key();
        auto other_end = (VarBytesKey*)range.get_end_key();

        assert(0); // Do not support it yet
        return 0;
    }

    virtual sisl::blob get_blob() const {
        sisl::blob b = {(uint8_t*)&m_num, sizeof(uint64_t)};
        return b;
    };

    virtual void set_blob(const sisl::blob& b) {
        auto n = *((uint64_t*)b.bytes);
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
        VarBytesKey* nk = (VarBytesKey*)&k;
        if (m_num + 1 == nk->m_num)
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
#endif // HOMESTORE_BTREE_KEY_SPEC_HPP
