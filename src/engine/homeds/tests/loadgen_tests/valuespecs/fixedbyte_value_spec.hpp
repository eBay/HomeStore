//
// Created by Kadayam, Hari on 3/28/19.
//

#ifndef HOMESTORE_BTREE_VALUE_SPEC_HPP
#define HOMESTORE_BTREE_VALUE_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

namespace homeds {
namespace loadgen {

template < size_t Size >
class FixedBytesValue : public homeds::btree::BtreeValue, public ValueSpec {
public:
    static std::shared_ptr< FixedBytesValue< Size > > gen_value(ValuePattern spec,
                                                                FixedBytesValue< Size >* ref_value = nullptr) {
        FixedBytesValue val;
        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            gen_random_string(val.m_bytes, Size);
            break;

        default:
            // We do not support other gen spec yet
            assert(0);
        }

        std::shared_ptr< FixedBytesValue< Size > > temp = std::make_shared< FixedBytesValue >(val);
        return temp;
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return Size; }

    FixedBytesValue() : homeds::btree::BtreeValue() { m_bytes_ptr = &m_bytes[0]; }

    FixedBytesValue(const char* bytes) : FixedBytesValue() {
        if (bytes) { memcpy(m_bytes, bytes, Size); }
    }
    FixedBytesValue(const FixedBytesValue& other) { copy_blob(other.get_blob()); }
    FixedBytesValue& operator=(const FixedBytesValue& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    sisl::blob get_blob() const override {
        sisl::blob b;
        b.bytes = (uint8_t*)m_bytes;
        b.size = Size;
        return b;
    }

    void set_blob(const sisl::blob& b) override { copy_blob(b); }
    void copy_blob(const sisl::blob& b) override { memcpy(m_bytes, b.bytes, b.size); }
    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { copy_blob(new_val.get_blob()); }
    uint32_t get_blob_size() const override { return Size; }
    void set_blob_size(uint32_t size) override { assert(size == sizeof(Size)); }
    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return Size; }
    static uint32_t get_fixed_size() { return Size; }
    std::string to_string() const { return std::string((const char*)m_bytes); }

    friend ostream& operator<<(ostream& os, const FixedBytesValue& v) {
        os << "val = " << v.m_bytes;
        return os;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const FixedBytesValue& other) const {
        return (memcpy(m_bytes, other.get_blob().m_bytes, Size) == 0);
    }

    virtual uint64_t get_hash_code() override {
        sisl::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

private:
    uint8_t* m_bytes_ptr;
    uint8_t m_bytes[Size];
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_BTREE_VALUE_SPEC_HPP
