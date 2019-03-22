//
// Created by Kadayam, Hari on 3/11/19.
//

#ifndef HOMESTORE_VALUE_SPEC_HPP
#define HOMESTORE_VALUE_SPEC_HPP

#include "../loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include <farmhash.h>

namespace homeds {
namespace loadgen {

void gen_random_string(uint8_t *s, const size_t len) {
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    for (size_t i = 0u; i < len-1; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    s[len-1] = 0;
}

template < size_t Size >
class FixedBytesValue : public homeds::btree::BtreeValue {
public:
    static FixedBytesValue<Size> gen_value(ValuePattern spec, FixedBytesValue<Size>* ref_value = nullptr) {
        FixedBytesValue val;
        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            gen_random_string(val.m_bytes_ptr, Size);
            return val;

        default:
            // We do not support other gen spec yet
            assert(0);
        }
        return val;
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return Size; }

    FixedBytesValue() : homeds::btree::BtreeValue() { m_bytes_ptr = &m_bytes[0]; }

    FixedBytesValue(const char* bytes) : FixedBytesValue() {
        if (bytes) {
            memcpy(m_bytes_ptr, bytes, Size);
        }
    }
    FixedBytesValue(const FixedBytesValue& other) { copy_blob(other.get_blob()); }
    FixedBytesValue& operator=(const FixedBytesValue& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.bytes = m_bytes_ptr;
        b.size = Size;
        return b;
    }

    void set_blob(const homeds::blob& b) override { m_bytes_ptr = b.bytes; }
    void copy_blob(const homeds::blob& b) override { memcpy(m_bytes_ptr, b.bytes, b.size); }
    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { copy_blob(new_val.get_blob()); }
    uint32_t        get_blob_size() const override { return Size; }
    void            set_blob_size(uint32_t size) override { assert(size == sizeof(Size)); }
    uint32_t        estimate_size_after_append(const BtreeValue& new_val) override { return Size; }
    static uint32_t get_fixed_size() { return Size; }
    std::string     to_string() const { return std::string((const char *)m_bytes_ptr); }

    friend ostream& operator<<(ostream& os, const FixedBytesValue& v) {
        os << "val = " << v.m_bytes_ptr;
        return os;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const FixedBytesValue& other) const {
        return (memcpy(m_bytes_ptr, other.get_blob().m_bytes, Size) == 0);
    }

    static uint64_t hash_code(const FixedBytesValue& value) {
        homeds::blob b = value.get_blob();
        return util::Hash64((const char *)b.bytes, (size_t)b.size);
    }

private:
    uint8_t* m_bytes_ptr;
    uint8_t  m_bytes[Size];
};
} } // namespace homeds::loadgen
#endif // HOMESTORE_VALUE_SPEC_HPP
