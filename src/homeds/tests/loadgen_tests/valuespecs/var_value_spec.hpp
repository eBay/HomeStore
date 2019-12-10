//
// Created by Kadayam, Hari on 3/28/19.
//

#ifndef HOMESTORE_BTREE_VAR_VALUE_SPEC_HPP
#define HOMESTORE_BTREE_VAR_VALUE_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

namespace homeds {
namespace loadgen {

template < size_t Max_Size >
class VarBytesValue : public homeds::btree::BtreeValue, public ValueSpec {
public:
    static std::shared_ptr< VarBytesValue <Max_Size> > gen_value(ValuePattern spec, 
                                       VarBytesValue< Max_Size >* ref_value = nullptr) {
        VarBytesValue val;
        size_t        size = 0;
        while (size < 8) {
            size = rand() % Max_Size;
        }
        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            val.m_bytes.clear();
            gen_random_string(val.m_bytes, size);
            assert(val.m_bytes.size() == size);
            break;
        default:
            // We do not support other gen spec yet
            assert(0);
        }
        std::shared_ptr< VarBytesValue <Max_Size> > temp = std::make_shared< VarBytesValue <Max_Size> >(val);
        return temp;
    }

    static constexpr bool     is_fixed_size() { return false; }
    static constexpr uint32_t get_max_size() { return Max_Size; }

    VarBytesValue() : homeds::btree::BtreeValue() { m_bytes_ptr = &m_bytes[0]; }

    VarBytesValue(const char* bytes) : VarBytesValue() {
        if (bytes) {
            memcpy((uint8_t*)&m_bytes[0], bytes, Max_Size);
        }
    }
    VarBytesValue(const VarBytesValue& other) { copy_blob(other.get_blob()); }
    VarBytesValue& operator=(const VarBytesValue& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.bytes = (uint8_t*)&m_bytes[0];
        b.size = m_bytes.size();
        return b;
    }

    void set_blob(const homeds::blob& b) override { copy_blob(b); }
    void copy_blob(const homeds::blob& b) override {
        // memcpy((uint8_t*)&m_bytes[0], b.bytes, b.size);
        m_bytes.clear();
        for (size_t i = 0; i < b.size; i++) {
            m_bytes.push_back(b.bytes[i]);
        }
        assert(m_bytes.size() == b.size);
    }
    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { copy_blob(new_val.get_blob()); }
    uint32_t        get_blob_size() const override { return m_bytes.size(); }
    void            set_blob_size(uint32_t size) override { assert(size == sizeof(m_bytes.size())); }
    uint32_t        estimate_size_after_append(const BtreeValue& new_val) override { return m_bytes.size(); }
    static uint32_t get_fixed_size() {
        assert(0);
        return 0;
    }
    std::string to_string() const { return std::string((const char*)&m_bytes[0]); }

    friend ostream& operator<<(ostream& os, const VarBytesValue& v) {
        os << "val = " << (uint8_t*)&(v.m_bytes[0]);
        return os;
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const VarBytesValue& other) const {
        return std::strcmp((char*)&m_bytes[0], (char*)other.get_blob().bytes) == 0;
    }

    virtual uint64_t get_hash_code() override {
        homeds::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

    void set_bytes_ptr() { m_bytes_ptr = &m_bytes[0]; }

private:
    uint8_t*               m_bytes_ptr = nullptr;
    std::vector< uint8_t > m_bytes;
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_BTREE_VALUE_SPEC_HPP
