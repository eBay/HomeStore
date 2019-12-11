//
// Created by Kuang Yaming
//

#pragma once 

#include <climits>
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

namespace homeds {
namespace loadgen {
       
class VDevValue : public ValueSpec {

public:
    static std::shared_ptr<  VDevValue > gen_value(ValuePattern spec, VDevValue* ref_value = nullptr) {
        size_t        size = 512;
        
        VDevValue     val;

        switch (spec) {
            case ValuePattern::RANDOM_BYTES:
                val.m_bytes.clear();
                gen_random_string(val.m_bytes, size);
                assert(val.m_bytes.size() == size);
                break;

            default:
                // We do not support other gen spec yet
                assert(0);
                break;
        }

        std::shared_ptr< VDevValue > temp = std::make_shared< VDevValue >(val);
        return temp;
    }

    ~VDevValue() {
        // m_bytes will be freed by homestore I/O path;
    }

    VDevValue() { }

    VDevValue(const VDevValue& other) { copy_blob(other.get_blob()); }

    void copy_blob(const homeds::blob& b) {
        m_bytes.clear();
        for (size_t i = 0; i < b.size; i++) {
            m_bytes.push_back(b.bytes[i]);
        }
        assert(m_bytes.size() == b.size);
    }

    std::string to_string() const { return std::string((const char*)&m_bytes[0]); }

    friend ostream& operator<<(ostream& os, const VDevValue& v) {
        os << "val = " << (uint8_t*)&(v.m_bytes[0]);
        return os;
    }

    homeds::blob get_blob() const {
        homeds::blob b;
        b.bytes = (uint8_t*)&m_bytes[0];
        b.size = m_bytes.size();
        return b;
    }

    bool operator==(const VDevValue& other) const {
        return std::strcmp((char*)&m_bytes[0], (char*)other.get_blob().bytes) == 0;
    }

    virtual uint64_t get_hash_code() {
        homeds::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

    uint8_t* get_buf() { return &m_bytes[0]; }
    
    size_t get_size() { return m_bytes.size(); }

    void update_value(size_t size) {
        m_bytes.clear();
        gen_random_string(m_bytes, size);
        assert(m_bytes.size() == size);
    }

private:
    std::vector< uint8_t > m_bytes;
};
} 
} // namespace homeds::loadgen
