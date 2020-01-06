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
        VDevValue     val;

        switch (spec) {
            case ValuePattern::RANDOM_BYTES:
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
        // buf won't be freed by homestore i/o path because vdev test doesn't involve cache layer.
        // in which cache layer will free the memory when cache is evicted or removed.
        free(m_bytes);
    }

    VDevValue() { }

    VDevValue(const VDevValue& other) { }
#if 0
    void copy_blob(const homeds::blob& b) {
        for (size_t i = 0; i < b.size; i++) {
            m_bytes[i] = b.bytes[i];
        }
    }

    std::string to_string() const { return std::string((const char*)m_bytes); }

    friend ostream& operator<<(ostream& os, const VDevValue& v) {
        os << "val = " << (uint8_t*)v.m_bytes;
        return os;
    }
    bool operator==(const VDevValue& other) const {
        return std::strcmp((char*)&m_bytes[0], (char*)other.get_blob().bytes) == 0;
    }

#endif

    homeds::blob get_blob() const {
        homeds::blob b;
        b.bytes = (uint8_t*)m_bytes;
        b.size = m_size;
        return b;
    }

    virtual uint64_t get_hash_code() {
        homeds::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

    uint8_t* get_buf() { return m_bytes; }
    
    size_t get_size() { return m_size; }

    void update_value(size_t size) {
        assert(m_bytes == nullptr);
        auto ret = posix_memalign((void**)&m_bytes, 4096, size);
        m_size = size;
        gen_random_string(m_bytes, size);
    }

private:
    uint8_t* m_bytes = nullptr;
    uint64_t m_size = 0;
};
} 
} // namespace homeds::loadgen
