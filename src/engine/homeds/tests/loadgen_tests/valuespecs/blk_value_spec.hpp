//
// Modified by Amit Desai
//

#ifndef HOMESTORE_BLK_VALUE_SPEC_HPP
#define HOMESTORE_BLK_VALUE_SPEC_HPP

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"
#include <farmhash.h>

#define BLK_SIZE 4096ul
namespace homeds {
namespace loadgen {
class BlkValue : public ValueSpec {

#define INVALID_SEQ_ID UINT64_MAX
    char* m_data;
    uint64_t m_hash_code;

public:
    static void populate_buf(uint8_t* buf, uint64_t size) {
        for (uint64_t write_sz = 0; write_sz < size; write_sz = write_sz + sizeof(uint64_t)) {
            *((uint64_t*)(buf + write_sz)) = std::rand();
        }
    }

    static std::shared_ptr< BlkValue > gen_value(ValuePattern spec, BlkValue* ref_value = nullptr) {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        for (auto i = 0ul; i < CS_ARRAY_STACK_SIZE; i++)
            carr[i] = 1;

        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL:
        case ValuePattern::RANDOM_BYTES: {
            char* data = (char*)iomanager.iobuf_alloc(512, BLK_SIZE);
            populate_buf((uint8_t*)data, BLK_SIZE);
            std::shared_ptr< BlkValue > temp = std::make_shared< BlkValue >(BlkValue());
            temp->set_buf(data);
            return temp;
        }
        default:
            // We do not support other gen spec yet
            assert(0);
            std::shared_ptr< BlkValue > temp = std::make_shared< BlkValue >(BlkValue());
            return temp;
        }
    }

    BlkValue() : m_data(nullptr) {}
    BlkValue(char* data) : m_data(data), m_hash_code(util::Hash64((const char*)m_data, BLK_SIZE)) {}
    BlkValue(uint64_t hash_code) : m_data(nullptr), m_hash_code(hash_code) {}

    BlkValue(BlkValue&& obj) {
        m_data = obj.get();
        m_hash_code = obj.get_hash_code();
        obj.set_buf(nullptr);
    }

    BlkValue& operator=(BlkValue&& obj) {
        m_data = obj.get();
        m_hash_code = obj.get_hash_code();
        obj.set_buf(nullptr);
        return *this;
    }

    ~BlkValue() {
        if (m_data) { iomanager.iobuf_free((uint8_t*)m_data); }
    }

    virtual uint64_t get_hash_code() override { return m_hash_code; }

    void set_hash_code(uint64_t hash_code) { m_hash_code = hash_code; }

    void set_buf(void* buf) {
        m_data = (char*)buf;
        if (m_data) { set_hash_code(util::Hash64((const char*)m_data, BLK_SIZE)); }
    }

    char* get() { return m_data; }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_VALUE_SPEC_HPP
