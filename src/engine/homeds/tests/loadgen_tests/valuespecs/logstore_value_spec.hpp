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

class LogStoreValue : public ValueSpec {
#define MAX_LOGSTORE_VALUE_ALLOC_SIZE 8192
#define LOGSTORE_VALUE_BLK_SIZE 512

private:
    // size is between LOGSTORE_VALUE_BLK_SIZE ~ MAX_LOGSTORE_VALUE_ALLOC_SIZE, aligned of LOGSTORE_VALUE_BLK_SIZE;
    static uint64_t get_rand_val_size() {
        auto d = rand() % (MAX_LOGSTORE_VALUE_ALLOC_SIZE / LOGSTORE_VALUE_BLK_SIZE);
        return (d + 1) * LOGSTORE_VALUE_BLK_SIZE;
    }

public:
    static std::shared_ptr< LogStoreValue > gen_value(ValuePattern spec, LogStoreValue* ref_value = nullptr) {
        auto size = get_rand_val_size();
        std::shared_ptr< LogStoreValue > temp = std::make_shared< LogStoreValue >(size);

        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            gen_random_string(temp->m_bytes, temp->m_size);
            break;

        default:
            // We do not support other gen spec yet
            assert(0);
            break;
        }

        return temp;
    }

    ~LogStoreValue() { iomanager.iobuf_free(m_bytes); }

    LogStoreValue() {}

    LogStoreValue(uint64_t size) : m_size(size) {
        assert(m_bytes == nullptr);
        m_bytes = iomanager.iobuf_alloc(512, m_size);
    }

    LogStoreValue(const LogStoreValue& other) { copy_blob(other.get_blob()); }

    void copy_blob(const homeds::blob& b) {
        for (size_t i = 0; i < b.size; i++) {
            m_bytes[i] = b.bytes[i];
        }
    }

    homeds::blob get_blob() const {
        homeds::blob b;
        b.bytes = m_bytes;
        b.size = m_size;
        return b;
    }

    virtual uint64_t get_hash_code() {
        homeds::blob b = get_blob();
        return util::Hash64((const char*)b.bytes, (size_t)b.size);
    }

    uint8_t* get_buf() { return m_bytes; }

    size_t get_size() { return m_size; }

private:
    uint8_t* m_bytes = nullptr;
    uint64_t m_size = 0;
};
} // namespace loadgen
} // namespace homeds
