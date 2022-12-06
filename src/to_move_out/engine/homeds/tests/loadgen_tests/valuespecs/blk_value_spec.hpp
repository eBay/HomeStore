//
// Modified by Amit Desai
//

#ifndef HOMESTORE_BLK_VALUE_SPEC_HPP
#define HOMESTORE_BLK_VALUE_SPEC_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <memory>
#include <random>

#include <farmhash.h>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {
class BlkValue : public ValueSpec {
private:
    char* m_data;
    uint64_t m_hash_code;

    static auto gen_array() {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        carr.fill(1);
        return carr;
    }

public:
    static constexpr size_t BLK_SIZE{4096};

    static void populate_buf(uint8_t* const buf, const uint64_t size) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< uint64_t > rand_num{0, std::numeric_limits< uint64_t >::max()};
        for (uint64_t write_sz{0}; write_sz < size; write_sz += sizeof(uint64_t)) {
            *reinterpret_cast<uint64_t*>(buf + write_sz) = rand_num(re);
        }
    }

    static std::shared_ptr< BlkValue > gen_value(const ValuePattern spec, const BlkValue* const ref_value = nullptr) {
        //static const auto carr{gen_array()};
        std::shared_ptr< BlkValue > temp;
        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL:
        case ValuePattern::RANDOM_BYTES: {
            char* const data{reinterpret_cast< char* >(iomanager.iobuf_alloc(512, BLK_SIZE))};
            populate_buf(reinterpret_cast<uint8_t*>(data), BLK_SIZE);
            temp = std::make_shared< BlkValue >();
            temp->set_buf(data);
            return temp;
        }
        default:
            // We do not support other gen spec yet
            assert(false);
            temp = std::make_shared< BlkValue >();
            return temp;
        }
    }

    BlkValue() : m_data{nullptr} {}
    BlkValue(char* const data) : m_data{data}, m_hash_code{util::Hash64(const_cast<const char*>(m_data), BLK_SIZE)} {}
    BlkValue(const uint64_t hash_code) : m_data{nullptr}, m_hash_code{hash_code} {}

    BlkValue(const BlkValue&) = delete;
    BlkValue& operator = (const BlkValue&) = delete;

    BlkValue(BlkValue&& obj) noexcept : m_data{obj.get()}, m_hash_code{obj.get_hash_code()} {
        obj.set_buf(nullptr);
    }

    BlkValue& operator=(BlkValue&& rhs) noexcept {
        if (this != &rhs) {
            m_data = rhs.get();
            m_hash_code = rhs.get_hash_code();
            rhs.set_buf(nullptr);
        }
        return *this;
    }

    virtual ~BlkValue() override {
        if (m_data) { iomanager.iobuf_free(reinterpret_cast<uint8_t*>(m_data)); }
    }

    virtual uint64_t get_hash_code() const override { return m_hash_code; }

    void set_hash_code(const uint64_t hash_code) { m_hash_code = hash_code; }

    void set_buf(void* const buf) {
        m_data = static_cast<char*>(buf);
        if (m_data) { set_hash_code(util::Hash64(const_cast<const char*>(m_data), BLK_SIZE)); }
    }

    char* get() { return m_data; }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_MAP_VALUE_SPEC_HPP
