/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Yaming Kuang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>

#include <farmhash.h>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {

class LogStoreValue : public ValueSpec {
    static constexpr uint64_t MAX_LOGSTORE_VALUE_ALLOC_SIZE{8192};
    static constexpr uint64_t LOGSTORE_VALUE_BLK_SIZE{512};

private:
    // size is between LOGSTORE_VALUE_BLK_SIZE ~ MAX_LOGSTORE_VALUE_ALLOC_SIZE, aligned of LOGSTORE_VALUE_BLK_SIZE;
    static uint64_t get_rand_val_size() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< uint64_t > rand_val{0,
                                                           MAX_LOGSTORE_VALUE_ALLOC_SIZE / LOGSTORE_VALUE_BLK_SIZE - 1};
        const auto d{rand_val(re)};
        return (d + 1) * LOGSTORE_VALUE_BLK_SIZE;
    }

public:
    static std::shared_ptr< LogStoreValue > gen_value(const ValuePattern spec,
                                                      const LogStoreValue* const ref_value = nullptr) {
        const auto size{get_rand_val_size()};
        std::shared_ptr< LogStoreValue > temp{std::make_shared< LogStoreValue >(size)};

        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            gen_random_string(temp->m_bytes, temp->m_size);
            break;

        default:
            // We do not support other gen spec yet
            assert(false);
            break;
        }

        return temp;
    }

    virtual ~LogStoreValue() override { iomanager.iobuf_free(m_bytes); }

    LogStoreValue() = default;

    LogStoreValue(const uint64_t size) : m_size{size} {
        assert(m_bytes == nullptr);
        m_bytes = iomanager.iobuf_alloc(512, m_size);
    }

    LogStoreValue(const LogStoreValue& other) { copy_blob(other.get_blob()); }
    LogStoreValue& operator=(const LogStoreValue& rhs) {
        if (this != &rhs) { copy_blob(rhs.get_blob()); }
        return *this;
    }
    LogStoreValue(LogStoreValue&&) noexcept = delete;
    LogStoreValue& operator=(LogStoreValue&&) noexcept = delete;

    void copy_blob(const sisl::blob& b) {
        if (!m_bytes) {
            m_size = b.size;
            m_bytes = iomanager.iobuf_alloc(512, m_size);
        } else if (b.size > m_size) {
            iomanager.iobuf_free(m_bytes);
            m_size = b.size;
            m_bytes = iomanager.iobuf_alloc(512, m_size);
        }

        std::memcpy(static_cast< void* >(m_bytes), static_cast< const void* >(b.bytes), static_cast< size_t >(b.size));
    }

    sisl::blob get_blob() const {
        sisl::blob b;
        b.bytes = const_cast< uint8_t* >(m_bytes);
        b.size = m_size;
        return b;
    }

    virtual uint64_t get_hash_code() const override {
        const sisl::blob b{get_blob()};
        return util::Hash64(reinterpret_cast< const char* >(b.bytes), static_cast< size_t >(b.size));
    }

    uint8_t* get_buf() { return m_bytes; }

    size_t get_size() const { return m_size; }

private:
    uint8_t* m_bytes{nullptr};
    uint64_t m_size{0};
};
} // namespace loadgen
} // namespace homeds
