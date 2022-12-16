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
#include <sstream>
#include <string>

#include <farmhash.h>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {

class VDevValue : public ValueSpec {

public:
    static std::shared_ptr< VDevValue > gen_value(const ValuePattern spec, const VDevValue* const ref_value = nullptr) {
        std::shared_ptr< VDevValue > temp{std::make_shared< VDevValue >()};

        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            break;

        default:
            // We do not support other gen spec yet
            assert(false);
            break;
        }

        return temp;
    }

    virtual ~VDevValue() override {
        // buf won't be freed by homestore i/o path because vdev test doesn't involve cache layer.
        // in which cache layer will free the memory when cache is evicted or removed.
        if (m_bytes) iomanager.iobuf_free(m_bytes);
    }

    VDevValue() = default;
    VDevValue(const VDevValue& other) : m_size{other.m_size} {
        m_bytes = (m_size > 0) ? iomanager.iobuf_alloc(512, m_size) : nullptr;
        if (m_bytes) {
            std::memcpy(static_cast< void* >(m_bytes), static_cast< const void* >(other.m_bytes),
                        static_cast< size_t >(m_size));
        }
    }
    VDevValue& operator=(const VDevValue& rhs) {
        if (this != &rhs) {
            m_size = rhs.m_size;
            m_bytes = (m_size > 0) ? iomanager.iobuf_alloc(512, m_size) : nullptr;
            if (m_bytes) {
                std::memcpy(static_cast< void* >(m_bytes), static_cast< const void* >(rhs.m_bytes),
                            static_cast< size_t >(m_size));
            }
        }
        return *this;
    }
    VDevValue(VDevValue&&) noexcept = delete;
    VDevValue& operator=(VDevValue&&) noexcept = delete;

    std::string to_string() const {
        return m_bytes ? std::string{reinterpret_cast< const char* >(m_bytes), static_cast< size_t >(m_size)}
                       : std::string{};
    }

    bool operator==(const VDevValue& rhs) const {
        if (m_size == rhs.m_size) {
            return (m_size > 0) ? (std::memcmp(static_cast< const void* >(m_bytes),
                                               static_cast< const void* >(rhs.m_bytes), m_size) == 0)
                                : true;
        } else
            return false;
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

    void update_value(const size_t size) {
        assert(m_bytes == nullptr);
        m_bytes = iomanager.iobuf_alloc(512, size);
        m_size = size;
        gen_random_string(m_bytes, size);
    }

private:
    uint8_t* m_bytes{nullptr};
    uint64_t m_size{0};
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const VDevValue& value) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << "val = " << value.to_string();
    outStream << outStringStream.str();

    return outStream;
}

} // namespace loadgen
} // namespace homeds
