/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#ifndef HOMESTORE_CACHE_VALUE_SPEC_HPP
#define HOMESTORE_CACHE_VALUE_SPEC_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <type_traits>

#include <boost/intrusive_ptr.hpp>
#include <farmhash.h>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {

//////////////////////////////////// SFINAE Hash Selection /////////////////////////////////

class CacheValueBuffer : public homestore::CacheBuffer< CacheKey > {
public:
    typedef homestore::CacheBuffer< CacheKey > CacheBufferType;

    CacheValueBuffer() = default;
    CacheValueBuffer(const CacheValueBuffer&) = delete;
    CacheValueBuffer& operator=(const CacheValueBuffer&) = delete;
    CacheValueBuffer(CacheValueBuffer&&) noexcept = delete;
    CacheValueBuffer& operator=(CacheValueBuffer&&) noexcept = delete;
    virtual ~CacheValueBuffer() override = default;

    virtual void init() override{};

    template < typename... Args >
    static CacheValueBuffer* make_object(Args... args) {
        return sisl::ObjectAllocator< CacheValueBuffer >::make_object(std::forward< Args >(args)...);
    }

    void free_yourself() { sisl::ObjectAllocator< CacheValueBuffer >::deallocate(this); }

    // virtual size_t get_your_size() const override { return sizeof(BlkBuffer); }

    friend void intrusive_ptr_add_ref(CacheValueBuffer* const buf) {
        // manage through base pointer
        intrusive_ptr_add_ref(static_cast< CacheBufferType* >(buf));
    }
    friend void intrusive_ptr_release(CacheValueBuffer* const buf) {
        // manage through base pointer
        intrusive_ptr_release(static_cast< CacheBufferType* >(buf));
    }
};

class CacheValue : public ValueSpec {
private:
    boost::intrusive_ptr< CacheValueBuffer > m_buf;

    static auto gen_array() {
        std::array< uint16_t, CS_ARRAY_STACK_SIZE > carr;
        carr.fill(1);
        return carr;
    }

public:
    static constexpr uint32_t CACHE_ENTRY_SIZE{8192};

    static std::shared_ptr< CacheValue > gen_value(const ValuePattern spec,
                                                   const CacheValue* const ref_value = nullptr) {
        // static const auto carr{gen_array()};

        std::shared_ptr< CacheValue > temp;
        switch (spec) {
        case ValuePattern::SEQUENTIAL_VAL:
        case ValuePattern::RANDOM_BYTES: {

            /* Seed */
            static thread_local std::random_device rd{};

            /* Random number generator */
            static thread_local std::default_random_engine generator{rd()};

            /* Distribution on which to apply the generator */
            std::uniform_int_distribution< uint64_t > distribution{0, MAX_VALUES};

            const auto sid{distribution(generator)};
            uint8_t* const raw_buf{generate_bytes(sid, CACHE_ENTRY_SIZE)};
            temp = std::make_shared< CacheValue >(raw_buf, CACHE_ENTRY_SIZE);
            return temp;
        }
        default:
            // We do not support other gen spec yet
            break;
        }
        assert(false);
        temp = std::make_shared< CacheValue >();
        return temp;
    }

    CacheValue() : m_buf{CacheValueBuffer::make_object()} {}
    CacheValue(uint8_t* const data, const size_t size) : m_buf{CacheValueBuffer::make_object()} {
        boost::intrusive_ptr< homeds::MemVector > mvec{new homeds::MemVector()};
        mvec->set(data, CACHE_ENTRY_SIZE, 0);
        m_buf->set_memvec(std::move(mvec), 0, CACHE_ENTRY_SIZE);
    }

    CacheValue(const CacheValue&) = delete;
    CacheValue& operator=(const CacheValue&) = delete;
    CacheValue(CacheValue&&) noexcept = delete;
    CacheValue& operator=(CacheValue&&) noexcept = delete;

    virtual ~CacheValue() override = default;

    virtual uint64_t get_hash_code() const override {
        auto blob{m_buf->at_offset(0)};
        assert(blob.size == CACHE_ENTRY_SIZE);
        return util::Hash64(reinterpret_cast< const char* >(blob.bytes), static_cast< size_t >(blob.size));
    }

    static uint8_t* generate_bytes(const uint64_t id, const uint64_t size) {
        // generates 4k bytes with repeating id at loc
        uint64_t* const raw_buf{reinterpret_cast< uint64_t* >(std::malloc(size))};
        for (size_t b{0}; b < static_cast< size_t >(size / sizeof(uint64_t)); ++b)
            raw_buf[b] = id;
        return reinterpret_cast< uint8_t* >(raw_buf);
    }

    boost::intrusive_ptr< CacheValueBuffer >& get_buf() { return m_buf; }
};
} // namespace loadgen
} // namespace homeds

#endif // HOMESTORE_CACHE_VALUE_SPEC_HPP
