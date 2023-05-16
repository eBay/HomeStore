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
#ifndef HOMESTORE_BTREE_VALUE_SPEC_HPP
#define HOMESTORE_BTREE_VALUE_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>

#include <farmhash.h>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {

template < const size_t Size >
class FixedBytesValue : public homeds::btree::BtreeValue, public ValueSpec {
public:
    static std::shared_ptr< FixedBytesValue< Size > >
    gen_value(const ValuePattern spec, const FixedBytesValue< Size >* const ref_value = nullptr) {
        std::shared_ptr< FixedBytesValue< Size > > temp{std::make_shared< FixedBytesValue >()};
        switch (spec) {
        case ValuePattern::RANDOM_BYTES:
            gen_random_string(temp->m_bytes, Size);
            break;

        default:
            // We do not support other gen spec yet
            assert(false);
        }

        return temp;
    }

    static constexpr bool is_fixed_size() { return true; }
    static constexpr uint32_t get_max_size() { return Size; }

    FixedBytesValue() : homeds::btree::BtreeValue{} {}

    FixedBytesValue(const char* const bytes) : FixedBytesValue{} {
        if (bytes) { std::memcpy(static_cast< void* >(m_bytes), static_cast< const void* >(bytes), Size); }
    }
    FixedBytesValue(const FixedBytesValue& other) { copy_blob(other.get_blob()); }
    FixedBytesValue& operator=(const FixedBytesValue& rhs) {
        if (this != &rhs) { copy_blob(rhs.get_blob()); }
        return *this;
    }
    FixedBytesValue(FixedBytesValue&&) noexcept = delete;
    FixedBytesValue& operator=(FixedBytesValue&&) noexcept = delete;
    virtual ~FixedBytesValue() override = default;

    sisl::blob get_blob() const override {
        sisl::blob b;
        b.bytes = const_cast< uint8_t* >(m_bytes);
        b.size = Size;
        return b;
    }

    void set_blob(const sisl::blob& b) override { copy_blob(b); }
    void copy_blob(const sisl::blob& b) override {
        std::memcpy(static_cast< void* >(m_bytes), static_cast< const void* >(b.bytes), static_cast< size_t >(b.size));
    }
    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { copy_blob(new_val.get_blob()); }
    uint32_t get_blob_size() const override { return Size; }
    void set_blob_size(const uint32_t size) override { assert(size == sizeof(Size)); }
    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return Size; }
    static uint32_t get_fixed_size() { return Size; }
    std::string to_string() const { return std::string{reinterpret_cast< const char* >(m_bytes), Size}; }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const FixedBytesValue& other) const {
        return (std::memcmp(static_cast< const void* >(m_bytes), static_cast< const void* >(other.get_blob().m_bytes),
                            Size) == 0);
    }

    virtual uint64_t get_hash_code() const override {
        const sisl::blob b{get_blob()};
        return util::Hash64(reinterpret_cast< const char* >(b.bytes), static_cast< size_t >(b.size));
    }

private:
    uint8_t m_bytes[Size];
};

template < typename charT, typename traits, const size_t Size >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const FixedBytesValue< Size >& value) {
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

#endif // HOMESTORE_BTREE_VALUE_SPEC_HPP
