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
#ifndef HOMESTORE_BTREE_VAR_VALUE_SPEC_HPP
#define HOMESTORE_BTREE_VAR_VALUE_SPEC_HPP

#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <farmhash.h>

#include "homeds/btree/btree.hpp"
#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/value_spec.hpp"

namespace homeds {
namespace loadgen {

template < const size_t Max_Size >
class VarBytesValue : public homeds::btree::BtreeValue, public ValueSpec {
public:
    static std::shared_ptr< VarBytesValue< Max_Size > >
    gen_value(const ValuePattern spec, const VarBytesValue< Max_Size >* const ref_value = nullptr) {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< size_t > size_rand{9, Max_Size - 1};

        std::shared_ptr< VarBytesValue< Max_Size > > temp{std::make_shared< VarBytesValue< Max_Size > >()};
        switch (spec) {
        case ValuePattern::RANDOM_BYTES: {
            temp->m_bytes.clear();
            const size_t size{size_rand(re)};
            gen_random_string(temp->m_bytes, size);
            assert(temp->m_bytes.size() == size);
            break;
        }
        default:
            // We do not support other gen spec yet
            assert(false);
        }
        return temp;
    }

    static constexpr bool is_fixed_size() { return false; }
    static constexpr uint32_t get_max_size() { return Max_Size; }

    VarBytesValue() : homeds::btree::BtreeValue{} {}

    VarBytesValue(const char* const bytes) : VarBytesValue{} {
        if (bytes) { std::copy(bytes, bytes + Max_Size, std::back_inserter< decltype(m_bytes) >(m_bytes)); }
    }
    VarBytesValue(const VarBytesValue& other) : VarBytesValue{} { copy_blob(other.get_blob()); }
    VarBytesValue& operator=(const VarBytesValue& rhs) {
        if (this != &rhs) { copy_blob(rhs.get_blob()); }
        return *this;
    }
    VarBytesValue(VarBytesValue&&) noexcept = delete;
    VarBytesValue& operator=(VarBytesValue&&) noexcept = delete;

    virtual ~VarBytesValue() override = default;

    sisl::blob get_blob() const override {
        sisl::blob b;
        b.bytes = const_cast< uint8_t* >(m_bytes.data());
        b.size = m_bytes.size();
        return b;
    }

    void set_blob(const sisl::blob& b) override { copy_blob(b); }
    void copy_blob(const sisl::blob& b) override {
        m_bytes.clear();
        std::copy(b.bytes, b.bytes + b.size, std::back_inserter< decltype(m_bytes) >(m_bytes));
        assert(m_bytes.size() == b.size);
    }
    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { copy_blob(new_val.get_blob()); }
    uint32_t get_blob_size() const override { return m_bytes.size(); }
    void set_blob_size(const uint32_t size) override { assert(size == sizeof(m_bytes.size())); }
    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return m_bytes.size(); }
    static uint32_t get_fixed_size() {
        assert(false);
        return 0;
    }
    std::string to_string() const {
        return std::string{reinterpret_cast< const char* >(m_bytes.data()), m_bytes.size()};
    }

    // This is not mandatory overridden method for BtreeValue, but for testing comparision
    bool operator==(const VarBytesValue& rhs) const { return (m_bytes == rhs.m_bytes); }

    virtual uint64_t get_hash_code() const override {
        return util::Hash64(reinterpret_cast< const char* >(m_bytes.data()), m_bytes.size());
    }

private:
    std::vector< uint8_t > m_bytes;
};

template < typename charT, typename traits, const size_t Size >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const VarBytesValue< Size >& value) {
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
