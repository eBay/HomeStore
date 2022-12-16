/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#ifndef HOMESTORE_WORKLOAD_GENERATOR_HPP
#define HOMESTORE_WORKLOAD_GENERATOR_HPP

#include <cstdint>

#include "homeds/loadgen/loadgen_common.hpp"

#include <farmhash.h>

namespace homeds {
namespace loadgen {

/*
template < typename K >
struct compare_keys {
public:
    bool operator()(const K& key1, const K& key2) const { return key1.compare(&key2) == 0; }
};

template < typename K >
struct key_hash {
    size_t operator()(const K& key) const {
        auto b = key.get_blob();
        return util::Hash32((const char*)b.bytes, (size_t)b.size);
    }
};

*/

class KeySpec {
public:
    KeySpec(const KeySpec&) = default;
    KeySpec& operator=(const KeySpec&) = default;
    KeySpec(KeySpec&&) noexcept = default;
    KeySpec& operator=(KeySpec&&) noexcept = default;
    virtual ~KeySpec() = default;

    static uint64_t MAX_KEYS;
    virtual bool operator==(const KeySpec& rhs) const = 0;
    virtual bool operator!=(const KeySpec& rhs) const { return !(operator==(rhs)); }
    virtual bool is_consecutive(const KeySpec& k) const = 0;

protected:
    KeySpec() = default;
};

uint64_t KeySpec::MAX_KEYS = 0;

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_WORKLOAD_GENERATOR_HPP
