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
#pragma once

#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <random>
#include <sstream>
#include <string>

#include "homeds/loadgen/loadgen_common.hpp"
#include "homeds/loadgen/spec/key_spec.hpp"

namespace homeds {
namespace loadgen {

class LogStoreKey : public KeySpec {
public:
    LogStoreKey() {}

    static LogStoreKey gen_key(const KeyPattern spec, const LogStoreKey* const ref_key = nullptr) {
        static std::atomic< logstore_seq_num_t > seq_num{0};
        seq_num.fetch_add(1, std::memory_order_relaxed);
        return LogStoreKey{seq_num.load()};
    }

    LogStoreKey(const logstore_seq_num_t seq) : m_seq_num{seq} {}

    LogStoreKey(const LogStoreKey&) = default;
    LogStoreKey(LogStoreKey&&) noexcept = default;
    LogStoreKey& operator=(const LogStoreKey&) = default;
    LogStoreKey& operator=(LogStoreKey&&) noexcept = default;

    virtual ~LogStoreKey() override = default;

    virtual bool operator==(const KeySpec& other) const override { return (compare(&other) == 0); }

    virtual bool is_consecutive(const KeySpec& k) const override {
        assert(false);
        return false;
    }

    virtual int compare(const KeySpec* const other) const {
#ifdef NDEBUG
        const LogStoreKey* const k{reinterpret_cast< const LogStoreKey* >(other)};
#else
        const LogStoreKey* const k{dynamic_cast< const LogStoreKey* >(other)};
#endif
        if (m_seq_num < k->m_seq_num)
            return -1;
        else if (m_seq_num > k->m_seq_num)
            return 1;
        return 0;
    }

    std::string to_string() const {
        std::ostringstream os;
        os << m_seq_num;
        return os.str();
    }

    logstore_seq_num_t get_key() const { return m_seq_num; }

private:
    logstore_seq_num_t m_seq_num{0};
};

template < typename charT, typename traits >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const LogStoreKey& log_store_key) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << log_store_key.to_string();
    outStream << outStringStream.str();

    return outStream;
}

} // namespace loadgen
} // namespace homeds
