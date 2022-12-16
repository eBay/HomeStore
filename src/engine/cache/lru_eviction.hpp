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

#include <iterator>
#include <mutex>

#include <boost/intrusive/list.hpp>

#include "engine/common/homestore_assert.hpp"

SISL_LOGGING_DECL(cache)

namespace homestore {

// This structure represents each entry into the evictable location
struct LRUEvictRecord : public boost::intrusive::list_base_hook<> {
    LRUEvictRecord(void* const cache_buffer) : cache_buffer{cache_buffer} {};
    void* cache_buffer;
    LRUEvictRecord(const LRUEvictRecord&) = delete;
    LRUEvictRecord(LRUEvictRecord&&) noexcept = delete;
    LRUEvictRecord& operator=(const LRUEvictRecord&) = default;
    LRUEvictRecord& operator=(LRUEvictRecord&&) noexcept = default;
    ~LRUEvictRecord() = default;
};

class LRUEvictionPolicy {
public:
    typedef LRUEvictRecord RecordType;

    LRUEvictionPolicy([[maybe_unused]] const size_t num_entries) {}
    LRUEvictionPolicy(const LRUEvictionPolicy&) = delete;
    LRUEvictionPolicy(LRUEvictionPolicy&&) noexcept = delete;
    LRUEvictionPolicy& operator=(const LRUEvictionPolicy&) = delete;
    LRUEvictionPolicy& operator=(LRUEvictionPolicy&&) noexcept = delete;

    ~LRUEvictionPolicy() {
        std::lock_guard< decltype(m_list_guard) > guard{m_list_guard};
        auto it{std::begin(m_list)};
        while (it != std::end(m_list)) {
            it = m_list.erase(it);
        }
    }

    void add(LRUEvictRecord& rec) {
        std::lock_guard< decltype(m_list_guard) > guard{m_list_guard};
        m_list.push_back(rec);
    }

    void remove(LRUEvictRecord& rec) {
        std::lock_guard< decltype(m_list_guard) > guard{m_list_guard};
        auto it{m_list.iterator_to(rec)};
        m_list.erase(it);
    }

    template < typename CallbackType >
    void eject_next_candidate(CallbackType&& cb) {
        std::lock_guard< decltype(m_list_guard) > guard{m_list_guard};

        size_t count{0};
        bool stop{false};
        auto it{std::begin(m_list)};
        while (it != std::end(m_list)) {
            LRUEvictRecord& rec{*it};
            /* return the next element */
            it = m_list.erase(it);
            if (std::forward< CallbackType >(cb)(rec, stop)) {
                if (stop) { return; }
            } else {
                /* reinsert it at the same position */
                it = m_list.insert(it, rec);
                HS_LOG(DEBUG, cache, "reinserting it");
                ++count;
                it = std::next(it);
            }

            if (count) { HS_LOG(DEBUG, cache, "LRU ejection had to skip {} entries", count); }
        }

        // No available candidate to evict
        // TODO: Throw no space available exception.  It is possible that this bucket does not contain enough
        // entries for eviction in which case we might want to look at evicting from other buckets before
        // throwing failure
        return;
    }

    void upvote(LRUEvictRecord& rec) {
        std::lock_guard< decltype(m_list_guard) > guard{m_list_guard};
        m_list.erase(m_list.iterator_to(rec));
        m_list.push_back(rec);
    }

    void downvote(LRUEvictRecord& rec) {
        std::lock_guard< decltype(m_list_guard) > guard{m_list_guard};
        m_list.erase(m_list.iterator_to(rec));
        m_list.push_front(rec);
    }

private:
    std::mutex m_list_guard;
    boost::intrusive::list< LRUEvictRecord > m_list;
};

} // namespace homestore
