//
// Created by Kadayam, Hari on 27/10/17.
//

#pragma once

#include <iterator>
#include <mutex>

#include <boost/intrusive/list.hpp>

#include "engine/common/homestore_assert.hpp"

SDS_LOGGING_DECL(cache)

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
