//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_LRU_EVICTION_HPP_HPP
#define OMSTORE_LRU_EVICTION_HPP_HPP

#include <mutex>
#include "cache_common.hpp"

namespace homestore {

// This structure represents each entry into the evictable location
struct LRUEvictRecord : public boost::intrusive::list_base_hook<> {
};

class LRUEvictionPolicy {
public:
    typedef LRUEvictRecord RecordType;
    typedef std::function< bool(const LRUEvictRecord &) > CanEjectCallback;

    LRUEvictionPolicy() {
    }

    void add(LRUEvictRecord &rec) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
        m_list.push_back(rec);
    }

    void remove(LRUEvictRecord &rec) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
        auto it = m_list.iterator_to(rec);
        m_list.erase(it);
    }

    LRUEvictRecord *eject_next_candidate(const CanEjectCallback &cb) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);

        auto count = 0U;
        auto itend = m_list.end();
        for (auto it = m_list.begin(); it != itend; ++it) {
            if (cb(*it)) {
                m_list.erase(it);
                return &*it;
            } else {
                count++;
            }
            if (count) { CVLOG(cache_vmod_evict, 2) << " LRU ejection had to skip " << count << " entries"; }
        }

        // No available candidate to evict
        // TODO: Throw no space available exception.
        return nullptr;
    }

    void upvote(LRUEvictRecord &rec) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
        m_list.erase(m_list.iterator_to(rec));
        m_list.push_back(rec);
    }

    void downvote(LRUEvictRecord &rec) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
        m_list.erase(m_list.iterator_to(rec));
        m_list.push_front(rec);
    }

private:
    std::mutex m_list_guard;
    boost::intrusive::list < LRUEvictRecord > m_list;
};

}
#endif //OMSTORE_LRU_EVICTION_HPP_HPP
