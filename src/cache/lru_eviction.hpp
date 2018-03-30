//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_LRU_EVICTION_HPP_HPP
#define OMSTORE_LRU_EVICTION_HPP_HPP

#include "eviction.hpp"

namespace homestore {

// This structure represents each entry into the evictable location
struct LRUEvictRecord : public boost::intrusive::list_base_hook<> {
};

class LRUEvictionPolicy {
public:
    typedef LRUEvictRecord RecordType;

    LRUEvictionPolicy(uint32_t estimated_entries) {
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

    LRUEvictRecord *get_next_candidate(LRUEvictRecord *prev) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
        if (prev) {
            auto it = m_list.iterator_to(*prev);
            return &(*(++it));
        } else {
            auto it = m_list.begin();
            return &*it;
        }
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
