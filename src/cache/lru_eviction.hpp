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
    typedef std::function< bool(RecordType *) > CanEvictCallback;
    typedef std::function< uint32_t(RecordType *) > GetSizeCallback;

    LRUEvictionPolicy(CanEvictCallback cb, GetSizeCallback gs_cb):
        m_can_evict_cb(cb),
        m_get_size_cb(gs_cb) {
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

    LRUEvictRecord *remove_candidate_ofsize(int needed_size) {
        std::lock_guard< decltype(m_list_guard) > guard(m_list_guard);
	auto it =  m_list.begin();
	auto e = m_list.end();
	for(it; it != e; ++it) {
	     if ((m_get_size_cb(&*it) >= needed_size)) {
	//	&& 
	//	m_can_evict_cb(&*it)) {
		m_list.erase(it);
		return &*it;
	     }
        }
	return NULL;
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
    CanEvictCallback m_can_evict_cb;
    GetSizeCallback m_get_size_cb;
};

}
#endif //OMSTORE_LRU_EVICTION_HPP_HPP
