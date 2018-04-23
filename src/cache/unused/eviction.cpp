//
// Created by Kadayam, Hari on 27/10/17.
//

#include "eviction.hpp"

namespace homestore {

#define EvictRecord typename Evictor<EvictionPolicy>::EvictRecordType

template <typename EvictionPolicy>
Evictor<EvictionPolicy>::Evictor(uint64_t max_size, Evictor<EvictionPolicy>::CanEvictCallback cb,
                                 Evictor<EvictionPolicy>::GetSizeCallback gs_cb) :
        m_evict_policy(0),
        m_can_evict_cb(cb),
        m_get_size_cb(gs_cb),
        m_cur_size(0),
        m_max_size(max_size) {
}

template <typename EvictionPolicy>
EvictRecord* Evictor<EvictionPolicy>::add_record(EvictRecord &r) {
    auto sz = m_get_size_cb(&r);

    if ((m_cur_size.fetch_add(sz, std::memory_order_acq_rel) + sz) <= m_max_size) {
        // We didn't have any size restriction while it is being added, so add to the record as is
        m_evict_policy.add(r);
        return nullptr;
    }

    // We were excess size earlier, so try evicting atleast this blk size
    return do_evict(sz);
}

template <typename EvictionPolicy>
EvictRecord *Evictor<EvictionPolicy>::do_evict(uint64_t needed_size) {
    typename EvictionPolicy::RecordType *rec = nullptr;
    do {
        rec = m_evict_policy.get_next_candidate(rec);
        if (rec == nullptr) {
            assert(0);
            // TODO: Throw no space available exception.
            return nullptr;
        }

        // Check if next record has enough space and also see if it is safe to evict.
        if ((m_get_size_cb(rec) >= needed_size) && m_can_evict_cb(rec)) {
            // Possible to evict, so, ask policy to remove the entry and reclaim the space.
            m_evict_policy.remove(*rec);
            m_cur_size.fetch_sub(needed_size, std::memory_order_acq_rel);
            break;
        } // else keep looking for next candidate
    } while (true);

    return rec;
}

template <typename EvictionPolicy>
void Evictor<EvictionPolicy>::upvote(EvictRecordType &rec) {
    m_evict_policy.upvote(rec);
}

template <typename EvictionPolicy>
void Evictor<EvictionPolicy>::downvote(EvictRecordType &rec) {
    m_evict_policy.downvote(rec);
}

template <typename EvictionPolicy>
void Evictor<EvictionPolicy>::delete_record(EvictRecordType &rec) {
    m_evict_policy.remove(rec);
    m_cur_size.fetch_sub(m_get_size_cb(&rec), std::memory_order_acq_rel);
}

} // namespace homestore
