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
//
// Created by Kadayam, Hari on 27/10/17.
//

#include "eviction.hpp"

namespace homestore {

#define EvictRecord typename Evictor< EvictionPolicy >::EvictRecordType

template < typename EvictionPolicy >
Evictor< EvictionPolicy >::Evictor(uint64_t max_size, Evictor< EvictionPolicy >::CanEvictCallback cb,
                                   Evictor< EvictionPolicy >::GetSizeCallback gs_cb) :
        m_evict_policy(cb, gs_cb),
        m_can_evict_cb(cb),
        m_get_size_cb(gs_cb),
        m_cur_size(0),
        m_max_size(max_size) {}

template < typename EvictionPolicy >
EvictRecord* Evictor< EvictionPolicy >::add_record(EvictRecord& r) {
    auto sz = m_get_size_cb(&r);

    if ((m_cur_size.fetch_add(sz, std::memory_order_acq_rel) + sz) <= m_max_size) {
        // We didn't have any size restriction while it is being added, so add to the record as is
        m_evict_policy.add(r);
        return nullptr;
    }

    // We were excess size earlier, so try evicting atleast this blk size
    EvictRecord* ev_rec = do_evict(sz);
    m_evict_policy.add(r);
    return ev_rec;
}

template < typename EvictionPolicy >
EvictRecord* Evictor< EvictionPolicy >::do_evict(uint64_t needed_size) {
    typename EvictionPolicy::RecordType* rec = nullptr;

    rec = m_evict_policy.remove_candidate_ofsize(needed_size);
    if (rec == nullptr) {
        assert(false);
        // TODO: Throw no space available exception.
        return nullptr;
    }

    m_cur_size.fetch_sub(m_get_size_cb(rec), std::memory_order_acq_rel);

    return rec;
}

template < typename EvictionPolicy >
void Evictor< EvictionPolicy >::upvote(EvictRecordType& rec) {
    m_evict_policy.upvote(rec);
}

template < typename EvictionPolicy >
void Evictor< EvictionPolicy >::downvote(EvictRecordType& rec) {
    m_evict_policy.downvote(rec);
}

template < typename EvictionPolicy >
void Evictor< EvictionPolicy >::delete_record(EvictRecordType& rec) {
    m_evict_policy.remove(rec);
    m_cur_size.fetch_sub(m_get_size_cb(&rec), std::memory_order_acq_rel);
}

} // namespace homestore
