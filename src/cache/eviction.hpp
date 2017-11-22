//
// Created by Kadayam, Hari on 27/10/17.
//

#ifndef OMSTORE_EVICTION_HPP
#define OMSTORE_EVICTION_HPP

#include "omds/memory/mempiece.hpp"
#include <mutex>
#include <boost/intrusive/list.hpp>
#include "main/store_limits.h"

namespace omstore {
typedef omds::MemVector< BLKSTORE_BLK_SIZE > EvictMemBlk;

template <typename EvictionPolicy>
class Evictor {
public:
    typedef std::function< bool(typename EvictionPolicy::RecordType *) > CanEvictCallback;
    typedef std::function< uint32_t(typename EvictionPolicy::RecordType *) > GetSizeCallback;
    typedef typename EvictionPolicy::RecordType EvictRecordType;

    /* Initialize the evictor with maximum size it needs to keep it under, before it starts evictions. Caller also
     * need to provide a callback function to check if the current record could be evicted or not. */
    Evictor(uint32_t max_size, CanEvictCallback cb, GetSizeCallback gs_cb);

    /* Add the given record to the list. The given record is automatically upvoted. This record might be added
     * only after evicting a record (once it reaches max limits). In that case it returns the record it just
     * evicted (This is the most probable case once we we reached steady state) */
    EvictRecordType *add_record(EvictRecordType &r);

    /* Upvote the entry. This depends on the current rank will move up and thus reduce the chances of getting evicted.
     * In case of LRU allocation, it moves to the tail end of the list The entry is expected to be present in the
     * eviction list */
    void upvote(EvictRecordType &rec);

    /* Downvote the entry and hence could be candidate to be evicted soon */
    void downvote(EvictRecordType &rec);

    /* Delete the record and thus creating more room for avoiding eviction. The record is expected to be present
     * in the eviction list */
    void delete_record(EvictRecordType &r);

private:
    EvictRecordType *do_evict(uint32_t needed_size);

private:
    CanEvictCallback m_can_evict_cb;
    GetSizeCallback m_get_size_cb;
    EvictionPolicy m_evict_policy;
    std::atomic<uint32_t> m_cur_size;
    uint32_t m_max_size;
};

}
#endif //OMSTORE_EVICTION_HPP
