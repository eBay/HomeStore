//
// Created by Kadayam, Hari on 27/10/17.
//

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>

#include <boost/intrusive/list.hpp>

#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/homeds/memory/mempiece.hpp"

SDS_LOGGING_DECL(cache)

namespace homestore {

template < typename EvictionPolicy >
class Evictor {
public:
    typedef typename EvictionPolicy::RecordType EvictRecordType;
    typedef std::function< bool(const EvictRecordType*) > CanEvictCallback;
    typedef std::function< uint32_t(const EvictRecordType*) > GetSizeCallback;

    /* Initialize the evictor with maximum size it needs to keep it under, before it starts evictions. Caller also
     * need to provide a callback function to check if the current record could be evicted or not. */
    Evictor(const uint32_t part_num, const int64_t max_size, CanEvictCallback cb, GetSizeCallback gs_cb) :
            m_can_evict_cb{std::move(cb)},
            m_get_size_cb{std::move(gs_cb)},
            m_evict_policy{0},
            m_cur_size{0},
            m_max_size{max_size},
            m_part_num{part_num} {}

    Evictor(const Evictor&) = delete;
    Evictor(Evictor&&) noexcept = delete;
    Evictor& operator=(const Evictor&) = delete;
    Evictor& operator=(Evictor&&) noexcept = delete;
    ~Evictor() = default;

    /* Add the given record to the list. The given record is automatically upvoted. This record might be added
     * only after evicting a record (once it reaches max limits).
     */
    bool add_record(EvictRecordType& r) {
        const auto sz{m_get_size_cb(&r)};

        if ((m_cur_size.fetch_add(sz, std::memory_order_acq_rel) + sz) <= m_max_size) {
            // We didn't have any size restriction while it is being added, so add to the record as is
            m_evict_policy.add(r);
            return true;
        }

        /* XXX there can be race when both threads try to evict it and there is only one entry in
         * lru eviction. But it can not happen if we assume that one entry can not completely
         * fill this evictor.
         */
        // We were excess size earlier, so try evicting atleast this blk size
        if (do_evict(sz)) {
            m_evict_policy.add(r);
            return true;
        } else {
            return false;
        }
    }

    bool modify_size(const uint32_t sz) {
        if ((m_cur_size.fetch_add(sz, std::memory_order_acq_rel) + sz) <= m_max_size) {
            // We didn't have any size restriction while it is being added, so add to the record as is
            return true;
        }
        if (do_evict(sz)) {
            return true;
        } else {
            return false;
        }
    }

    /* Upvote the entry. This depends on the current rank will move up and thus reduce the chances of getting evicted.
     * In case of LRU allocation, it moves to the tail end of the list The entry is expected to be present in the
     * eviction list */
    void upvote(EvictRecordType& rec) { m_evict_policy.upvote(rec); }

    /* Downvote the entry and hence could be candidate to be evicted soon */
    void downvote(EvictRecordType& rec) { m_evict_policy.downvote(rec); }

    /* Delete the record and thus creating more room for avoiding eviction. The record is expected to be present
     * in the eviction list */
    void delete_record(EvictRecordType& rec) {
        m_evict_policy.remove(rec);
        const auto rec_size{m_get_size_cb(&rec)};
        HS_LOG_ASSERT_GE(rec_size, 0);
        const int64_t size{m_cur_size.fetch_sub(rec_size, std::memory_order_acq_rel)};
        HS_LOG_ASSERT_GE(size, 0);
    }

private:
    bool do_evict(const uint64_t needed_size_in) {
        uint64_t needed_size{needed_size_in};
        uint64_t dealloc_size{0};
        m_evict_policy.eject_next_candidate(
            [this, &needed_size, &dealloc_size](const EvictRecordType& rec, bool& stop) {
                stop = false;
                const auto rec_size{m_get_size_cb(&rec)};
                /* it delete the record if it can be evicted */
                if (m_can_evict_cb(&rec)) {
                    if (needed_size > rec_size) {
                        needed_size -= rec_size;
                    } else {
                        needed_size = 0;
                    }
                    dealloc_size += rec_size;
                    if (needed_size == 0) { stop = true; }
                    return true;
                } else {
                    return false;
                }
            });

        if (dealloc_size > 0) {
            const int64_t size{m_cur_size.fetch_sub(dealloc_size, std::memory_order_acq_rel)};
            HS_LOG_ASSERT_GE(size, 0);
            if (dealloc_size < needed_size) {
                HS_LOG(DEBUG, cache, "Unable to evict enough entries to meet needed size - needed {} evicted {}",
                       needed_size, dealloc_size);
                return false;
            }
            return true;
        } else {
            HS_LOG(DEBUG, cache, "Unable to evict any entries.", needed_size, dealloc_size);
            return false;
        }
    }

private:
    CanEvictCallback m_can_evict_cb;
    GetSizeCallback m_get_size_cb;
    EvictionPolicy m_evict_policy;
    std::atomic< int64_t > m_cur_size;
    int64_t m_max_size;
    uint32_t m_part_num;
};

} // namespace homestore

#if 0
template <typename EvictionPolicy>
class Evictor {
public:
    typedef std::function< bool(typename EvictionPolicy::RecordType *) > CanEvictCallback;
    typedef std::function< uint32_t(typename EvictionPolicy::RecordType *) > GetSizeCallback;
    typedef typename EvictionPolicy::RecordType EvictRecordType;

    /* Initialize the evictor with maximum size it needs to keep it under, before it starts evictions. Caller also
     * need to provide a callback function to check if the current record could be evicted or not. */
    Evictor(uint64_t max_size, CanEvictCallback cb, GetSizeCallback gs_cb);

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
    EvictRecordType *do_evict(uint64_t needed_size);

private:
    CanEvictCallback m_can_evict_cb;
    GetSizeCallback m_get_size_cb;
    EvictionPolicy m_evict_policy;
    std::atomic<uint64_t> m_cur_size;
    uint64_t m_max_size;
};
}
#endif
