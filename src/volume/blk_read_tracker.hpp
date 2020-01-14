//
// Created by Amit Desai on 07/15/19.
//
#ifndef HOMESTORE_BLK_READ_TRACKER_STORE_SPEC_HPP
#define HOMESTORE_BLK_READ_TRACKER_STORE_SPEC_HPP

#include "blkalloc/blk.h"
#include <utility/obj_life_counter.hpp>
#include "homeds/hash/intrusive_hashset.hpp"
#include "homeds/memory/obj_allocator.hpp"
#include <metrics/metrics.hpp>
#include <boost/uuid/uuid.hpp>

namespace homestore {

#define BLK_READ_MAP_SIZE 128
struct Free_Blk_Entry {
    BlkId   m_blkId;
    uint8_t m_blk_offset : NBLKS_BITS;
    uint8_t m_nblks_to_free : NBLKS_BITS;

    Free_Blk_Entry(){};
    Free_Blk_Entry(const BlkId& m_blkId, uint8_t m_blk_offset, uint8_t m_nblks_to_free) :
            m_blkId(m_blkId),
            m_blk_offset(m_blk_offset),
            m_nblks_to_free(m_nblks_to_free) {}

    BlkId   blk_id() const { return m_blkId; }
    uint8_t blk_offset() const { return m_blk_offset; }
    uint8_t blks_to_free() const { return m_nblks_to_free; }
};

struct BlkEvictionRecord : public homeds::HashNode, sisl::ObjLifeCounter< BlkEvictionRecord > {
    BlkId                            m_key;       // Key to access this cache
    sisl::atomic_counter< uint32_t > m_refcount;  // Refcount
    std::atomic< bool >              m_can_free;  // mark free for erasure
    std::vector< Free_Blk_Entry >    m_free_list; // list of pair(offset,size) to be freed when no ref left
    std::mutex                       m_mtx;       // This mutex prevents multiple writers to free list

    BlkEvictionRecord(BlkId& key) : m_key(key), m_refcount(0), m_can_free(false), m_free_list(0), m_mtx() {}

    friend void intrusive_ptr_add_ref(BlkEvictionRecord* ber) { ber->m_refcount.increment(); }

    friend void intrusive_ptr_release(BlkEvictionRecord* ber) {
        int cnt = ber->m_refcount.decrement();
        assert(cnt >= 0);
        if (cnt == 0) {
            ber->free_yourself();
        }
    }

    void add_to_free_list(Free_Blk_Entry& fbe) {
        m_mtx.lock();
        m_free_list.push_back(fbe);
        m_mtx.unlock();
    }

    BlkId&                         get_key() { return m_key; }
    std::vector< Free_Blk_Entry >* get_free_list() { return &m_free_list; }
    void                           free_yourself() { homeds::ObjectAllocator< BlkEvictionRecord >::deallocate(this); }
    void                           set_free_state() { m_can_free = true; }
    void                           reset_free_state() { m_can_free = false; }
    bool                           can_free() { return (m_can_free); }

    static BlkEvictionRecord* make_object(BlkId& bid) {
        return homeds::ObjectAllocator< BlkEvictionRecord >::make_object(bid);
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(BlkEvictionRecord& b) { intrusive_ptr_add_ref(&b); }

    static void set_free_state(BlkEvictionRecord& b) { b.set_free_state(); }

    static void reset_free_state(BlkEvictionRecord& b) { b.reset_free_state(); }

    static void deref(BlkEvictionRecord& b) { intrusive_ptr_release(&b); }

    static bool test_le(BlkEvictionRecord& b, int32_t check) { return b.m_refcount.test_le(check); }

    static bool test_le(const BlkEvictionRecord& b, int32_t check) { return b.m_refcount.test_le(check); }

    static const BlkId* extract_key(const BlkEvictionRecord& b) { return &(b.m_key); }
};

class BlkReadTrackerMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkReadTrackerMetrics(const char* vol_name) : sisl::MetricsGroupWrapper("BlkReadTracker", vol_name) {
        REGISTER_COUNTER(blktrack_pending_blk_read_map_sz, "Size of pending blk read map",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blktrack_erase_blk_rescheduled, "Erase blk rescheduled due to concurrent rw");
        register_me_to_farm();
    }
};

class Blk_Read_Tracker {
    homeds::IntrusiveHashSet< BlkId, BlkEvictionRecord > m_pending_reads_map;
    BlkReadTrackerMetrics                                m_metrics;
    typedef std::function< void(Free_Blk_Entry) >        blk_remove_cb;
    blk_remove_cb                                        m_remove_cb;
    std::string                                          m_vol_name;
    std::string                                          m_vol_uuid;

public:
    Blk_Read_Tracker(   const char* vol_name,
                        boost::uuids::uuid vol_uuid,
                        blk_remove_cb remove_cb ) :
            m_pending_reads_map(BLK_READ_MAP_SIZE),
            m_metrics(vol_name),
            m_remove_cb(remove_cb),
            m_vol_name(vol_name),
            m_vol_uuid(boost::uuids::to_string(vol_uuid)) {}

    void insert(BlkId& bid);

    /* after read is finished, tis marked for safe removal*/
    void safe_remove_blk_on_read(Free_Blk_Entry& fbe);

    /* after overwriting blk id in write flow, its marked for safe removal if cannot be freed immediatly*/
    void safe_remove_blk_on_write(Free_Blk_Entry& fbe);

    void     safe_remove_blks(bool is_read, std::vector< Free_Blk_Entry >* fbes, const std::error_condition& err);
    uint64_t get_size() { return m_pending_reads_map.get_size(); }
};
} // namespace homestore

#endif
