//
// Created by Amit Desai on 07/15/19.
//
#ifndef HOMESTORE_BLK_READ_TRACKER_STORE_SPEC_HPP
#define HOMESTORE_BLK_READ_TRACKER_STORE_SPEC_HPP

#include <atomic>
#include <functional>
#include <mutex>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <fds/obj_allocator.hpp>
#include <metrics/metrics.hpp>
#include <utility/obj_life_counter.hpp>

#include "engine/blkalloc/blk.h"
#include "engine/homeds/hash/intrusive_hashset.hpp"
#include "homeblks/homeblks_config.hpp"

namespace homestore {

#define BLK_READ_MAP_SIZE 128
struct Free_Blk_Entry;
struct indx_req;

struct BlkEvictionRecord : public homeds::HashNode, sisl::ObjLifeCounter< BlkEvictionRecord > {
    BlkId m_key;                                 // Key to access this cache
    sisl::atomic_counter< uint32_t > m_refcount; // Refcount
    std::atomic< bool > m_can_free;              // mark free for erasure
    std::vector< Free_Blk_Entry > m_free_list;   // list of pair(offset,size) to be freed when no ref left
    std::mutex m_mtx;                            // This mutex prevents multiple writers to free list

    BlkEvictionRecord(const BlkId& key) : m_key(key), m_refcount(0), m_can_free(false), m_free_list(0), m_mtx() {}

    friend void intrusive_ptr_add_ref(BlkEvictionRecord* ber) { ber->m_refcount.increment(); }

    friend void intrusive_ptr_release(BlkEvictionRecord* ber) {
        int cnt = ber->m_refcount.decrement();
        assert(cnt >= 0);
        if (cnt == 0) { ber->free_yourself(); }
    }

    void add_to_free_list(const Free_Blk_Entry& fbe) {
        m_mtx.lock();
        m_free_list.push_back(fbe);
        m_mtx.unlock();
    }

    BlkId& get_key() { return m_key; }
    std::vector< Free_Blk_Entry >* get_free_list() { return &m_free_list; }
    void free_yourself() { sisl::ObjectAllocator< BlkEvictionRecord >::deallocate(this); }
    void set_free_state() { m_can_free = true; }
    void reset_free_state() { m_can_free = false; }
    bool can_free() const { return (m_can_free); }

    static BlkEvictionRecord* make_object(const BlkId& bid) {
        return sisl::ObjectAllocator< BlkEvictionRecord >::make_object(bid);
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(BlkEvictionRecord& b) { intrusive_ptr_add_ref(&b); }

    static void set_free_state(BlkEvictionRecord& b) { b.set_free_state(); }

    static void reset_free_state(BlkEvictionRecord& b) { b.reset_free_state(); }

    static void deref(BlkEvictionRecord& b) { intrusive_ptr_release(&b); }

    static bool test_le(const BlkEvictionRecord& b, const int32_t check) { return b.m_refcount.test_le(check); }

    static bool test_eq(const BlkEvictionRecord& b, const int32_t check) { return b.m_refcount.test_eq(check); }

    static const BlkId* extract_key(const BlkEvictionRecord& b) { return &(b.m_key); }
};

class BlkReadTrackerMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkReadTrackerMetrics(const char* indx_name) : sisl::MetricsGroupWrapper("BlkReadTracker", indx_name) {
        REGISTER_COUNTER(blktrack_pending_blk_read_map_sz, "Size of pending blk read map",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blktrack_erase_blk_rescheduled, "Erase blk rescheduled due to concurrent rw");
        register_me_to_farm();
    }

    ~BlkReadTrackerMetrics() { deregister_me_from_farm(); }
};

class Blk_Read_Tracker {
    homeds::IntrusiveHashSet< BlkId, BlkEvictionRecord > m_pending_reads_map;
    BlkReadTrackerMetrics m_metrics;
    typedef std::function< void(const Free_Blk_Entry&) > blk_remove_cb;
    blk_remove_cb m_remove_cb;

public:
    Blk_Read_Tracker(const blk_remove_cb& remove_cb) :
            m_pending_reads_map(1000), m_metrics("blk_read_tracker"), m_remove_cb(remove_cb) {}

    void insert(const Free_Blk_Entry& fbe);

    /* after a read is finished, remove this blkid from the tracker */
    void remove(const Free_Blk_Entry& fbe);

    /* safely free these blkids. If a blkid is already in a tracker then it wait for it to remove */
    void safe_free_blks(const Free_Blk_Entry& fbe);

    uint64_t get_size() const { return m_pending_reads_map.get_size(); }
};
} // namespace homestore

#endif
