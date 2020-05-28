/*
 * BitmapBlkAllocator.h
 *
 *  Created on: Jun 17, 2015
 *      Author: Hari Kadayam
 */

#pragma once

#include <thread>
#include <vector>
#include <queue>
#include <boost/heap/binomial_heap.hpp>
#include "libutils/omds/btree/mem_btree.hpp"
#include "libutils/omds/bitmap/bitmap.hpp"
#include "blk_allocator.h"

using namespace std;
using namespace boost::heap;

namespace omstorage {

class __attribute__((__packed__)) BlkId {
private:
    uint64_t m_blknum : 50;
    uint64_t m_segnum : 14;

public:
    BlkId(uint64_t blknum, uint64_t segnum) {
        m_blknum = blknum;
        m_segnum = segnum;
    }

    uint64_t get_blk_num() const { return m_blknum; }

    uint64_t get_seg_num() const { return m_segnum; }
};

#define RANGE_FIRST 0
#define RANGE_LAST ((uint32_t)-1)

#if 0
typedef struct
{
    uint64_t startRange;
    bool startInclusive;
    uint64_t endRange;
    bool endInclusive;
}
search_range_t;

class PageCacheSearchMeta
{
private:
    search_range_t m_freeBlksRange;
    search_range_t m_contgiousBlksRange;
    search_range_t m_tempRange;
    search_range_t m_pageIdRange;

public:
    search_range_t *getFreeBlksSearchRange()
    {
        return &m_freeBlksRange;
    };
    search_range_t *getContigousBlksSearchRange()
    {
        return &m_contgiousBlksRange;
    };
    search_range_t *getTemperatureRange()
    {
        return &m_tempRange;
    };
    search_range_t *getPageIdRange()
    {
        return &m_pageIdRange;
    };

    void formFilter(search_range_t *r, uint64_t start, bool sincl, uint64_t end, bool eincl)
    {
        r->startRange = start;
        r->startInclusive = sincl;
        r->endRange = end;
        r->endInclusive = eincl;
    }
};
#endif

class PageAllocGroup {
private:
    pthread_mutex_t m_blk_lock;

public:
#ifndef NDEBUG
    uint32_t m_blk_group_id;
#endif

    PageAllocGroup() { pthread_mutex_init(&m_blk_lock, NULL); }

    ~PageAllocGroup() { pthread_mutex_destroy(&m_blk_lock); }

    void lock() { pthread_mutex_lock(&m_blk_lock); }

    void unlock() { pthread_mutex_unlock(&m_blk_lock); }
};

class PageAllocSegment {
public:
    class CompareSegAvail {
    public:
        bool operator()(PageAllocSegment* seg1, PageAllocSegment* seg2) const {
            return (seg1->get_free_atoms() < seg2->get_free_atoms());
        }
    };

    typedef boost::heap::binomial_heap< PageAllocSegment*, compare< CompareSegAvail > > SegQueue;

private:
    uint64_t m_alloc_clock_hand;
    uint64_t m_free_atoms;
    uint64_t m_total_atoms;
    uint32_t m_seg_num;             // Segment sequence number
    SegQueue::handle_type m_seg_id; // Opaque segment Id.

public:
    PageAllocSegment(uint64_t npieces, uint32_t seg_num) {
        set_total_atoms(npieces);
        set_free_atoms(npieces);
        set_seg_num(seg_num);
    }

    virtual ~PageAllocSegment() {}

    uint64_t get_clock_hand() const { return m_alloc_clock_hand; }

    void set_clock_hand(uint64_t hand) { m_alloc_clock_hand = hand; }

    void inc_clock_hand() {
        if (m_alloc_clock_hand == m_total_atoms) {
            m_alloc_clock_hand = 0;
        } else {
            m_alloc_clock_hand++;
        }
    }

    bool operator<(PageAllocSegment& other_seg) const { return (this->get_free_atoms() < other_seg.get_free_atoms()); }

    void set_free_atoms(uint64_t freeAtoms) { m_free_atoms = freeAtoms; }

    uint64_t get_free_atoms() const { return m_free_atoms; }

    void set_total_atoms(uint64_t a) { m_total_atoms = a; }

    uint64_t get_total_atoms() const { return m_total_atoms; }

    void set_seg_num(uint32_t n) { m_seg_num = n; }

    uint32_t get_seg_num() const { return m_seg_num; }

    void set_segment_id(SegQueue::handle_type& seg_id) { m_seg_id = seg_id; }

    SegQueue::handle_type get_segment_id() const { return m_seg_id; }
};

class DynamicBlkAllocator : public BlkAllocator {
public:
    DynamicBlkAllocator(BlkAllocConfig& cfg);

    ~DynamicBlkAllocator();

    void allocator_state_machine();

    BlkAllocStatus alloc(uint32_t size, uint32_t desired_temp, Blk* out_blk);
    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid,
                         bool retry = true) override;
    virtual bool is_blk_alloced(BlkId& in_bid) override;
    virtual uint8_t* serialize_alloc_blks(uint64_t chunk_id, size_t& mem_size) override;

    void free(Blk& blk);
    void free(const BlkId& b, std::shared_ptr< blkalloc_cp_id > id) override;

    // void freeBlks(uint64_t blkNum, uint32_t blkSize);
    // void commitBlks(uint64_t blkNum, uint32_t blkSize);
    void commit(Blk& blk);

    uint64_t* get_partial_page_map(uint64_t page_num);

    string to_string();

    const BlkAllocConfig* get_config() const { return BlkAllocator::get_config(); }

    void inited();
    override BlkAllocStatus alloc(BlkId& out_blkid);
    override private : std::thread m_thread_id; // Thread pointer for this region
    std::mutex m_mutex;                         // Mutex to protect regionstate & cb
    std::condition_variable m_cv;               // CV to signal thread
    BlkAllocatorState m_region_state;

    BitMapUnsafe* m_allocBm; // Bitset of all allocation
    BitMapUnsafe* m_cacheBm; // Bitset of what is provided to cache or allocated

    std::atomic< uint32_t > m_cache_entries; // Total number of page entries to cache
    omds::btree::MemBtree< DynamicPageAllocCacheEntry, EmptyClass >* m_blk_cache; // Blk Entry caches

    typedef boost::heap::binomial_heap< PageAllocSegment*, compare< PageAllocSegment::CompareSegAvail > > SegQueue;

    SegQueue m_heap_segments;               // Heap of segments within a region.
    PageAllocSegment* m_wait_alloc_segment; // A flag/hold variable, for caller thread
    // to pass which segment to look for sweep

    // Overall page and page group tables
    PageAllocGroup* m_pg_grps;
    DynamicPageAllocEntry* m_pg_entries;

private:
    // Thread related functions
    std::thread* get_thread() const;

    std::string state_string(BlkAllocatorState state) const;

    // Sweep and cache related functions
    void request_more_pages(PageAllocSegment* seg = NULL);

    void request_more_pages_wait(PageAllocSegment* seg = NULL);

    void fill_cache(PageAllocSegment* seg);

    uint64_t fill_cache_in_group(uint64_t grp_num, PageAllocSegment* seg);

    // Bitset related methods
    // bool canAllocBlock(uint64_t b);
    // void setCacheUsed(uint64_t startBlk, uint32_t count);
    // void setBlksUsed(uint32_t startBlk, uint32_t count);
    // void setBlksFreed(uint32_t startBlk, uint32_t count);

    // Convenience routines
    const PageAllocGroup* get_page_group(uint64_t grp_num) const;
    const PageAllocGroup* pageid_to_group(uint64_t pgid) const;
    uint32_t pageid_to_groupid(uint64_t pgid) cpmst;
    const DynamicPageAllocEntry* get_page_entry(uint64_t pgid) const;
    uint64_t page_id_to_atom(uint64_t pgid) const;

    uint64_t pageid_to_bit(uint64_t pgid, uint32_t offset) const {
        return (pgid * get_config()->get_atoms_per_page() + offset / get_config()->get_atom_size());
    }

    uint32_t size_to_nbits(uint32_t size) const { return size / get_config()->get_atom_size(); }
    //	std::priority_queue<BlkSegment *, vector<BlkSegment *>, CompareSegAvail> m_blkSegments;
};

class DynamicPageAllocCacheEntry : public omds::btree::BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_nfree_atoms : 8;
        uint64_t m_max_contigous_free_atoms : 8;
        uint64_t m_temp : 10;
        uint64_t m_page_id : 38;
    } blob_t;

    blob_t* m_blob;
    blob_t m_in_place_blob;

public:
    DynamicPageAllocCacheEntry() {
        m_blob = &m_in_place_blob;
        set_free_atoms_count(0);
        set_max_contigous_free_atoms(0);
        set_temperature(0);
        set_page_id(0);
    }

    DynamicPageAllocCacheEntry(uint32_t free_blks, uint32_t cont_blks, uint32_t temp, uint32_t page_id) {
        m_blob = &m_in_place_blob;
        set_free_atoms_count(free_blks);
        set_max_contigous_free_atoms(cont_blks);
        set_temperature(temp);
        set_page_id(page_id);
    }

    uint32_t get_free_atoms_count() const { return (m_blob->m_nfree_atoms); }

    void set_free_atoms_count(uint32_t free_pieces) { m_blob->m_nfree_atoms = free_pieces; }

    uint32_t get_temperature() const { return (m_blob->m_temp); }

    void set_temperature(uint32_t temp) { m_blob->m_temp = temp; }

    uint64_t get_page_id() const { return m_blob->m_page_id; }

    inline void set_page_id(uint64_t pageId) { m_blob->m_page_id = pageId; }

    uint32_t get_max_contigous_free_atoms() const { return m_blob->m_max_contigous_free_atoms; }

    inline void set_max_contigous_free_atoms(uint32_t f) { m_blob->m_max_contigous_free_atoms = f; }

    int is_in_range(uint64_t val, uint64_t start, bool start_incl, uint64_t end, bool end_incl) const {
        if (val < start) {
            return 1;
        } else if ((val == start) && (!start_incl)) {
            return 1;
        } else if (val > end) {
            return -1;
        } else if ((val == end) && (!end_incl)) {
            return -1;
        } else {
            return 0;
        }
    }

#if 0
    int compareRange(uint64_t val, search_range_t *range)
    {
        if (val < range->startRange) {
            return 1;
        } else if ((val == range->startRange) && (!range->startInclusive)) {
            return 1;
        } else if (val > range->endRange) {
            return -1;
        } else if ((val == range->endRange) && (!range->endInclusive)) {
            return -1;
        } else {
            return 0;
        }
    }
#endif

    int compare_range(const omds::btree::BtreeKey* s, bool start_incl, const omds::btree::BtreeKey* e,
                      bool end_incl) const {
        DynamicPageAllocCacheEntry* start = (DynamicPageAllocCacheEntry*)s;
        DynamicPageAllocCacheEntry* end = (DynamicPageAllocCacheEntry*)e;

        int ret = is_in_range(this->get_free_atoms_count(), start->get_free_atoms_count(), start_incl,
                              end->get_free_atoms_count(), end_incl);
        if (ret != 0) {
            return ret;
        }

        ret = is_in_range(this->get_max_contigous_free_atoms(), start->get_max_contigous_free_atoms(), start_incl,
                          end->get_max_contigous_free_atoms(), end_incl);
        if (ret != 0) {
            return ret;
        }

        ret = is_in_range(this->get_temperature(), start->get_temperature(), start_incl, end->get_temperature(),
                          end_incl);
        if (ret != 0) {
            return ret;
        }

        ret = is_in_range(this->getPageId(), start->getPageId(), start_incl, end->getPageId(), end_incl);
        return ret;
    }

#if 0
    int compare(DynamicPageAllocCacheEntry &other)
    {

        if (searchMeta == NULL) {
            return (compare(other));
        }

        PageCacheSearchMeta *sm = (PageCacheSearchMeta *)searchMeta;

        int ret = compareRange(this->getFreeAtomsCount(), &sm->m_freeBlksRange);
        if (ret != 0) {
            return ret;
        }

        ret = compareRange(this->getMaxContigousFreeAtoms(), &sm->m_contgiousBlksRange);
        if (ret != 0) {
            return ret;
        }

        ret = compareRange(this->getTemperature(), &sm->m_tempRange);
        if (ret != 0) {
            return ret;
        }

        ret = compareRange(this->getPageId(), &sm->m_pageIdRange);
        if (ret != 0) {
            return ret;
        }
    }
#endif

    int compare(omds::btree::BtreeKey* o) const override {
        auto* other = (DynamicPageAllocCacheEntry*)o;
        if (get_free_atoms_count() < other->get_free_atoms_count()) {
            return 1;
        } else if (get_free_atoms_count() > other->get_free_atoms_count()) {
            return -1;
        } else if (get_max_contigous_free_atoms() < other->get_max_contigous_free_atoms()) {
            return 1;
        } else if (get_max_contigous_free_atoms() > other->get_max_contigous_free_atoms()) {
            return -1;
        } else if (get_temperature() < other->get_temperature()) {
            return 1;
        } else if (get_temperature() > other->get_temperature()) {
            return -1;
        } else if (get_page_id() < other->get_page_id()) {
            return 1;
        } else if (get_page_id() > other->get_page_id()) {
            return -1;
        } else {
            return 0;
        }
    }

    virtual uint8_t* get_blob(uint32_t* pSize) const {
        *pSize = sizeof(blob_t);
        return (uint8_t*)m_blob;
    }

    virtual void set_blob(const uint8_t* blob, uint32_t size) {
        assert(size == sizeof(blob));
        m_blob = (blob_t*)blob;
    }

    virtual void copy_blob(const uint8_t* blob, uint32_t size) {
        assert(size == sizeof(blob));
        memcpy(m_blob, blob, size);
    }

    virtual uint32_t get_blob_size() const { return (sizeof(DynamicPageAllocCacheEntry)); }

    virtual void set_blob_size(uint32_t size) {}

    void print() {
        cout << "free_atom_count: " << get_free_atoms_count() << " temp: " << get_temperature()
             << " pageid: " << get_page_id();
    }
};

class DynamicPageAllocEntry {
private:
    uint8_t m_temperature; // Temperature of each blk.

public:
#ifdef DEBUG
    uint32_t m_blkid;
#endif

public:
    void set_temperature(uint8_t t) { m_temperature = t; }

    uint8_t get_temperature() const { return m_temperature; }
} __attribute__((packed));

} // namespace omstorage
