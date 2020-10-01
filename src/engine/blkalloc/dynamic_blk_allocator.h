/*
 * BitmapBlkAllocator.h
 *
 *  Created on: Jun 17, 2015
 *      Author: Hari Kadayam
 */

#pragma once

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include <boost/heap/binomial_heap.hpp>

#include "libutils/omds/bitmap/bitmap.hpp"
#include "libutils/omds/btree/btree_internal.h"
#include "libutils/omds/btree/mem_btree.hpp"

#include "blk_allocator.h"

namespace boost {
namespace heap {
namespace tag {
struct compare;
}
} // namespace heap
} // namespace boost

using namespace std;
using namespace boost::heap;

namespace omstorage {
    class DynamicPageAllocEntry;

    class __attribute__((__packed__)) BlkId {
private:
    uint64_t m_blknum : 50;
    uint64_t m_segnum : 14;

public:
    BlkId(const uint64_t blknum, const uint64_t segnum) {
        m_blknum = blknum;
        m_segnum = segnum;
    }
    BlkId(const BlkId&) = default;
    BlkId(BlkId&&) noexcept = default;
    BlkId& operator=(const BlkId&) = default;
    BlkId& operator=(BlkId&&) noexcept = default;

    [[nodiscard]] uint64_t get_blk_num() const { return m_blknum; }

    [[nodiscard]] uint64_t get_seg_num() const { return m_segnum; }
};

constexpr uint32_t RANGE_FIRST{std::numeric_limits< uint32_t >::min()};
constexpr uint32_t RANGE_LAST{std::numeric_limits< uint32_t >::max()};

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
     std::mutex m_blk_lock;

public:
#ifndef NDEBUG
    uint32_t m_blk_group_id;
#endif

    PageAllocGroup() = default;
    PageAllocGroup(const PageAllocGroup&) = delete;
    PageAllocGroup(PageAllocGroup&&) noexcept = delete;
    PageAllocGroup& operator=(const PageAllocGroup&) = delete;
    PageAllocGroup& operator=(PageAllocGroup&&) noexcept = delete;
    ~PageAllocGroup() = default;

    [[nodiscard]] auto pagealloc_auto_lock() { return std::scoped_lock< std::mutex >{m_blk_lock}; }
};

class PageAllocSegment {
public:
    class CompareSegAvail {
    public:
        bool operator()(const PageAllocSegment* const seg1, const PageAllocSegment* const seg2) const {
            return (seg1->get_free_atoms() < seg2->get_free_atoms());
        }
    };

    typedef boost::heap::binomial_heap< PageAllocSegment*, tag::compare< CompareSegAvail > > SegQueue;

private:
    uint64_t m_alloc_clock_hand;
    uint64_t m_free_atoms;
    uint64_t m_total_atoms;
    uint32_t m_seg_num;             // Segment sequence number
    SegQueue::handle_type m_seg_id; // Opaque segment Id.

public:
    PageAllocSegment(const uint64_t npieces, const uint32_t seg_num) {
        set_total_atoms(npieces);
        set_free_atoms(npieces);
        set_seg_num(seg_num);
    }
    PageAllocSegment(const PageAllocSegment&) = delete;
    PageAllocSegment(PageAllocSegment&&) noexcept = delete;
    PageAllocSegment& operator=(const PageAllocSegment&) = delete;
    PageAllocSegment& operator=(PageAllocSegment&&) noexcept = delete;

    virtual ~PageAllocSegment() {}

    [[nodiscard]] uint64_t get_clock_hand() const { return m_alloc_clock_hand; }

    void set_clock_hand(const uint64_t hand) { m_alloc_clock_hand = hand; }

    void inc_clock_hand() {
        if (m_alloc_clock_hand == m_total_atoms) {
            m_alloc_clock_hand = 0;
        } else {
            m_alloc_clock_hand++;
        }
    }

    [[nodiscard]] bool operator<(const PageAllocSegment& other_seg) const { return (this->get_free_atoms() < other_seg.get_free_atoms()); }

    void set_free_atoms(const uint64_t freeAtoms) { m_free_atoms = freeAtoms; }

    [[nodiscard]] uint64_t get_free_atoms() const { return m_free_atoms; }

    void set_total_atoms(uint64_t a) { m_total_atoms = a; }

    [[nodiscard]] uint64_t get_total_atoms() const { return m_total_atoms; }

    void set_seg_num(uint32_t n) { m_seg_num = n; }

    [[nodiscard]] uint32_t get_seg_num() const { return m_seg_num; }

    void set_segment_id(const SegQueue::handle_type& seg_id) { m_seg_id = seg_id; }

    [[nodiscard]] SegQueue::handle_type get_segment_id() const { return m_seg_id; }
};

class DynamicBlkAllocator : public homestore::BlkAllocator {
public:
    DynamicBlkAllocator(const BlkAllocConfig& cfg);
    DynamicBlkAllocator(const DynamicBlkAllocator&) = delete;
    DynamicBlkAllocator(DynamicBlkAllocator&&) noexcept = delete;
    DynamicBlkAllocator& operator=(const DynamicBlkAllocator&) = delete;
    DynamicBlkAllocator& operator=(DynamicBlkAllocator&&) noexcept = delete;

    virtual ~DynamicBlkAllocator() override;

    void allocator_state_machine();

    [[nodiscard]] BlkAllocStatus alloc(const uint32_t size, const uint32_t desired_temp, Blk* const out_blk);
    [[nodiscard]] BlkAllocStatus alloc(const uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid,
                         constbool retry = true) override;
    [[nodiscard]] virtual bool is_blk_alloced(const BlkId& in_bid) const;
    [[nodiscard]] virtual uint8_t* serialize_alloc_blks(const uint64_t chunk_id, const size_t mem_size) override;

    virtual void free(const Blk& blk) override;
    // void freeBlks(uint64_t blkNum, uint32_t blkSize);
    // void commitBlks(uint64_t blkNum, uint32_t blkSize);
    void commit(const Blk& blk);

    [[nodiscard]] uint64_t* get_partial_page_map(const uint64_t page_num);

    [[nodiscard]] string to_string();

    [[nodiscard]] const BlkAllocConfig* get_config() const { return BlkAllocator::get_config(); }

    void inited();
    override private : std::thread m_thread_id; // Thread pointer for this region
    std::mutex m_mutex;                         // Mutex to protect regionstate & cb
    std::condition_variable m_cv;               // CV to signal thread
    BlkAllocatorState m_region_state;

    std::unique_ptr<BitMapUnsafe> m_allocBm; // Bitset of all allocation
    std::unique_ptr< BitMapUnsafe > m_cacheBm; // Bitset of what is provided to cache or allocated

    std::atomic< uint32_t > m_cache_entries; // Total number of page entries to cache
    std::unique_ptr<omds::btree::MemBtree< DynamicPageAllocCacheEntry, EmptyClass >> m_blk_cache; // Blk Entry caches

    typedef boost::heap::binomial_heap<std::unique_ptr<PageAllocSegment>, compare< PageAllocSegment::CompareSegAvail > > SegQueue;

    SegQueue m_heap_segments;               // Heap of segments within a region.
    PageAllocSegment* m_wait_alloc_segment; // A flag/hold variable, for caller thread
    // to pass which segment to look for sweep

    // Overall page and page group tables
    std::unique_ptr<PageAllocGroup[]> m_pg_grps;
    std::unique_ptr<DynamicPageAllocEntry[]> m_pg_entries;

private:
    // Thread related functions
    [[nodiscard]] std::thread* get_thread() const;

    [[nodiscard]] std::string state_string(const BlkAllocatorState state) const;

    // Sweep and cache related functions
    void request_more_pages(PageAllocSegment* const seg = nullptr);

    void request_more_pages_wait(PageAllocSegment* const seg = nullptr);

    void fill_cache(PageAllocSegment* const seg);

    uint64_t fill_cache_in_group(const uint64_t grp_num, PageAllocSegment* const seg);

    // Bitset related methods
    // bool canAllocBlock(uint64_t b);
    // void setCacheUsed(uint64_t startBlk, uint32_t count);
    // void setBlksUsed(uint32_t startBlk, uint32_t count);
    // void setBlksFreed(uint32_t startBlk, uint32_t count);

    // Convenience routines
    [[nodiscard]] const PageAllocGroup* get_page_group(const uint64_t grp_num) const;
    [[nodiscard]] const PageAllocGroup* pageid_to_group(const uint64_t pgid) const;
    [[nodiscard]] uint32_t pageid_to_groupid(const uint64_t pgid) const;
    [[nodiscard]] const DynamicPageAllocEntry* get_page_entry(const uint64_t pgid) const;
    [[nodiscard]] uint64_t page_id_to_atom(const uint64_t pgid) const;

    [[nodiscard]] uint64_t pageid_to_bit(const uint64_t pgid, const uint32_t offset) const {
        return (pgid * get_config()->get_atoms_per_page() + offset / get_config()->get_atom_size());
    }

    [[nodiscard]] uint32_t size_to_nbits(const uint32_t size) const { return size / get_config()->get_atom_size(); }
    //  std::priority_queue<BlkSegment *, vector<BlkSegment *>, CompareSegAvail> m_blkSegments;
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

    DynamicPageAllocCacheEntry(const uint32_t free_blks, const uint32_t cont_blks, const uint32_t temp, const uint32_t page_id) {
        m_blob = &m_in_place_blob;
        set_free_atoms_count(free_blks);
        set_max_contigous_free_atoms(cont_blks);
        set_temperature(temp);
        set_page_id(page_id);
    }

    DynamicPageAllocCacheEntry(const DynamicPageAllocCacheEntry&) = delete;
    DynamicPageAllocCacheEntry(DynamicPageAllocCacheEntry&&) noexcept = delete;
    DynamicPageAllocCacheEntry& operator=(const DynamicPageAllocCacheEntry&) = delete;
    DynamicPageAllocCacheEntry& operator=(DynamicPageAllocCacheEntry&&) noexcept = delete;

    virtual ~DynamicPageAllocCacheEntry() override = default;

    [[nodiscard]] uint32_t get_free_atoms_count() const { return (m_blob->m_nfree_atoms); }

    void set_free_atoms_count(const uint32_t free_pieces) { m_blob->m_nfree_atoms = free_pieces; }

    [[nodiscard]] uint32_t get_temperature() const { return (m_blob->m_temp); }

    void set_temperature(const uint32_t temp) { m_blob->m_temp = temp; }

    [[nodiscard]] uint64_t get_page_id() const { return m_blob->m_page_id; }

    inline void set_page_id(const uint64_t pageId) { m_blob->m_page_id = pageId; }

    [[nodiscard]] uint32_t get_max_contigous_free_atoms() const { return m_blob->m_max_contigous_free_atoms; }

    inline void set_max_contigous_free_atoms(const uint32_t f) { m_blob->m_max_contigous_free_atoms = f; }

    [[nodiscard]] int is_in_range(const uint64_t val, const uint64_t start, const bool start_incl, const uint64_t end, const bool end_incl) const {
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

[[nodiscard]] int compare_range(const omds::btree::BtreeKey* const s, const bool start_incl, const omds::btree::BtreeKey* const e,
                      const bool end_incl) const {
        DynamicPageAllocCacheEntry* start = (DynamicPageAllocCacheEntry*)s;
        DynamicPageAllocCacheEntry* end = (DynamicPageAllocCacheEntry*)e;

        int ret = is_in_range(this->get_free_atoms_count(), start->get_free_atoms_count(), start_incl,
                              end->get_free_atoms_count(), end_incl);
        if (ret != 0) { return ret; }

        ret = is_in_range(this->get_max_contigous_free_atoms(), start->get_max_contigous_free_atoms(), start_incl,
                          end->get_max_contigous_free_atoms(), end_incl);
        if (ret != 0) { return ret; }

        ret = is_in_range(this->get_temperature(), start->get_temperature(), start_incl, end->get_temperature(),
                          end_incl);
        if (ret != 0) { return ret; }

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

    [[nodiscard]] int compare(const omds::btree::BtreeKey* const o) const override {
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

    [[nodiscard]] virtual uint8_t* get_blob(int32_t* const pSize) const {
        *pSize = sizeof(blob_t);
        return (uint8_t*)m_blob;
    }

    virtual void set_blob(const uint8_t* blob, const uint32_t size) {
        assert(size == sizeof(blob));
        m_blob = (blob_t*)blob;
    }

    virtual void copy_blob(const uint8_t* const blob, const uint32_t size) {
        assert(size == sizeof(blob));
        memcpy(m_blob, blob, size);
    }

    [[nodiscard]] virtual uint32_t get_blob_size() const { return (sizeof(DynamicPageAllocCacheEntry)); }

    virtual void set_blob_size(const uint32_t size) {}

    void print() {
        cout << "free_atom_count: " << get_free_atoms_count() << " temp: " << get_temperature()
             << " pageid: " << get_page_id();
    }
};

class DynamicPageAllocEntry {
private:
    uint8_t m_temperature{0}; // Temperature of each blk.

public:
#ifdef DEBUG
    uint32_t m_blkid;
#endif

public:
    DynamicPageAllocEntry() = default;
    DynamicPageAllocEntry(const DynamicPageAllocEntry&) = delete;
    DynamicPageAllocEntry(DynamicPageAllocEntry&&) noexcept = delete;
    DynamicPageAllocEntry& operator=(const DynamicPageAllocEntry&) = delete;
    DynamicPageAllocEntry& operator=(DynamicPageAllocEntry&&) noexcept = delete;

    void set_temperature(const uint8_t t) { m_temperature = t; }

    [[nodiscard]] uint8_t get_temperature() const { return m_temperature; }
} __attribute__((packed));

} // namespace omstorage
