//
// Created by Kadayam, Hari on 14/10/17.
//
#pragma once

#include "blk_allocator.h"
#include <boost/heap/binomial_heap.hpp>
#include <condition_variable>

namespace homestore {
/****************** VarsizeBlkAllocator Section **********************/

class VarsizeBlkAllocConfig : public BlkAllocConfig {
private:
    uint32_t m_page_size;
    uint32_t m_nsegments;
    uint32_t m_pages_per_portion;
    uint32_t m_pages_per_temp_group;
    uint64_t m_max_cache_blks;
    uint64_t m_max_chunk_blks;
    uint32_t m_max_chunk_size;

public:
    VarsizeBlkAllocConfig() : VarsizeBlkAllocConfig(0, 0) {
    }

    VarsizeBlkAllocConfig(uint64_t blk_size, uint64_t n_blks) :
            BlkAllocConfig(blk_size, n_blks),
            m_page_size(8192),
            m_nsegments(1),
            m_pages_per_portion(n_blks),
            m_pages_per_temp_group(n_blks),
            m_max_cache_blks(0) {
    }

    void set_page_size(uint32_t page_size) {
        m_page_size = page_size;
    }

    void set_total_segments(uint32_t nsegments) {
        m_nsegments = nsegments;
    }

    void set_pages_per_portion(uint32_t pg_per_portion) {
        m_pages_per_portion = pg_per_portion;
    }

    void set_max_cache_blks(uint64_t ncache_entries) {
        m_max_cache_blks = ncache_entries;
    }
    
    void set_max_cache_chunks(uint64_t ncache_entries) {
        m_max_chunk_blks = ncache_entries;
    }

    void set_chunk_size(uint32_t size) {
        m_max_chunk_size = size;
    }

    void set_pages_per_temp_group(uint64_t npgs_per_temp_group) {
        m_pages_per_temp_group = npgs_per_temp_group;
    }

    uint32_t get_page_size() const {
        return m_page_size;
    }

    uint64_t get_total_pages() const {
        assert ((get_total_blks() * get_blk_size() % 
                   (get_page_size() * get_pages_per_portion())) == 0);
        return get_total_blks() * get_blk_size() / get_page_size();
    }

    uint32_t get_blks_per_page() const {
        assert(get_page_size() % get_blk_size() == 0);
        return (uint32_t) (get_page_size() / get_blk_size());
    }

    uint32_t get_total_segments() const {
        return m_nsegments;
    }

    uint64_t get_pages_per_portion() const {
        return m_pages_per_portion;
    }

    uint64_t get_blks_per_portion() const {
        return get_pages_per_portion() * get_blks_per_page();
    }

    uint64_t get_total_portions() const {
        assert(get_total_pages() % get_pages_per_portion() == 0);
            return get_total_pages() / get_pages_per_portion();
    }

    uint64_t get_max_cache_blks() const {
        return m_max_cache_blks;
    }

    uint64_t get_pages_per_temp_group() const {
        return m_pages_per_temp_group;
    }

    uint32_t get_total_temp_group() const {
        if (get_total_pages() % get_pages_per_temp_group() == 0) {
            return (uint32_t) (get_total_pages() / get_pages_per_temp_group());
        } else {
            return (uint32_t) ((get_total_pages() / get_pages_per_temp_group()) + 1);
        }
    }
    
    uint64_t get_max_cache_chunks() const {
        return(m_max_chunk_blks);
    }

    uint32_t get_chunk_size() const {
        return(m_max_chunk_size);
    }

    std::string to_string() {
        std::stringstream ss;
        ss << BlkAllocConfig::to_string() << " Pagesize=" << get_page_size() << " Totalsegments="
           << get_total_segments()
           << " PagesPerPortion=" << get_pages_per_portion() << " MaxCacheBlks=" << get_max_cache_blks();
        return ss.str();
    }
};

class BlkAllocSegment {
public:
    class CompareSegAvail {
    public:
        bool operator()(BlkAllocSegment *seg1, BlkAllocSegment *seg2) const {
            return (seg1->get_free_blks() < seg2->get_free_blks());
        }
    };

    //typedef boost::heap::binomial_heap< BlkAllocSegment *, boost::heap::compare< BlkAllocSegment::CompareSegAvail>> SegQueue;
    typedef boost::heap::binomial_heap< BlkAllocSegment *, boost::heap::compare< CompareSegAvail>> SegQueue;

private:
    uint64_t m_alloc_clock_hand;
    uint64_t m_free_blks;
    uint64_t m_total_blks;
    uint32_t m_seg_num; // Segment sequence number
    SegQueue::handle_type m_seg_id;   // Opaque segment Id.

public:
    BlkAllocSegment(uint64_t nblks, uint32_t seg_num) {
        set_total_blks(nblks);
        set_free_blks(nblks);
        set_seg_num(seg_num);
        set_clock_hand(0);
    }

    virtual ~BlkAllocSegment() {
    }

    uint64_t get_clock_hand() const {
        return m_alloc_clock_hand;
    }

    void set_clock_hand(uint64_t hand) {
        m_alloc_clock_hand = hand;
    }

    void inc_clock_hand() {
        if (m_alloc_clock_hand == m_total_blks) {
            m_alloc_clock_hand = 0;
        } else {
            m_alloc_clock_hand++;
        }
    }

    bool operator<(BlkAllocSegment &other_seg) const {
        return (this->get_free_blks() < other_seg.get_free_blks());
    }

    void set_free_blks(uint64_t nblks) {
        m_free_blks = nblks;
    }

    uint64_t get_free_blks() const {
        return m_free_blks;
    }

    void set_total_blks(uint64_t a) {
        m_total_blks = a;
    }

    uint64_t get_total_blks() const {
        return m_total_blks;
    }

    void set_seg_num(uint32_t n) {
        m_seg_num = n;
    }

    uint32_t get_seg_num() const {
        return m_seg_num;
    }

    void set_segment_id(SegQueue::handle_type &seg_id) {
        m_seg_id = seg_id;
    }

    SegQueue::handle_type get_segment_id() const {
        return m_seg_id;
    }
};

class BlkAllocPortion {
private:
    pthread_mutex_t m_blk_lock;

public:
#ifndef NDEBUG
    uint32_t m_blk_portion_id;
#endif

    BlkAllocPortion() {
        pthread_mutex_init(&m_blk_lock, NULL);
    }

    ~BlkAllocPortion() {
        pthread_mutex_destroy(&m_blk_lock);
    }

    void lock() {
        pthread_mutex_lock(&m_blk_lock);
    }

    void unlock() {
        pthread_mutex_unlock(&m_blk_lock);
    }
};

class BlkAllocTemperatureGroup {
private:
    uint8_t m_temperature; // Temperature of the group.

public:
#ifndef NDEBUG
    uint32_t m_temp_group_id;
#endif

public:
    void set_temperature(uint8_t t) {
        m_temperature = t;
    }

    uint8_t get_temperature() const {
        return m_temperature;
    }
}__attribute__((packed));

class VarsizeAllocCacheEntry : public homeds::btree::BtreeKey {
private:
    typedef struct __attribute__((packed)) {
        uint64_t m_page_id:36; // Page id and blk num inside page
        uint64_t m_blk_num:36;
        uint64_t m_nblks:10;   // Total number of blocks
        uint64_t m_temp :10;   // Temperature of each page
	uint64_t padd:28; // will be removed later
    } blob_t;

    blob_t *m_blob;
    blob_t m_in_place_blob;

public:
    VarsizeAllocCacheEntry() {
        m_blob = &m_in_place_blob;
        set_page_id(0UL);
        set_blk_num(0UL);
        set_blk_count(0U);
        set_temperature(0U);
    }

    VarsizeAllocCacheEntry(uint64_t page_id, uint64_t blknum, uint32_t nblks, uint32_t temp) {
        m_blob = &m_in_place_blob;
        set_page_id(page_id);
        set_blk_num(blknum);
        set_blk_count(nblks);
        set_temperature(temp);
    }

    void set_blk_num(uint64_t blknum) {
        m_blob->m_blk_num = blknum;
    }

    void set_blk_count(uint32_t blkcount) {
        m_blob->m_nblks = blkcount;
    }

    void set_temperature(uint32_t temp) {
        m_blob->m_temp = temp;
    }

    void set_page_id(uint64_t page_id) {
        m_blob->m_page_id = page_id;
    }

    uint64_t get_blk_num() const {
        return (m_blob->m_blk_num);
    }

    uint32_t get_blk_count() const {
        return (uint32_t) (m_blob->m_nblks);
    }

    uint32_t get_temperature() const {
        return (uint32_t) (m_blob->m_temp);
    }

    uint64_t get_page_id() const {
        return (uint32_t) (m_blob->m_page_id);
    }

    int compare(const homeds::btree::BtreeKey *o) const override;
    int compare_range(const homeds::btree::BtreeSearchRange &range) const override;

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.bytes = (uint8_t *)m_blob;
        b.size = sizeof(blob_t);
        return b;
    }

    void set_blob(const homeds::blob &b) override {
        assert(b.size == sizeof(blob_t));
        m_blob = (blob_t *)b.bytes;
    }

    void copy_blob(const homeds::blob &b) override {
        assert(b.size == sizeof(blob_t));
        memcpy(&m_in_place_blob, b.bytes, b.size);
        m_blob = &m_in_place_blob;
    }

    uint32_t get_blob_size() const override {
        return (sizeof(blob_t));
    }

    static uint32_t get_fixed_size() {
        return (sizeof(blob_t));
    }

    void set_blob_size(uint32_t size) override {
    }

    void print() {
        cout << "free blk count: " << get_blk_count() << " temp: " << get_temperature() << " blknum: "
             << get_blk_num();
    }

    std::string to_string() const  {
        std::stringstream ss;
        ss << "free blk count: " << get_blk_count() << " temp: " << get_temperature() << " blknum: " << get_blk_num();
        return ss.str();
    }

private:
    int is_in_range(uint64_t val, uint64_t start, bool start_incl, uint64_t end, bool end_incl) const;

#if 0
    int compare_range(const VarsizeAllocCacheEntry *start, bool start_incl, const VarsizeAllocCacheEntry *end,
                      bool end_incl) const;
#endif
};

#if 0
class VarsizeAllocCacheSearch : public homeds::btree::BtreeSearchRange {
public:
    VarsizeAllocCacheSearch(VarsizeAllocCacheEntry &start_entry, bool start_incl,
                            VarsizeAllocCacheEntry &end_entry, bool end_incl,
                            bool left_leaning, VarsizeAllocCacheEntry *out_entry) :
            homeds::btree::BtreeSearchRange(start_entry, start_incl, end_entry, end_incl, left_leaning) {}

    bool is_full_match(homeds::btree::BtreeRangeKey *rkey) const override {
        return true;
    }

    int compare(homeds::btree::BtreeKey *other) const override {
        assert(0); // Comparision of 2 search keys is not required feature yet.
        homeds::btree::BtreeSearchRange *regex = (homeds::btree::BtreeSearchRange *) other;
        return 0;
    }

    uint8_t *get_blob(uint32_t *psize) const override {
        return nullptr;
    }

    void set_blob(const uint8_t *blob, uint32_t size) override {
    }

    void copy_blob(const uint8_t *blob, uint32_t size) override {
    }

    uint32_t get_blob_size() const override {
        return 0;
    }

    void set_blob_size(uint32_t size) override {
    }
};
#endif

#define VarsizeBlkAllocatorBtree homeds::btree::Btree< homeds::btree::MEM_BTREE, VarsizeAllocCacheEntry, \
                                                     homeds::btree::EmptyClass, homeds::btree::BTREE_NODETYPE_SIMPLE, \
                                                     homeds::btree::BTREE_NODETYPE_SIMPLE>

/* VarsizeBlkAllocator provides a flexibility in allocation. It provides following features:
 *
 * 1. Could allocate variable number of blks in single allocation
 * 2. Provides the option of allocating blocks based on requested temperature.
 * 3. Caching of available blocks instead of scanning during allocation.
 *
 */
class VarsizeBlkAllocator : public BlkAllocator {
public:
    VarsizeBlkAllocator(VarsizeBlkAllocConfig &cfg);
    virtual ~VarsizeBlkAllocator();

    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints &hints, BlkId *out_blkid, bool retry = true) override;
    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints &hints, 
                                 std::vector<BlkId> &out_blkid) override;
    void free(const BlkId &b) override;

    std::string to_string() const override;
    void allocator_state_machine();

private:
    VarsizeBlkAllocConfig m_cfg; // Config for Varsize
    std::thread m_thread_id; // Thread pointer for this region
    std::mutex m_mutex;    // Mutex to protect regionstate & cb
    std::condition_variable m_cv; // CV to signal thread
    BlkAllocatorState m_region_state;

    homeds::Bitset *m_alloc_bm;   // Bitset of all allocation

#ifndef DEBUG
    homeds::Bitset *m_alloced_bm;   // Bitset of all allocation
#endif

    VarsizeBlkAllocatorBtree *m_blk_cache; // Blk Entry caches

    BlkAllocSegment::SegQueue m_heap_segments;  // Heap of segments within a region.
    BlkAllocSegment *m_wait_alloc_segment; // A flag/hold variable, for caller thread
    // to pass which segment to look for sweep

    // Overall page and page group tables
    std::vector< BlkAllocPortion > m_blk_portions;
    std::vector< BlkAllocTemperatureGroup > m_temp_groups;

    std::atomic< uint32_t > m_cache_n_entries; // Total number of page entries to cache
    std::atomic< uint32_t > m_cache_chunk_entries; // Total number of page entries to cache

private:
    const VarsizeBlkAllocConfig &get_config() const override {
        return (VarsizeBlkAllocConfig &) m_cfg;
    }

    // Thread related functions
    std::string state_string(BlkAllocatorState state) const;

    // Sweep and cache related functions
    void request_more_blks(BlkAllocSegment *seg = nullptr);
    void request_more_blks_wait(BlkAllocSegment *seg = nullptr);
    void fill_cache(BlkAllocSegment *seg);
    uint64_t fill_cache_in_portion(uint64_t portion_num, BlkAllocSegment *seg);

    // Convenience routines
    uint64_t blknum_to_pageid(uint64_t blknum) const {
        return blknum / get_config().get_blks_per_page();
    }

    uint32_t offset_within_page(uint64_t blknum) const {
        return blknum % get_config().get_blks_per_page();
    }

    uint64_t blknum_to_portion_num(uint64_t blknum) const {
        return blknum / get_config().get_blks_per_portion();
    }

    BlkAllocPortion *blknum_to_portion(uint64_t blknum) {
        return &m_blk_portions[blknum_to_portion_num(blknum)];
    }

    const BlkAllocPortion *blknum_to_portion_const(uint64_t blknum) const {
        return &m_blk_portions[blknum_to_portion_num(blknum)];
    }

    uint32_t blknum_to_tempgroup_num(uint64_t blknum) const {
        return (uint32_t) (blknum_to_pageid(blknum) / get_config().get_pages_per_temp_group());
    }

    const BlkAllocTemperatureGroup *blknum_to_tempgroup_const(uint64_t blknum) const {
        return &m_temp_groups[blknum_to_tempgroup_num(blknum)];
    }

    BlkAllocTemperatureGroup *blknum_to_tempgroup(uint64_t blknum) {
        return &m_temp_groups[blknum_to_tempgroup_num(blknum)];
    }

    uint8_t get_blk_temperature(uint64_t blknum) const {
        return blknum_to_tempgroup_const(blknum)->get_temperature();
    }

    void set_blk_temperature(uint64_t blknum, uint8_t t) {
        blknum_to_tempgroup(blknum)->set_temperature(t);
    }

    // This method generates a cache entry based on given blknumber and count.
    void gen_cache_entry(uint64_t blknum, uint32_t blk_count, VarsizeAllocCacheEntry *out_entry) {
        out_entry->set_blk_num(blknum);
        out_entry->set_blk_count(blk_count);
        out_entry->set_page_id(blknum_to_pageid(blknum));
        out_entry->set_temperature(get_blk_temperature(blknum));
    }
};

#define BLKID_RANGE_FIRST    0UL
#define PAGEID_RANGE_FIRST   0UL
#define BLKCOUNT_RANGE_FIRST 0U
#define TEMP_RANGE_FIRST     0U

#define BLKID_RANGE_LAST     (uint64_t)-1
#define PAGEID_RANGE_LAST    (uint32_t)-1
#define BLKCOUNT_RANGE_LAST  (uint32_t)-1
#define TEMP_RANGE_LAST      (uint32_t)-1

} // namespace homestore
