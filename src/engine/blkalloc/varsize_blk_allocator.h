//
// Created by Kadayam, Hari on 14/10/17.
//
#pragma once

#include <atomic>
#include <condition_variable>
#include <vector>

#include <boost/heap/binomial_heap.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <flip/flip.hpp>
#include <metrics/metrics.hpp>
#include <sds_logging/logging.h>

#include "engine/common/homestore_assert.hpp"

#include "blk_allocator.h"

using namespace homeds::btree;

namespace homestore {
/****************** VarsizeBlkAllocator Section **********************/

template < typename T >
struct atomwrapper {
    std::atomic< T > _a;
    atomwrapper(T val) : _a(val) {}
    atomwrapper(const std::atomic< T >& a) : _a(a.load()) {}
    atomwrapper(const atomwrapper& other) : _a(other._a.load()) {}
    atomwrapper& operator=(const atomwrapper& other) { _a.store(other._a.load()); }
};

class VarsizeBlkAllocConfig : public BlkAllocConfig {
private:
    uint32_t m_phys_page_size;
    uint32_t m_nsegments;
    uint32_t m_blks_per_temp_group;
    uint64_t m_max_cache_blks;
    std::vector< uint32_t > m_slab_nblks;
    std::vector< uint32_t > m_slab_capacity;

public:
    //! VarsizeBlkAllocConfig constructor type 1
    /*!
      Default constructor
    */
    VarsizeBlkAllocConfig() : VarsizeBlkAllocConfig(0, 0, "") {}

    //! VarsizeBlkAllocConfig constructor type 2
    /*!
      \param name as std::string argument signifies name of block allocator
    */
    VarsizeBlkAllocConfig(const std::string& name) : VarsizeBlkAllocConfig(0, 0, name) {}

    //! VarsizeBlkAllocConfig constructor type 3
    /*!
      \param blk_size as uint64 argument signifies block size
      \param n_blks as uint64 argument signifies number of blocks
      \param name as std::string argument signifies name of block allocator
    */
    VarsizeBlkAllocConfig(const uint64_t blk_size, const uint64_t n_blks, const std::string& name) :
            BlkAllocConfig(blk_size, n_blks, name),
            m_nsegments(1),
            m_blks_per_temp_group(n_blks),
            m_max_cache_blks(0) {}

    VarsizeBlkAllocConfig(const VarsizeBlkAllocConfig& other) :
            BlkAllocConfig{other},
            m_phys_page_size{other.m_phys_page_size},
            m_nsegments{other.m_nsegments},
            m_blks_per_temp_group{other.m_blks_per_temp_group},
            m_max_cache_blks{other.m_max_cache_blks},
            m_slab_nblks{other.m_slab_nblks},
            m_slab_capacity{other.m_slab_capacity} {}

    VarsizeBlkAllocConfig(VarsizeBlkAllocConfig&&) noexcept = delete;
    VarsizeBlkAllocConfig& operator=(const VarsizeBlkAllocConfig&) = delete;
    VarsizeBlkAllocConfig& operator=(VarsizeBlkAllocConfig&&) noexcept = delete;
    virtual ~VarsizeBlkAllocConfig() override = default;

    //! Set Physical Page Size
    /*!
      \param page_size an uint32 argument
      \return void
    */
    void set_phys_page_size(const uint32_t page_size) { m_phys_page_size = page_size; }

    //! Set Total Segments
    /*!
      \param nsegments an uint32 argument signifies number of segments
      \return void
    */
    void set_total_segments(const uint32_t nsegments) { m_nsegments = nsegments; }

    //! Set Max Cache Blocks
    /*!
      \param ncache_entries an uint32 argument signifies max blocks in cache
      \return void
    */
    void set_max_cache_blks(const uint64_t ncache_entries) { m_max_cache_blks = ncache_entries; }

    //! Set Block Count per Slab
    /*!
      \param nblks a uint32 vector argument signifies block count for all slabs
      \param weights a float vector argument signifies weights for all slabs
      \return void
    */
    void set_slab(std::vector< uint32_t >& nblks, const std::vector< float >& weights) {
        assert(nblks.size() + 1 == weights.size());
        m_slab_nblks.swap(nblks);
        for (auto i = 0U; i < weights.size(); i++) {
            m_slab_capacity.push_back((uint32_t)(m_max_cache_blks * weights[i]));
        }
    }

    //! Set Blocks per Temp group
    /*!
      \param npgs_per_temp_group an uint64 argument signifies number of pages per temp group
      \return void
    */
    void set_blks_per_temp_group(const uint64_t npgs_per_temp_group) { m_blks_per_temp_group = npgs_per_temp_group; }

    //! Get Physical Page Size
    /*!
      \return physical page size as uint32
    */
    [[nodiscard]] uint32_t get_phys_page_size() const { return m_phys_page_size; }

    //! Get Total Segments
    /*!
      \return number of segments as uint32
    */
    [[nodiscard]] uint32_t get_total_segments() const { return m_nsegments; }

    //! Get Blocks per Segment
    /*!
      \return blocks per segment as uint64
    */
    [[nodiscard]] uint64_t get_blks_per_segment() const { return (uint64_t)(get_total_blks() / get_total_segments()); }

    //! Get Max Cache Blocks
    /*!
      \return max cache blocks as uint64
    */
    [[nodiscard]] uint64_t get_max_cache_blks() const { return m_max_cache_blks; }

    //! Get Blocks per Temp Group
    /*!
      \return blocks per temp group as uint64
    */
    [[nodiscard]] uint64_t get_blks_per_temp_group() const { return m_blks_per_temp_group; }

    //! Get Blocks per Physical Page
    /*!
      \return blocks per physical page as uint32
    */
    [[nodiscard]] uint32_t get_blks_per_phys_page() const {
        uint32_t nblks = get_phys_page_size() / get_blk_size();
        assert(get_blks_per_portion() % nblks == 0);
        return nblks;
    }

    //! Get Temp Group Count
    /*!
      \return temp group count as uint32
    */
    [[nodiscard]] uint32_t get_total_temp_group() const {
        if (get_total_blks() % get_blks_per_temp_group() == 0) {
            return (uint32_t)(get_total_blks() / get_blks_per_temp_group());
        } else {
            return (uint32_t)((get_total_blks() / get_blks_per_temp_group()) + 1);
        }
    }

    //! Get Slab Count
    /*!
      \return slab count as uint32
    */
    [[nodiscard]] uint32_t get_slab_cnt() const { return m_slab_capacity.size(); }

    //! Get Slab Capacity
    /*!
      \return slab capacity as uint32
    */
    [[nodiscard]] uint32_t get_slab_capacity(const uint32_t index) const { return m_slab_capacity[index]; }

    //! Get slab
    /*!
      \param nblks an uint32 argument signifies number of blocks
      \return slab index and capacity as a std::pair of uint32s
    */
    [[nodiscard]] std::pair< uint32_t, uint32_t > get_slab(const uint32_t nblks) const {
        uint32_t i = m_slab_nblks.size();
        for (; i > 0 && nblks < m_slab_nblks[i - 1]; i--)
            ;
        return std::make_pair(i, m_slab_capacity[i]);
    }

    //! Get lower bound of a particular slab
    /*!
      \param indx an uint32 argument signifies slab index
      \return lower bound of slab pointed by indx as uint32
    */
    [[nodiscard]] uint32_t get_slab_lower_bound(const uint32_t indx) const {
        /* m_slab_nblks[i] has the blocks from m_slab_nblks[i - 1] to m_slab_nblks[i] */
        return (m_slab_nblks[indx - 1]);
    }

    [[nodiscard]] std::string to_string() const {
        std::stringstream oSS{};
        oSS << BlkAllocConfig::to_string() << " Pagesize=" << get_phys_page_size()
            << " Totalsegments=" << get_total_segments() << " BlksPerPortion=" << get_blks_per_portion()
            << " MaxCacheBlks=" << get_max_cache_blks();
        return oSS.str();
    }
};

class SegmentMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit SegmentMetrics(const char* seg_name) : sisl::MetricsGroupWrapper("Segment", seg_name) {
        /* Metrics for monitoring fragmentation */
        REGISTER_HISTOGRAM(frag_pct_distribution, "Distribution of fragmentation percentage",
                           HistogramBucketsType(LinearUpto64Buckets));
        register_me_to_farm();
    }

    SegmentMetrics(const SegmentMetrics&) = delete;
    SegmentMetrics(SegmentMetrics&&) noexcept = delete;
    SegmentMetrics& operator=(const SegmentMetrics&) = delete;
    SegmentMetrics& operator=(SegmentMetrics&&) noexcept = delete;
    ~SegmentMetrics() { deregister_me_from_farm(); }
};

class BlkAllocSegment {
public:
    class CompareSegAvail {
    public:
        bool operator()(const BlkAllocSegment* const seg1, const BlkAllocSegment* const seg2) const {
            return (seg1->get_free_blks() < seg2->get_free_blks());
        }
    };

    // typedef boost::heap::binomial_heap< BlkAllocSegment *, boost::heap::compare< BlkAllocSegment::CompareSegAvail>>
    // SegQueue;
    typedef boost::heap::binomial_heap< BlkAllocSegment*, boost::heap::compare< CompareSegAvail > > SegQueue;

private:
    uint64_t m_alloc_clock_hand;
    std::atomic< uint64_t > m_free_blks = 0;
    uint64_t m_total_blks;
    uint64_t m_total_portions;
    uint32_t m_seg_num; // Segment sequence number
    SegmentMetrics m_metrics;

public:
    BlkAllocSegment(const uint64_t nblks, const uint32_t seg_num, const uint64_t nportions,
                    const std::string& seg_name) :
            m_total_portions(nportions), m_metrics(seg_name.c_str()) {
        set_total_blks(nblks);
        add_free_blks(nblks);
        set_seg_num(seg_num);
        set_clock_hand(0);
    }

    BlkAllocSegment(const BlkAllocSegment&) = delete;
    BlkAllocSegment(BlkAllocSegment&&) noexcept = delete;
    BlkAllocSegment& operator=(const BlkAllocSegment&) = delete;
    BlkAllocSegment& operator=(BlkAllocSegment&&) noexcept = delete;
    virtual ~BlkAllocSegment() {}

    [[nodiscard]] uint64_t get_clock_hand() const { return m_alloc_clock_hand % m_total_portions; }

    void set_clock_hand(uint64_t hand) { m_alloc_clock_hand = hand; }

    void inc_clock_hand() { ++m_alloc_clock_hand; }

    bool operator<(const BlkAllocSegment& other_seg) const {
        return (this->get_free_blks() < other_seg.get_free_blks());
    }

    void add_free_blks(const uint64_t nblks) { m_free_blks.fetch_add(nblks, std::memory_order_acq_rel); }

    void remove_free_blks(const uint64_t nblks) {
        if (get_free_blks() < nblks) return;
        m_free_blks.fetch_sub(nblks, std::memory_order_acq_rel);
    }

    [[nodiscard]] uint64_t get_free_blks() const { return m_free_blks.load(std::memory_order_acq_rel); }

    void set_total_blks(const uint64_t a) { m_total_blks = a; }

    [[nodiscard]] uint64_t get_total_blks() const { return m_total_blks; }

    void set_seg_num(const uint32_t n) { m_seg_num = n; }

    [[nodiscard]] uint32_t get_seg_num() const { return m_seg_num; }

    void reportFragmentation(const uint64_t nadded_blks, const uint64_t nfragments) {
        float frag_ratio = (static_cast< float >(nfragments)) / nadded_blks;
        uint32_t scaled_frag_factor = static_cast< uint32_t >(frag_ratio * 64);
        HISTOGRAM_OBSERVE(m_metrics, frag_pct_distribution, scaled_frag_factor);
    }
};

class BlkAllocTemperatureGroup {
private:
    uint8_t m_temperature{0}; // Temperature of the group.

public:
#ifndef NDEBUG
    uint32_t m_temp_group_id;
#endif

public:
    BlkAllocTemperatureGroup() = default;
    BlkAllocTemperatureGroup(const BlkAllocTemperatureGroup&) = delete;
    BlkAllocTemperatureGroup(BlkAllocTemperatureGroup&&) noexcept = delete;
    BlkAllocTemperatureGroup& operator=(const BlkAllocTemperatureGroup&) = delete;
    BlkAllocTemperatureGroup& operator=(BlkAllocTemperatureGroup&&) noexcept = delete;

    void set_temperature(const uint8_t t) { m_temperature = t; }

    [[nodiscard]] uint8_t get_temperature() const { return m_temperature; }
} __attribute__((packed));

class VarsizeAllocCacheEntry : public BtreeKey {
private:
    typedef struct __attribute__((packed, aligned(1))) {
        uint64_t m_phys_page_id : 36; // Page id and blk num inside page
        uint64_t m_blk_num : 36;
        uint64_t m_nblks : 10; // Total number of blocks
        uint64_t m_temp : 14;  // Temperature of each page
    } blob_t;

    blob_t* m_blob;
    blob_t m_in_place_blob;

public:
    VarsizeAllocCacheEntry() {
        m_blob = &m_in_place_blob;
        set_phys_page_id(0UL);
        set_blk_num(0UL);
        set_blk_count(0U);
        set_temperature(0U);
    }

    VarsizeAllocCacheEntry(uint64_t page_id, uint64_t blknum, uint32_t nblks, uint32_t temp) {
        m_blob = &m_in_place_blob;
        set_phys_page_id(page_id);
        set_blk_num(blknum);
        set_blk_count(nblks);
        set_temperature(temp);
    }

    explicit VarsizeAllocCacheEntry(const VarsizeAllocCacheEntry& other) { copy_blob(other.get_blob()); }
    VarsizeAllocCacheEntry& operator=(const VarsizeAllocCacheEntry& other) {
        copy_blob(other.get_blob());
        return *this;
    }

    VarsizeAllocCacheEntry(VarsizeAllocCacheEntry&&) noexcept = delete;
    VarsizeAllocCacheEntry& operator=(VarsizeAllocCacheEntry&&) noexcept = delete;

    virtual ~VarsizeAllocCacheEntry() override = default;

    void set_blk_num(const uint64_t blknum) { m_blob->m_blk_num = blknum; }

    void set_blk_count(const uint32_t blkcount) { m_blob->m_nblks = blkcount; }

    void set_temperature(const uint32_t temp) { m_blob->m_temp = temp; }

    void set_phys_page_id(const uint64_t page_id) { m_blob->m_phys_page_id = page_id; }

    [[nodiscard]] uint64_t get_blk_num() const { return (m_blob->m_blk_num); }

    [[nodiscard]] uint32_t get_blk_count() const { return (uint32_t)(m_blob->m_nblks); }

    [[nodiscard]] uint32_t get_temperature() const { return (uint32_t)(m_blob->m_temp); }

    [[nodiscard]] uint64_t get_phys_page_id() const { return (uint32_t)(m_blob->m_phys_page_id); }

    [[nodiscard]] int compare(const BtreeKey* const o) const override;
    [[nodiscard]] int compare_range(const BtreeSearchRange& range) const override;

    [[nodiscard]] sisl::blob get_blob() const override {
        sisl::blob b;
        b.bytes = (uint8_t*)m_blob;
        b.size = sizeof(blob_t);
        return b;
    }

    void set_blob(const sisl::blob& b) override {
        assert(b.size == sizeof(blob_t));
        m_blob = (blob_t*)b.bytes;
    }

    void copy_blob(const sisl::blob& b) override {
        assert(b.size == sizeof(blob_t));
        memcpy(&m_in_place_blob, b.bytes, b.size);
        m_blob = &m_in_place_blob;
    }

    [[nodiscard]] uint32_t get_blob_size() const override { return (sizeof(blob_t)); }

    [[nodiscard]] static uint32_t get_fixed_size() { return (sizeof(blob_t)); }

    void set_blob_size(const uint32_t size) override {}

    void print() const {
        cout << "free blk count: " << get_blk_count() << " temp: " << get_temperature() << " blknum: " << get_blk_num();
    }

    [[nodiscard]] std::string to_string() const {
        std::stringstream oSS{};
        oSS << "free blk count: " << get_blk_count() << " temp: " << get_temperature() << " blknum: " << get_blk_num();
        return oSS.str();
    }

private:
    [[nodiscard]] int is_in_range(const uint64_t val, const uint64_t start, const bool start_incl, const uint64_t end,
                                  const bool end_incl) const;

#if 0
    [[nodiscard]]int compare_range(const VarsizeAllocCacheEntry *start, const bool start_incl, const VarsizeAllocCacheEntry *end,
                      const bool end_incl) const;
#endif
};

class BlkAllocMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkAllocMetrics(const char* inst_name) : sisl::MetricsGroupWrapper("BlkAlloc", inst_name) {
        REGISTER_COUNTER(blkalloc_slab0_capacity, "Block allocator slab 0 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab1_capacity, "Block allocator slab 1 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab2_capacity, "Block allocator slab 2 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab3_capacity, "Block allocator slab 3 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab4_capacity, "Block allocator slab 4 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab5_capacity, "Block allocator slab 5 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab6_capacity, "Block allocator slab 6 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab7_capacity, "Block allocator slab 7 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab8_capacity, "Block allocator slab 8 capacity",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blkalloc_slab9_capacity, "Block allocator slab 9 capacity",
                         sisl::_publish_as::publish_as_gauge);

        REGISTER_COUNTER(num_alloc, "number of times alloc called");
        REGISTER_COUNTER(alloc_fail, "number of times alloc failed");
        /* In ideal scnario if there are no splits then it should be same as num_alloc */
        REGISTER_COUNTER(num_split, "number of times it split");
        /* It should be zero in ideal scenario */
        REGISTER_COUNTER(num_retry, "number of times it retry because of cache of no blks");
        REGISTER_COUNTER(num_attempts_failed, "number of times it fail to get entry from cache after max retry");
        register_me_to_farm();
    }

    BlkAllocMetrics(const BlkAllocMetrics&) = delete;
    BlkAllocMetrics(BlkAllocMetrics&&) noexcept = delete;
    BlkAllocMetrics& operator=(const BlkAllocMetrics&) = delete;
    BlkAllocMetrics& operator=(BlkAllocMetrics&&) noexcept = delete;
    ~BlkAllocMetrics() { deregister_me_from_farm(); }
};

#if 0
class VarsizeAllocCacheSearch : public BtreeSearchRange {
public:
    VarsizeAllocCacheSearch(VarsizeAllocCacheEntry &start_entry, bool start_incl,
                            VarsizeAllocCacheEntry &end_entry, bool end_incl,
                            bool left_leaning, VarsizeAllocCacheEntry *out_entry) :
            BtreeSearchRange(start_entry, start_incl, end_entry, end_incl, left_leaning) {}

    bool is_full_match(BtreeRangeKey *rkey) const override {
        return true;
    }

    int compare(BtreeKey *other) const override {
        assert(0); // Comparision of 2 search keys is not required feature yet.
        BtreeSearchRange *regex = (BtreeSearchRange *) other;
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

#define VarsizeBlkAllocatorBtree                                                                                       \
    Btree< btree_store_type::MEM_BTREE, VarsizeAllocCacheEntry, EmptyClass, btree_node_type::SIMPLE,                   \
           btree_node_type::SIMPLE >

/* VarsizeBlkAllocator provides a flexibility in allocation. It provides following features:
 *
 * 1. Could allocate variable number of blks in single allocation
 * 2. Provides the option of allocating blocks based on requested temperature.
 * 3. Caching of available blocks instead of scanning during allocation.
 *
 */
class VarsizeBlkAllocator : public BlkAllocator {
    uint32_t m_last_indx = 0;

public:
    VarsizeBlkAllocator(const VarsizeBlkAllocConfig& cfg, const bool init, const uint32_t id);
    VarsizeBlkAllocator(const VarsizeBlkAllocator&) = delete;
    VarsizeBlkAllocator(VarsizeBlkAllocator&&) noexcept = delete;
    VarsizeBlkAllocator& operator=(const VarsizeBlkAllocator&) = delete;
    VarsizeBlkAllocator& operator=(VarsizeBlkAllocator&&) noexcept = delete;
    virtual ~VarsizeBlkAllocator() override;

    BlkAllocStatus alloc(const uint8_t nblks, const blk_alloc_hints& hints, BlkId* const out_blkid,
                         const bool best_fit = false) override;
    BlkAllocStatus alloc(const uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) override;
    void free(const BlkId& b) override;

    [[nodiscard]] std::string to_string() const override;
    void allocator_state_machine();

    virtual void inited() override;
    [[nodiscard]] virtual bool is_blk_alloced(const BlkId& in_bid) const;

private:
    VarsizeBlkAllocConfig m_cfg;  // Config for Varsize
    std::thread m_thread_id;      // Thread pointer for this region
    std::mutex m_mutex;           // Mutex to protect regionstate & cb
    std::condition_variable m_cv; // CV to signal thread
    BlkAllocatorState m_region_state;

    sisl::Bitset* m_cache_bm; // Bitset of all allocation

    VarsizeBlkAllocatorBtree* m_blk_cache; // Blk Entry caches

    std::vector< BlkAllocSegment* > m_segments;      // Lookup map for segment id - segment
    BlkAllocSegment* m_wait_alloc_segment = nullptr; // A flag/hold variable, for caller thread
    int m_wait_slab_indx = -1;
    // to pass which segment to look for sweep

    // Overall page and page group tables
    std::vector< BlkAllocTemperatureGroup > m_temp_groups;

    std::atomic< uint32_t > m_cache_n_entries;             // Total number of blk entries to cache
    std::vector< atomwrapper< uint32_t > > m_slab_entries; // Blk cnt for each slab in cache
    BlkAllocMetrics m_metrics;

private:
    const VarsizeBlkAllocConfig& get_config() const override { return (VarsizeBlkAllocConfig&)m_cfg; }
    [[nodiscard]] uint64_t get_portions_per_segment();

    // Thread related functions
    std::string state_string(BlkAllocatorState state) const;

    // Sweep and cache related functions
    void request_more_blks(BlkAllocSegment* const seg, const int slab_indx);
    void request_more_blks_wait(BlkAllocSegment* const seg, const int slab_indx);
    void fill_cache(BlkAllocSegment** const pSeg, const int slab_indx);
    [[nodiscard]] uint64_t fill_cache_in_portion(const uint64_t portion_num, BlkAllocSegment* const seg);

    // Convenience routines
    [[nodiscard]] uint64_t blknum_to_phys_pageid(const uint64_t blknum) const {
        return blknum / get_config().get_blks_per_phys_page();
    }

    [[nodiscard]] uint32_t offset_within_phys_page(const uint64_t blknum) const {
        return blknum % get_config().get_blks_per_phys_page();
    }

    [[nodiscard]] uint64_t blknum_to_segment_num(const uint64_t blknum) const {
        auto seg_num = blknum / get_config().get_blks_per_segment();
        assert(seg_num < m_cfg.get_total_segments());
        return seg_num;
    }

    [[nodiscard]] BlkAllocSegment* blknum_to_segment(const uint64_t blknum) const {
        return m_segments[blknum_to_segment_num(blknum)];
    }

    [[nodiscard]] uint32_t blknum_to_tempgroup_num(const uint64_t blknum) const {
        return ((uint32_t)blknum / get_config().get_blks_per_temp_group());
    }

    [[nodiscard]] const BlkAllocTemperatureGroup* blknum_to_tempgroup_const(const uint64_t blknum) const {
        return &m_temp_groups[blknum_to_tempgroup_num(blknum)];
    }

    [[nodiscard]] BlkAllocTemperatureGroup* blknum_to_tempgroup(const uint64_t blknum) {
        return &m_temp_groups[blknum_to_tempgroup_num(blknum)];
    }

    [[nodiscard]] uint8_t get_blk_temperature(const uint64_t blknum) const {
        return blknum_to_tempgroup_const(blknum)->get_temperature();
    }

    void set_blk_temperature(const uint64_t blknum, const uint8_t t) {
        blknum_to_tempgroup(blknum)->set_temperature(t);
    }

    // This method generates a cache entry based on given blknumber and count.
    void gen_cache_entry(const uint64_t blknum, const uint32_t blk_count, VarsizeAllocCacheEntry* const out_entry) {
        out_entry->set_blk_num(blknum);
        out_entry->set_blk_count(blk_count);
        out_entry->set_phys_page_id(blknum_to_phys_pageid(blknum));
        out_entry->set_temperature(get_blk_temperature(blknum));
    }
    [[nodiscard]] uint64_t get_best_fit_cache(const uint64_t blks_rqstd) const;
    void incr_counter(const unsigned int index, const unsigned int val);
    void decr_counter(const unsigned int index, const unsigned int val);
};

constexpr uint64_t BLKID_RANGE_FIRST{std::numeric_limits< uint64_t >::min()};
constexpr uint32_t PAGEID_RANGE_FIRST{std::numeric_limits< uint32_t >::min()};
constexpr uint32_t BLKCOUNT_RANGE_FIRST{std::numeric_limits< uint32_t >::min()};
constexpr uint32_t TEMP_RANGE_FIRST{std::numeric_limits< uint32_t >::min()};

constexpr uint64_t BLKID_RANGE_LAST{std::numeric_limits< uint64_t >::max()};
constexpr uint32_t PAGEID_RANGE_LAST{std::numeric_limits< uint32_t >::max()};
constexpr uint32_t BLKCOUNT_RANGE_LAST{std::numeric_limits< uint32_t >::max()};
constexpr uint32_t TEMP_RANGE_LAST{std::numeric_limits< uint32_t >::max()};

} // namespace homestore
