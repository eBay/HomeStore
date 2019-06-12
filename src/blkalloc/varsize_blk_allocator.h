//
// Created by Kadayam, Hari on 14/10/17.
//
#pragma once

#include "blk_allocator.h"
#include <boost/heap/binomial_heap.hpp>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <flip/flip.hpp>
#include <sds_logging/logging.h>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/stringize.hpp>

using namespace homeds::btree;

namespace homestore {
/****************** VarsizeBlkAllocator Section **********************/

// clang-format off

#define BLKALLOC_LOG(level, mod, ...)                         \
    LOG##level##MOD(                                    \
        BOOST_PP_IF(BOOST_PP_IS_EMPTY(mod), base, mod), \
        "[blkalloc = {}]",                              \
        m_cfg.get_name(),                               \
        ##__VA_ARGS__)

#define _BLKALLOC_ASSERT_MSG(asserttype, ...)                           \
    "\n**********************************************************\n"    \
    "[blkalloc = {}\n]", "Metrics = {}\n" "{}"                          \
    "\n**********************************************************\n",   \
    m_cfg.get_name(),                                                   \
    asserttype##_METRICS_DUMP_MSG,                                      \
    sds_logging::format_log_msg(__VA_ARGS__)

// clang-format on

#define BLKALLOC_ASSERT(asserttype, cond, ...)  \
    asserttype##_ASSERT(cond, _BLKALLOC_ASSERT_MSG(asserttype, ##__VA_ARGS__))
#define BLKALLOC_ASSERT_OP(asserttype, optype, val1, val2, ...)   \
    asserttype##_ASSERT_##optype(val1, val2, _BLKALLOC_ASSERT_MSG(asserttype, ##__VA_ARGS__))
#define BLKALLOC_ASSERT_EQ(asserttype, ...) BLKALLOC_ASSERT_OP(asserttype, EQ, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_NE(asserttype, ...) BLKALLOC_ASSERT_OP(asserttype, NE, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_GT(asserttype, ...) BLKALLOC_ASSERT_OP(asserttype, GT, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_GE(asserttype, ...) BLKALLOC_ASSERT_OP(asserttype, GE, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_LT(asserttype, ...) BLKALLOC_ASSERT_OP(asserttype, LT, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_LE(asserttype, ...) BLKALLOC_ASSERT_OP(asserttype, LE, ##__VA_ARGS__)
#define BLKALLOC_DEBUG_ASSERT(...)          BLKALLOC_ASSERT(DEBUG, __VA_ARGS__)
#define BLKALLOC_RELEASE_ASSERT(...)        BLKALLOC_ASSERT(RELEASE, __VA_ARGS__)
#define BLKALLOC_LOG_ASSERT(...)            BLKALLOC_ASSERT(LOGMSG, __VA_ARGS__)
#define BLKALLOC_DEBUG_ASSERT_CMP(optype, ...)      \
                                            BLKALLOC_ASSERT_OP(DEBUG, optype, ##__VA_ARGS__)
#define BLKALLOC_RELEASE_ASSERT_CMP(optype, ...)    \
                                            BLKALLOC_ASSERT_OP(RELEASE, optype, ##__VA_ARGS__)
#define BLKALLOC_LOG_ASSERT_CMP(optype, ...)        \
                                            BLKALLOC_ASSERT_OP(LOGMSG, optype, ##__VA_ARGS__)

template <typename T>
struct atomwrapper {
    std::atomic<T> _a;
    atomwrapper(T val) : _a(val) {}
    atomwrapper(const std::atomic<T> &a) : _a(a.load()) {}
    atomwrapper(const atomwrapper &other) : _a(other._a.load()) {}
    atomwrapper &operator=(const atomwrapper &other) { _a.store(other._a.load()); }
};

class VarsizeBlkAllocConfig : public BlkAllocConfig {
private:
    uint32_t m_phys_page_size;
    uint32_t m_nsegments;
    uint32_t m_blks_per_portion;
    uint32_t m_blks_per_temp_group;
    uint64_t m_max_cache_blks;
    std::vector<uint32_t> m_slab_nblks;
    std::vector<uint32_t> m_slab_capacity;

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
    VarsizeBlkAllocConfig(uint64_t blk_size, uint64_t n_blks, const std::string& name) :
            BlkAllocConfig(blk_size, n_blks, name),
            m_nsegments(1),
            m_blks_per_portion(n_blks),
            m_blks_per_temp_group(n_blks),
            m_max_cache_blks(0) {
    }

    //! Set Physical Page Size
    /*!
      \param page_size an uint32 argument
      \return void
    */
    void set_phys_page_size(uint32_t page_size) {
        m_phys_page_size = page_size;
    }

    //! Set Total Segments
    /*!
      \param nsegments an uint32 argument signifies number of segments
      \return void
    */
    void set_total_segments(uint32_t nsegments) {
        m_nsegments = nsegments;
    }

    //! Set Blocks per Portion
    /*!
      \param pg_per_portion an uint32 argument signifies pages per portion
      \return void
    */
    void set_blks_per_portion(uint32_t pg_per_portion) {
        assert(pg_per_portion % get_blks_per_phys_page() == 0);
        m_blks_per_portion = pg_per_portion;
    }

    //! Set Max Cache Blocks
    /*!
      \param ncache_entries an uint32 argument signifies max blocks in cache
      \return void
    */
    void set_max_cache_blks(uint64_t ncache_entries) {
        m_max_cache_blks = ncache_entries;
    }
    
    //! Set Block Count per Slab
    /*!
      \param nblks a uint32 vector argument signifies block count for all slabs
      \param weights a float vector argument signifies weights for all slabs
      \return void
    */
    void set_slab(  std::vector<uint32_t> nblks,
                    std::vector<float> weights  ) {
        assert(nblks.size()+1 == weights.size());
        m_slab_nblks.swap(nblks);
        for (auto i = 0U; i < weights.size(); i++) {
            m_slab_capacity.push_back((uint32_t)(m_max_cache_blks*weights[i]));
        }
    }

    //! Set Blocks per Temp group
    /*!
      \param npgs_per_temp_group an uint64 argument signifies number of pages per temp group
      \return void
    */
    void set_blks_per_temp_group(uint64_t npgs_per_temp_group) {
        m_blks_per_temp_group = npgs_per_temp_group;
    }

    //! Get Physical Page Size
    /*!
      \return physical page size as uint32
    */
    uint32_t get_phys_page_size() const {
        return m_phys_page_size;
    }

    //! Get Total Segments
    /*!
      \return number of segments as uint32
    */
    uint32_t get_total_segments() const {
        return m_nsegments;
    }

    //! Get Blocks per Portion
    /*!
      \return blocks per portion as uint64
    */
    uint64_t get_blks_per_portion() const {
        return m_blks_per_portion;
    }

    //! Get Blocks per Segment
    /*!
      \return blocks per segment as uint64
    */
    uint64_t get_blks_per_segment() const {
        return (uint64_t) (get_total_blks() / get_total_segments());
    }

    //! Get Total Portions
    /*!
      \return portion count as uint64
    */
    uint64_t get_total_portions() const {
        assert(get_total_blks() % get_blks_per_portion() == 0);
            return get_total_blks() / get_blks_per_portion();
    }

    //! Get Max Cache Blocks
    /*!
      \return max cache blocks as uint64
    */
    uint64_t get_max_cache_blks() const {
        return m_max_cache_blks;
    }

    //! Get Blocks per Temp Group
    /*!
      \return blocks per temp group as uint64
    */
    uint64_t get_blks_per_temp_group() const {
        return m_blks_per_temp_group;
    }

    //! Get Blocks per Physical Page
    /*!
      \return blocks per physical page as uint32
    */
    uint32_t get_blks_per_phys_page() const {
        return get_phys_page_size() / get_blk_size();
    }

    //! Get Temp Group Count
    /*!
      \return temp group count as uint32
    */
    uint32_t get_total_temp_group() const {
        if (get_total_blks() % get_blks_per_temp_group() == 0) {
            return (uint32_t) (get_total_blks() / get_blks_per_temp_group());
        } else {
            return (uint32_t) ((get_total_blks() / get_blks_per_temp_group()) + 1);
        }
    }

    //! Get Slab Count
    /*!
      \return slab count as uint32
    */
    uint32_t get_slab_cnt() const {
        return m_slab_capacity.size();
    }

    //! Get Slab Capacity
    /*!
      \return slab capacity as uint32
    */
    uint32_t get_slab_capacity(uint32_t index) const {
        return m_slab_capacity[index];
    }

    //! Get slab
    /*!
      \param nblks an uint32 argument signifies number of blocks
      \return slab index and capacity as a std::pair of uint32s
    */
    std::pair<uint32_t,uint32_t> get_slab(uint32_t nblks) const {
        uint32_t i = m_slab_nblks.size();
        for(; i > 0 && nblks < m_slab_nblks[i-1]; i--);
        return std::make_pair(i, m_slab_capacity[i]);
    }

    //! Get lower bound of a particular slab
    /*!
      \param indx an uint32 argument signifies slab index
      \return lower bound of slab pointed by indx as uint32
    */
    uint32_t get_slab_lower_bound(uint32_t indx) const {
        /* m_slab_nblks[i] has the blocks from m_slab_nblks[i - 1] to m_slab_nblks[i] */
        return(m_slab_nblks[indx - 1]);
    }

    std::string to_string() {
        std::stringstream ss;
        ss << BlkAllocConfig::to_string() << " Pagesize=" << get_phys_page_size() << " Totalsegments="
           << get_total_segments()
           << " BlksPerPortion=" << get_blks_per_portion() << " MaxCacheBlks=" << get_max_cache_blks();
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
    std::atomic<uint64_t> m_free_blks = 0;
    uint64_t m_total_blks;
    uint64_t m_total_portions;
    uint32_t m_seg_num; // Segment sequence number

public:
    BlkAllocSegment(uint64_t nblks, uint32_t seg_num, uint64_t nportions) :
                m_total_portions(nportions) {
        set_total_blks(nblks);
        add_free_blks(nblks);
        set_seg_num(seg_num);
        set_clock_hand(0);
    }

    virtual ~BlkAllocSegment() {
    }

    uint64_t get_clock_hand() const {
        return m_alloc_clock_hand % m_total_portions;
    }

    void set_clock_hand(uint64_t hand) {
        m_alloc_clock_hand = hand;
    }

    void inc_clock_hand() {
        ++m_alloc_clock_hand;
    }

    bool operator<(BlkAllocSegment &other_seg) const {
        return (this->get_free_blks() < other_seg.get_free_blks());
    }

    void add_free_blks(uint64_t nblks) {
        m_free_blks.fetch_add(nblks, std::memory_order_acq_rel);
    }

    void remove_free_blks(uint64_t nblks) {
        if (get_free_blks() < nblks) return;
        m_free_blks.fetch_sub(nblks, std::memory_order_acq_rel);
    }

    uint64_t get_free_blks() const {
        return m_free_blks.load(std::memory_order_acq_rel);
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

class VarsizeAllocCacheEntry : public BtreeKey {
private:
    typedef struct __attribute__((packed, aligned(1))) {
        uint64_t m_phys_page_id:36; // Page id and blk num inside page
        uint64_t m_blk_num:36;
        uint64_t m_nblks:10;   // Total number of blocks
        uint64_t m_temp :14;   // Temperature of each page
    } blob_t;

    blob_t *m_blob;
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

    explicit VarsizeAllocCacheEntry(const VarsizeAllocCacheEntry& other) {
        copy_blob(other.get_blob());
    }

    VarsizeAllocCacheEntry& operator=(const VarsizeAllocCacheEntry& other) {
        copy_blob(other.get_blob());
        return *this;
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

    void set_phys_page_id(uint64_t page_id) {
        m_blob->m_phys_page_id = page_id;
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

    uint64_t get_phys_page_id() const {
        return (uint32_t) (m_blob->m_phys_page_id);
    }

    int compare(const BtreeKey *o) const override;
    int compare_range(const BtreeSearchRange &range) const override;

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

class BlkAllocMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BlkAllocMetrics(const char* inst_name) :
                sisl::MetricsGroupWrapper("BlkAlloc", inst_name) {
        REGISTER_COUNTER(   blkalloc_slab0_capacity,
                            "Block allocator slab 0 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab1_capacity,
                            "Block allocator slab 1 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab2_capacity,
                            "Block allocator slab 2 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab3_capacity,
                            "Block allocator slab 3 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab4_capacity,
                            "Block allocator slab 4 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab5_capacity,
                            "Block allocator slab 5 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab6_capacity,
                            "Block allocator slab 6 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab7_capacity,
                            "Block allocator slab 7 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab8_capacity,
                            "Block allocator slab 8 capacity",
                            sisl::_publish_as::publish_as_gauge );
        REGISTER_COUNTER(   blkalloc_slab9_capacity,
                            "Block allocator slab 9 capacity",
                            sisl::_publish_as::publish_as_gauge );
        register_me_to_farm();
    }
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

#define VarsizeBlkAllocatorBtree Btree< btree_store_type::MEM_BTREE, VarsizeAllocCacheEntry, \
                                                     EmptyClass, btree_node_type::SIMPLE, \
                                                     btree_node_type::SIMPLE>

/* VarsizeBlkAllocator provides a flexibility in allocation. It provides following features:
 *
 * 1. Could allocate variable number of blks in single allocation
 * 2. Provides the option of allocating blocks based on requested temperature.
 * 3. Caching of available blocks instead of scanning during allocation.
 *
 */
class VarsizeBlkAllocator : public BlkAllocator {
    uint32_t m_last_indx = 0 ;
public:
    VarsizeBlkAllocator(VarsizeBlkAllocConfig &cfg, bool init);
    virtual ~VarsizeBlkAllocator();

    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints &hints,
                        BlkId *out_blkid, bool best_fit = false) override;
    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints &hints, 
                                 std::vector<BlkId> &out_blkid) override;
    void free(const BlkId &b) override;

    std::string to_string() const override;
    void allocator_state_machine();

    virtual BlkAllocStatus alloc(BlkId &out_blkid) override;
    virtual void inited() override;
    virtual bool is_blk_alloced(BlkId &in_bid) override;

private:
    VarsizeBlkAllocConfig m_cfg; // Config for Varsize
    std::thread m_thread_id; // Thread pointer for this region
    std::mutex m_mutex;    // Mutex to protect regionstate & cb
    std::condition_variable m_cv; // CV to signal thread
    BlkAllocatorState m_region_state;

    homeds::Bitset *m_alloc_bm;   // Bitset of all allocation

#ifndef NDEBUG
    homeds::Bitset *m_alloced_bm;   // Bitset of all allocation
#endif

    VarsizeBlkAllocatorBtree *m_blk_cache; // Blk Entry caches

    std::vector<BlkAllocSegment*> m_segments; // Lookup map for segment id - segment
    BlkAllocSegment *m_wait_alloc_segment = nullptr; // A flag/hold variable, for caller thread
    // to pass which segment to look for sweep

    // Overall page and page group tables
    std::vector< BlkAllocPortion > m_blk_portions;
    std::vector< BlkAllocTemperatureGroup > m_temp_groups;

    std::atomic< uint32_t > m_cache_n_entries; // Total number of blk entries to cache
    std::vector<atomwrapper<uint32_t>> m_slab_entries; // Blk cnt for each slab in cache
    BlkAllocMetrics m_metrics;
    bool m_init;

private:
    const VarsizeBlkAllocConfig &get_config() const override {
        return (VarsizeBlkAllocConfig &) m_cfg;
    }
    uint64_t get_portions_per_segment();

    // Thread related functions
    std::string state_string(BlkAllocatorState state) const;

    // Sweep and cache related functions
    void request_more_blks(BlkAllocSegment *seg = nullptr);
    void request_more_blks_wait(BlkAllocSegment *seg = nullptr);
    void fill_cache(BlkAllocSegment *seg);
    uint64_t fill_cache_in_portion(uint64_t portion_num, BlkAllocSegment *seg);

    // Convenience routines
    uint64_t blknum_to_phys_pageid(uint64_t blknum) const {
        return blknum / get_config().get_blks_per_phys_page();
    }

    uint32_t offset_within_phys_page(uint64_t blknum) const {
        return blknum % get_config().get_blks_per_phys_page();
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

    uint64_t blknum_to_segment_num(uint64_t blknum) const {
        auto seg_num = blknum / get_config().get_blks_per_segment();
        assert(seg_num < m_cfg.get_total_segments());
        return seg_num;
    }

    BlkAllocSegment *blknum_to_segment(uint64_t blknum) const {
        return m_segments[blknum_to_segment_num(blknum)];
    }

    uint32_t blknum_to_tempgroup_num(uint64_t blknum) const {
        return ((uint32_t) blknum / get_config().get_blks_per_temp_group());
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
        out_entry->set_phys_page_id(blknum_to_phys_pageid(blknum));
        out_entry->set_temperature(get_blk_temperature(blknum));
    }
    uint64_t get_best_fit_cache(uint64_t blks_rqstd);
    void incrCounter(unsigned int index, unsigned int val);
    void decrCounter(unsigned int index, unsigned int val);
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
