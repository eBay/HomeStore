//
// Created by Kadayam, Hari on 14/10/17.
//
#pragma once

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/heap/binomial_heap.hpp>
#include <flip/flip.hpp>
#include <metrics/metrics.hpp>
#include <sds_logging/logging.h>

#include "blk_allocator.h"
#include "blk_cache.h"
#include "engine/common/homestore_assert.hpp"

namespace homestore {
typedef blk_num_t seg_num_t;

class VarsizeBlkAllocConfig : public BlkAllocConfig {
private:
    uint32_t m_phys_page_size;
    seg_num_t m_nsegments;
    const blk_cap_t m_blks_per_temp_group;
    blk_cap_t m_max_cache_blks;
    SlabCacheConfig m_slab_config;

public:
    VarsizeBlkAllocConfig() : VarsizeBlkAllocConfig(0, 0, "") {}
    VarsizeBlkAllocConfig(const std::string& name) : VarsizeBlkAllocConfig(0, 0, name) {}

    VarsizeBlkAllocConfig(const uint32_t blk_size, const uint64_t size, const std::string& name) :
            BlkAllocConfig{blk_size, size, name},
            m_phys_page_size{HS_STATIC_CONFIG(drive_attr.phys_page_size)},
            m_nsegments{HS_DYNAMIC_CONFIG(blkallocator.max_segments)},
            m_blks_per_temp_group{get_total_blks() / HS_DYNAMIC_CONFIG(blkallocator.num_blk_temperatures)} {
        // Initialize the max cache blks as minimum dictated by the number of blks or memory limits whichever is lower
        const auto size_by_count =
            HS_DYNAMIC_CONFIG(blkallocator.free_blk_cache_count_by_vdev_percent) * get_total_blks() / 100;
        const auto size_by_mem = HS_DYNAMIC_CONFIG(blkallocator.max_free_blk_cache_memory_percent) *
            HS_STATIC_CONFIG(input.app_mem_size) / 100;
        m_max_cache_blks = std::min(size_by_count, size_by_mem);

        // Initialize the slab config based on number of temperatures
        slab_idx_t slab_idx = 0;
        int64_t cum_slab_nblks = 0;

        HS_RELEASE_ASSERT_GT(HS_DYNAMIC_CONFIG(blkallocator.free_blk_slab_distribution).size(), 0,
                             "Config does not have free blk slab distribution");
        const auto reuse_pct = HS_DYNAMIC_CONFIG(blkallocator.free_blk_reuse_pct);
        const auto num_temp = HS_DYNAMIC_CONFIG(blkallocator.num_blk_temperatures);
        const auto num_temp_slab_pct = (100 - reuse_pct) / num_temp;

        m_slab_config.m_name = name;
        for (const auto& pct : HS_DYNAMIC_CONFIG(blkallocator.free_blk_slab_distribution)) {
            SlabCacheConfig::_slab_config s_cfg;
            s_cfg.slab_size = (1 << slab_idx);
            s_cfg.max_entries = (m_max_cache_blks / s_cfg.slab_size) * pct / 100;
            s_cfg.m_name = name;
            s_cfg.refill_threshold_pct = HS_DYNAMIC_CONFIG(blkallocator.free_blk_cache_refill_threshold_pct);

            // Distribute the slab among different temperature based on config provided
            s_cfg.m_level_distribution_pct.reserve(num_temp + 1);
            s_cfg.m_level_distribution_pct.push_back(reuse_pct);
            for (blk_temp_t i{0}; i < num_temp; ++i) {
                s_cfg.m_level_distribution_pct.push_back(num_temp_slab_pct);
            }
            ++slab_idx;
            cum_slab_nblks += s_cfg.max_entries * s_cfg.slab_size;
            m_slab_config.m_per_slab_cfg.push_back(s_cfg);
        }

        // If after percentage calculation, if there are any remaining (possible if config doesn't add upto 100),
        // then put that in first slab.
        m_slab_config.m_per_slab_cfg[0].max_entries += ((int64_t)m_max_cache_blks - cum_slab_nblks);
    }

    VarsizeBlkAllocConfig(const VarsizeBlkAllocConfig& other) :
            BlkAllocConfig{other},
            m_phys_page_size{other.m_phys_page_size},
            m_nsegments{other.m_nsegments},
            m_blks_per_temp_group{other.m_blks_per_temp_group},
            m_max_cache_blks{other.m_max_cache_blks},
            m_slab_config{other.m_slab_config} {}

    VarsizeBlkAllocConfig(VarsizeBlkAllocConfig&&) noexcept = delete;
    VarsizeBlkAllocConfig& operator=(const VarsizeBlkAllocConfig&) = delete;
    VarsizeBlkAllocConfig& operator=(VarsizeBlkAllocConfig&&) noexcept = delete;
    virtual ~VarsizeBlkAllocConfig() override = default;

    //////////// Physical page size related getters/setters /////////////
    void set_phys_page_size(const uint32_t page_size) { m_phys_page_size = page_size; }
    [[nodiscard]] uint32_t get_phys_page_size() const { return m_phys_page_size; }

    //////////// Segments related getters/setters /////////////
    void set_total_segments(const seg_num_t nsegments) { m_nsegments = nsegments; }
    [[nodiscard]] seg_num_t get_total_segments() const { return m_nsegments; }
    [[nodiscard]] blk_cap_t get_blks_per_segment() const { return (get_total_blks() / get_total_segments()); }
    [[nodiscard]] blk_cap_t get_portions_per_segment() const { return (get_total_portions() / get_total_segments()); }

    //////////// Blks related getters/setters /////////////
    [[nodiscard]] blk_cap_t get_max_cache_blks() const { return m_max_cache_blks; }
    [[nodiscard]] blk_cap_t get_blks_per_temp_group() const { return m_blks_per_temp_group; }
    [[nodiscard]] blk_cap_t get_blks_per_phys_page() const {
        blk_cap_t nblks = get_phys_page_size() / get_blk_size();
        assert(get_blks_per_portion() % nblks == 0);
        return nblks;
    }

    //////////// Slab related getters/setters /////////////
    [[nodiscard]] blk_count_t get_slab_cnt() const { return m_slab_config.m_per_slab_cfg.size(); }
    [[nodiscard]] blk_cap_t get_slab_capacity(const slab_idx_t slab_idx) const {
        return m_slab_config.m_per_slab_cfg[slab_idx].max_entries;
    }
    [[nodiscard]] blk_cap_t highest_slab_blks_count() const { return (1 << (m_slab_config.m_per_slab_cfg.size() - 1)); }

    [[nodiscard]] std::string to_string() const override {
        return fmt::format("{} Pagesize={} Totalsegments={} BlksPerPortion={} MaxCacheBlks={} Slabconfig=[{}]",
                           BlkAllocConfig::to_string(), get_phys_page_size(), get_total_segments(),
                           get_blks_per_portion(), get_max_cache_blks(), m_slab_config.to_string());
    }
};

class BlkAllocSegment {
public:
#if 0
    class CompareSegAvail {
    public:
        bool operator()(const BlkAllocSegment* const seg1, const BlkAllocSegment* const seg2) const {
            return (seg1->get_free_blks() < seg2->get_free_blks());
        }
    };

    // typedef boost::heap::binomial_heap< BlkAllocSegment *, boost::heap::compare< BlkAllocSegment::CompareSegAvail>>
    // SegQueue;
    typedef boost::heap::binomial_heap< BlkAllocSegment*, boost::heap::compare< CompareSegAvail > > SegQueue;
#endif

private:
    blk_cap_t m_total_blks;
    blk_num_t m_total_portions;
    seg_num_t m_seg_num; // Segment sequence number
    blk_num_t m_alloc_clock_hand;

public:
    BlkAllocSegment(blk_cap_t nblks, seg_num_t seg_num, blk_num_t nportions, const std::string& seg_name) :
            m_total_blks{nblks}, m_total_portions{nportions}, m_seg_num{seg_num}, m_alloc_clock_hand{0} {}

    BlkAllocSegment(const BlkAllocSegment&) = delete;
    BlkAllocSegment(BlkAllocSegment&&) noexcept = delete;
    BlkAllocSegment& operator=(const BlkAllocSegment&) = delete;
    BlkAllocSegment& operator=(BlkAllocSegment&&) noexcept = delete;
    virtual ~BlkAllocSegment() {}

    [[nodiscard]] blk_num_t get_clock_hand() const { return m_alloc_clock_hand % m_total_portions; }
    void set_clock_hand(const blk_num_t hand) { m_alloc_clock_hand = hand; }
    void inc_clock_hand() { ++m_alloc_clock_hand; }

    // bool operator<(BlkAllocSegment& other_seg) const { return (this->get_free_blks() < other_seg.get_free_blks()); }

    void set_total_blks(const blk_cap_t a) { m_total_blks = a; }
    [[nodiscard]] blk_cap_t get_total_blks() const { return m_total_blks; }

    void set_seg_num(const seg_num_t n) { m_seg_num = n; }
    [[nodiscard]] seg_num_t get_seg_num() const { return m_seg_num; }
};

class BlkAllocMetrics : public sisl::MetricsGroup {
public:
    explicit BlkAllocMetrics(const char* inst_name) : sisl::MetricsGroup("BlkAlloc", inst_name) {
        REGISTER_COUNTER(num_alloc, "Number of blks alloc attempts");
        REGISTER_COUNTER(num_alloc_failure, "Number of blk alloc failures");
        REGISTER_COUNTER(num_retries, "Number of times it retried because of empty cache");
        REGISTER_COUNTER(num_blks_alloc_direct, "Number of blks alloc attempt directly because of empty cache");

        REGISTER_HISTOGRAM(frag_pct_distribution, "Distribution of fragmentation percentage",
                           HistogramBucketsType(LinearUpto64Buckets));

        register_me_to_farm();
    }

    BlkAllocMetrics(const BlkAllocMetrics&) = delete;
    BlkAllocMetrics(BlkAllocMetrics&&) noexcept = delete;
    BlkAllocMetrics& operator=(const BlkAllocMetrics&) = delete;
    BlkAllocMetrics& operator=(BlkAllocMetrics&&) noexcept = delete;
    ~BlkAllocMetrics() { deregister_me_from_farm(); }
};

/* VarsizeBlkAllocator provides a flexibility in allocation. It provides following features:
 *
 * 1. Could allocate variable number of blks in single allocation
 * 2. Provides the option of allocating blocks based on requested temperature.
 * 3. Caching of available blocks instead of scanning during allocation.
 *
 */
class VarsizeBlkAllocator : public BlkAllocator {
public:
    VarsizeBlkAllocator(const VarsizeBlkAllocConfig& cfg, const bool init, const chunk_num_t chunk_id);
    VarsizeBlkAllocator(const VarsizeBlkAllocator&) = delete;
    VarsizeBlkAllocator(VarsizeBlkAllocator&&) noexcept = delete;
    VarsizeBlkAllocator& operator=(const VarsizeBlkAllocator&) = delete;
    VarsizeBlkAllocator& operator=(VarsizeBlkAllocator&&) noexcept = delete;
    virtual ~VarsizeBlkAllocator() override;

    BlkAllocStatus alloc(BlkId& bid) override;
    BlkAllocStatus alloc(const blk_count_t nblks, const blk_alloc_hints& hints,
                         std::vector< BlkId >& out_blkid) override;
    void free(const BlkId& b) override;
    void inited() override;
    BlkAllocStatus alloc_blks_direct(const blk_count_t nblks, const blk_alloc_hints& hints,
                                     std::vector< BlkId >& out_blkids);

    [[nodiscard]] blk_cap_t get_available_blks() const override;
    [[nodiscard]] blk_cap_t get_used_blks() const override;
    [[nodiscard]] bool is_blk_alloced(const BlkId& in_bid, const bool use_lock = false) const override;
    [[nodiscard]] std::string to_string() const override;
    [[nodiscard]] nlohmann::json get_metrics_in_json();

private:
    std::unique_ptr< sisl::Bitset > m_bm;       // Bitset representing entire blks in this allocator
    std::unique_ptr< FreeBlkCache > m_fb_cache; // Free Blks cache

    chunk_num_t m_chunk_id;       // Chunk ID this allocator is associated to (this will be filled in BlkId generated)
    VarsizeBlkAllocConfig m_cfg;  // Config for Varsize
    std::thread m_thread_id;      // Sweeper thread
    std::mutex m_mutex;           // Mutex to protect regionstate & cb
    std::condition_variable m_cv; // CV to signal thread
    BlkAllocatorState m_state;    // Current state of the blkallocator

    std::vector< std::unique_ptr< BlkAllocSegment > > m_segments; // Lookup map for segment id - segment

    BlkAllocSegment* m_sweep_segment{nullptr};                    // Segment to sweep - if woken up
    std::shared_ptr< blk_cache_fill_session > m_cur_fill_session; // Cache fill requirements while sweeping

    std::uniform_int_distribution< blk_num_t > m_rand_portion_num_generator;
    BlkAllocMetrics m_metrics;

private:
    void allocator_state_machine();

#ifndef NDEBUG
    [[nodiscard]] bool is_set_on_bitmap(const BlkId& b) const;
    void alloc_sanity_check(const blk_count_t nblks, const blk_alloc_hints& hints,
                            const std::vector< BlkId >& out_blkids) const;
#endif

    const VarsizeBlkAllocConfig& get_config() const override { return (VarsizeBlkAllocConfig&)m_cfg; }
    [[nodiscard]] blk_num_t get_portions_per_segment() const;

    // Sweep and cache related functions
    void _prepare_sweep(BlkAllocSegment* seg, const bool fill_entire_cache);
    void request_more_blks(BlkAllocSegment* seg, const bool fill_entire_cache);
    void request_more_blks_wait(BlkAllocSegment* seg, const blk_cap_t wait_for_blks_count);
    void fill_cache(BlkAllocSegment* seg, blk_cache_fill_session& fill_session);
    void fill_cache_in_portion(const blk_num_t portion_num, blk_cache_fill_session& fill_session);

    void free_on_bitmap(const BlkId& b);

    //////////////////////////////////////////// Convenience routines ///////////////////////////////////////////
    ///////////////////// Physical page related routines ////////////////////////
    [[nodiscard]] blk_num_t blknum_to_phys_pageid(const blk_num_t blknum) const {
        return blknum / get_config().get_blks_per_phys_page();
    }
    [[nodiscard]] blk_num_t offset_within_phys_page(const blk_num_t blknum) const {
        return blknum % get_config().get_blks_per_phys_page();
    }

    ///////////////////// Segment related routines ////////////////////////
    [[nodiscard]] seg_num_t blknum_to_segment_num(const blk_num_t blknum) const {
        const auto seg_num = blknum / get_config().get_blks_per_segment();
        assert(seg_num < m_cfg.get_total_segments());
        return seg_num;
    }

    BlkAllocSegment* blknum_to_segment(const blk_num_t blknum) const {
        return m_segments[blknum_to_segment_num(blknum)].get();
    }

    ///////////////////// Cache Entry related routines ////////////////////////
    void blk_cache_entries_to_blkids(const std::vector< blk_cache_entry >& entries, std::vector< BlkId >& out_blkids);
    [[nodiscard]] BlkId blk_cache_entry_to_blkid(const blk_cache_entry& e);
    [[nodiscard]] blk_cache_entry blkid_to_blk_cache_entry(const BlkId& bid);
};
} // namespace homestore
