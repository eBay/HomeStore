/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <algorithm>
#include <atomic>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sisl/flip/flip.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>

#include <homestore/blk.h>
#include "blk_allocator.h"
#include "blk_cache.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"

namespace homestore {
typedef blk_num_t seg_num_t;

struct VarsizeBlkAllocConfig : public BlkAllocConfig {
public:
    const uint32_t m_phys_page_size;
    const seg_num_t m_nsegments;
    const blk_cap_t m_blks_per_temp_group;
    blk_cap_t m_max_cache_blks;
    SlabCacheConfig m_slab_config;
    const bool m_use_slabs{true}; // use sweeping thread pool with slabs in variable size block allocator

public:
    VarsizeBlkAllocConfig() : VarsizeBlkAllocConfig{0, 0, 0, 0, ""} {}
    VarsizeBlkAllocConfig(const std::string& name) : VarsizeBlkAllocConfig{0, 0, 0, 0, name} {}

    VarsizeBlkAllocConfig(uint32_t blk_size, uint32_t ppage_sz, uint32_t align_sz, uint64_t size,
                          const std::string& name, bool realtime_bm_on = true, bool use_slabs = true) :
            BlkAllocConfig{blk_size, align_sz, size, name, realtime_bm_on},
            m_phys_page_size{ppage_sz},
            m_nsegments{HS_DYNAMIC_CONFIG(blkallocator.max_segments)},
            m_blks_per_temp_group{m_capacity / HS_DYNAMIC_CONFIG(blkallocator.num_blk_temperatures)},
            m_use_slabs{use_slabs} {
        // Initialize the max cache blks as minimum dictated by the number of blks or memory limits whichever is lower
        const blk_cap_t size_by_count{static_cast< blk_cap_t >(
            std::trunc(HS_DYNAMIC_CONFIG(blkallocator.free_blk_cache_count_by_vdev_percent) * m_capacity / 100.0))};
        const blk_cap_t size_by_mem{
            static_cast< blk_cap_t >(std::trunc(HS_DYNAMIC_CONFIG(blkallocator.max_free_blk_cache_memory_percent) *
                                                HS_STATIC_CONFIG(input.app_mem_size) / 100.0))};
        m_max_cache_blks = std::min(size_by_count, size_by_mem);

        // Initialize the slab config based on number of temperatures
        slab_idx_t slab_idx{0};
        uint64_t cum_slab_nblks{0};
        double cum_pct{0.0};

        HS_REL_ASSERT_GT(HS_DYNAMIC_CONFIG(blkallocator.free_blk_slab_distribution).size(), 0,
                         "Config does not have free blk slab distribution");
        const auto reuse_pct{HS_DYNAMIC_CONFIG(blkallocator.free_blk_reuse_pct)};
        const auto num_temp{HS_DYNAMIC_CONFIG(blkallocator.num_blk_temperatures)};
        const auto num_temp_slab_pct{(100.0 - reuse_pct) / static_cast< double >(num_temp)};

        m_slab_config.m_name = name;
        for (const auto& pct : HS_DYNAMIC_CONFIG(blkallocator.free_blk_slab_distribution)) {
            cum_pct += pct;
            SlabCacheConfig::_slab_config s_cfg;
            s_cfg.slab_size = static_cast< blk_count_t >(1) << slab_idx;
            s_cfg.max_entries = static_cast< blk_cap_t >((m_max_cache_blks / s_cfg.slab_size) * (pct / 100.0));
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

        // If after percentage calculation, if there are any remaining (possible if config doesn't add up to 100),
        // then put that in first slab.
        assert(cum_pct < 100.0 * (1.0 + std::numeric_limits< double >::epsilon()));
        if (cum_slab_nblks < m_max_cache_blks) {
            m_slab_config.m_per_slab_cfg[0].max_entries += m_max_cache_blks - cum_slab_nblks;
        }
    }

    VarsizeBlkAllocConfig(const VarsizeBlkAllocConfig& other) = default;
    VarsizeBlkAllocConfig(VarsizeBlkAllocConfig&&) noexcept = delete;
    VarsizeBlkAllocConfig& operator=(const VarsizeBlkAllocConfig&) = delete;
    VarsizeBlkAllocConfig& operator=(VarsizeBlkAllocConfig&&) noexcept = delete;
    virtual ~VarsizeBlkAllocConfig() override = default;

    ///////////// SlabConfig getter /////////////
    SlabCacheConfig get_slab_config() const { return m_slab_config; }

    //////////// Segments related getters/setters /////////////
    seg_num_t get_total_segments() const { return m_nsegments; }
    blk_cap_t get_blks_per_segment() const { return (m_capacity / m_nsegments); }

    //////////// Blks related getters/setters /////////////
    blk_cap_t get_max_cache_blks() const { return m_max_cache_blks; }
    blk_cap_t get_blks_per_temp_group() const { return m_blks_per_temp_group; }
    blk_cap_t get_blks_per_phys_page() const { return m_phys_page_size / m_blk_size; }

    //////////// Slab related getters/setters /////////////
    slab_idx_t get_slab_cnt() const { return m_slab_config.m_per_slab_cfg.size(); }
    blk_count_t get_slab_block_count(const slab_idx_t index) { return m_slab_config.m_per_slab_cfg[index].slab_size; }
    blk_cap_t get_slab_capacity(const slab_idx_t slab_idx) const {
        return m_slab_config.m_per_slab_cfg[slab_idx].max_entries;
    }
    blk_cap_t highest_slab_blks_count() const {
        const slab_idx_t index{get_slab_cnt()};
        return (index > 0) ? m_slab_config.m_per_slab_cfg[index - 1].slab_size : 0;
    }

    std::string to_string() const override {
        return fmt::format("IsSlabAlloc={}, {} Pagesize={} Totalsegments={} MaxCacheBlks={} Slabconfig=[{}]",
                           m_use_slabs, BlkAllocConfig::to_string(), in_bytes(m_phys_page_size), m_nsegments,
                           in_bytes(m_max_cache_blks), m_slab_config.to_string());
    }
};

class BlkAllocSegment {
private:
    blk_num_t m_total_portions;
    seg_num_t m_seg_num; // Segment sequence number
    blk_num_t m_alloc_clock_hand;

public:
    BlkAllocSegment(const seg_num_t seg_num, const blk_num_t nportions, const std::string& seg_name) :
            m_total_portions{nportions}, m_seg_num{seg_num}, m_alloc_clock_hand{0} {}

    BlkAllocSegment(const BlkAllocSegment&) = delete;
    BlkAllocSegment(BlkAllocSegment&&) noexcept = delete;
    BlkAllocSegment& operator=(const BlkAllocSegment&) = delete;
    BlkAllocSegment& operator=(BlkAllocSegment&&) noexcept = delete;
    virtual ~BlkAllocSegment() {}

    blk_num_t get_clock_hand() const { return m_alloc_clock_hand % m_total_portions; }
    void set_clock_hand(const blk_num_t hand) { m_alloc_clock_hand = hand; }
    void inc_clock_hand() { ++m_alloc_clock_hand; }

    // bool operator<(BlkAllocSegment& other_seg) const { return (this->get_free_blks() < other_seg.get_free_blks()); }

    void set_seg_num(const seg_num_t n) { m_seg_num = n; }
    seg_num_t get_seg_num() const { return m_seg_num; }
};

class BlkAllocMetrics : public sisl::MetricsGroup {
public:
    explicit BlkAllocMetrics(const char* inst_name) : sisl::MetricsGroup("BlkAlloc", inst_name) {
        REGISTER_COUNTER(num_alloc, "Number of blks alloc attempts");
        REGISTER_COUNTER(num_alloc_failure, "Number of blk alloc failures");
        REGISTER_COUNTER(num_alloc_partial, "Number of blk alloc partial allocations");
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
    VarsizeBlkAllocator(const VarsizeBlkAllocConfig& cfg, bool init, chunk_num_t chunk_id);
    VarsizeBlkAllocator(const VarsizeBlkAllocator&) = delete;
    VarsizeBlkAllocator(VarsizeBlkAllocator&&) noexcept = delete;
    VarsizeBlkAllocator& operator=(const VarsizeBlkAllocator&) = delete;
    VarsizeBlkAllocator& operator=(VarsizeBlkAllocator&&) noexcept = delete;
    virtual ~VarsizeBlkAllocator() override;

    BlkAllocStatus alloc(BlkId& bid) override;
    BlkAllocStatus alloc(blk_count_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) override;
    void free(const std::vector< BlkId >& blk_ids) override;
    void free(const BlkId& b) override;
    void inited() override;
    BlkAllocStatus alloc_blks_direct(blk_count_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids,
                                     blk_count_t& num_allocated);

    blk_cap_t available_blks() const override;
    blk_cap_t get_used_blks() const override;
    bool is_blk_alloced(const BlkId& in_bid, bool use_lock = false) const override;
    std::string to_string() const override;
    nlohmann::json get_metrics_in_json();

private:
    // global block allocator sweep threads
    static std::mutex s_sweeper_create_delete_mutex;                      // sweeper threads create/destroy mutex
    static std::atomic< size_t > s_sweeper_thread_references;             // num active sweeper threads
    static std::vector< std::thread > s_sweeper_threads;                  // Sweeper threads
    static std::atomic< bool > s_sweeper_threads_stop;                    // atomic flag to stop sweeper threads
    static std::mutex s_sweeper_mutex;                                    // Sweeper threads mutex
    static std::condition_variable s_sweeper_cv;                          // sweeper threads cv
    static std::queue< VarsizeBlkAllocator* > s_sweeper_queue;            // Sweeper threads queue
    static std::unordered_set< VarsizeBlkAllocator* > s_block_allocators; // block allocators to be swept

    static constexpr blk_num_t INVALID_PORTION_NUM{UINT_MAX}; // max of type blk_num_t

    // per class sweeping logic
    std::mutex m_mutex;           // Mutex to protect regionstate & cb
    std::condition_variable m_cv; // CV to signal thread
    BlkAllocatorState m_state;    // Current state of the blkallocator

    std::unique_ptr< sisl::Bitset > m_cache_bm; // Bitset representing entire blks in this allocator
    std::unique_ptr< FreeBlkCache > m_fb_cache; // Free Blks cache

    VarsizeBlkAllocConfig m_cfg; // Config for Varsize

    std::vector< std::unique_ptr< BlkAllocSegment > > m_segments; // Lookup map for segment id - segment

    BlkAllocSegment* m_sweep_segment{nullptr};                    // Segment to sweep - if woken up
    std::shared_ptr< blk_cache_fill_session > m_cur_fill_session; // Cache fill requirements while sweeping

    std::uniform_int_distribution< blk_num_t > m_rand_portion_num_generator;
    BlkAllocMetrics m_metrics;

    // TODO: this fields needs to be passed in from hints and persisted in volume's sb;
    blk_num_t m_start_portion_num{INVALID_PORTION_NUM};

    blk_cap_t m_blks_per_seg{1};
    blk_num_t m_portions_per_seg{1};

private:
    static void sweeper_thread(size_t thread_num);
    bool allocator_state_machine();

#ifdef _PRERELEASE
    bool is_set_on_bitmap(const BlkId& b) const;
    void alloc_sanity_check(blk_count_t nblks, const blk_alloc_hints& hints,
                            const std::vector< BlkId >& out_blkids) const;
#endif

    // Sweep and cache related functions
    bool prepare_sweep(BlkAllocSegment* seg, bool fill_entire_cache);
    void request_more_blks(BlkAllocSegment* seg, bool fill_entire_cache);
    void request_more_blks_wait(BlkAllocSegment* seg, blk_count_t wait_for_blks_count);

    void fill_cache(BlkAllocSegment* seg, blk_cache_fill_session& fill_session);
    void fill_cache_in_portion(blk_num_t portion_num, blk_cache_fill_session& fill_session);

    void free_on_bitmap(const BlkId& b);

    //////////////////////////////////////////// Convenience routines ///////////////////////////////////////////
    ///////////////////// Physical page related routines ////////////////////////
    blk_num_t blknum_to_phys_pageid(blk_num_t blknum) const { return blknum / m_cfg.get_blks_per_phys_page(); }
    blk_num_t offset_within_phys_page(blk_num_t blknum) const { return blknum % m_cfg.get_blks_per_phys_page(); }

    ///////////////////// Segment related routines ////////////////////////
    seg_num_t blknum_to_segment_num(blk_num_t blknum) const {
        const auto seg_num{blknum / m_cfg.get_blks_per_segment()};
        assert(seg_num < m_cfg.m_nsegments);
        return seg_num;
    }

    BlkAllocSegment* blknum_to_segment(blk_num_t blknum) const {
        return m_segments[blknum_to_segment_num(blknum)].get();
    }

    ///////////////////// Cache Entry related routines ////////////////////////
    void blk_cache_entries_to_blkids(const std::vector< blk_cache_entry >& entries, std::vector< BlkId >& out_blkids);
    BlkId blk_cache_entry_to_blkid(const blk_cache_entry& e);
    blk_cache_entry blkid_to_blk_cache_entry(const BlkId& bid, blk_temp_t preferred_level = 1);
};
} // namespace homestore
