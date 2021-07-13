//
// Created by Kadayam, Hari on Sep 20 2020
//
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <fds/buffer.hpp>
#include <folly/MPMCQueue.h>

#include "blk_cache.h"

namespace homestore {

class SlabCacheQueue;
class BlkAllocMetrics;
class SlabMetrics : public sisl::MetricsGroup {
public:
    SlabMetrics(const blk_count_t slab_size, SlabCacheQueue* const slab_queue, BlkAllocMetrics* const parent);
    SlabMetrics(const SlabMetrics&) = delete;
    SlabMetrics(SlabMetrics&&) noexcept = delete;
    SlabMetrics& operator=(const SlabMetrics&) = delete;
    SlabMetrics& operator=(SlabMetrics&&) noexcept = delete;
    ~SlabMetrics() = default;

    void on_gather();

private:
    SlabCacheQueue* m_slab_queue;
};

class SlabCacheQueue {
public:
    SlabCacheQueue(const blk_count_t slab_size, const std::vector< blk_cap_t >& level_limits, const float refill_pct,
                   BlkAllocMetrics* metrics);
    SlabCacheQueue(const SlabCacheQueue&) = delete;
    SlabCacheQueue(SlabCacheQueue&&) noexcept = delete;
    SlabCacheQueue& operator=(const SlabCacheQueue&) = delete;
    SlabCacheQueue& operator=(SlabCacheQueue&&) noexcept = delete;
    ~SlabCacheQueue() = default;

    [[nodiscard]] std::optional< blk_temp_t > push(const blk_cache_entry& entry, const bool only_this_level);
    [[nodiscard]] std::optional< blk_temp_t > pop(const blk_temp_t level, const bool only_this_level,
                                                  blk_cache_entry& out_entry);
    [[nodiscard]] blk_cap_t entry_count() const;
    [[nodiscard]] blk_cap_t entry_capacity() const;
    [[nodiscard]] blk_cap_t num_level_entries(const blk_temp_t level) const;

    [[nodiscard]] blk_num_t entries_needed(const blk_num_t nblks) const { return (nblks - 1) / m_slab_size + 1; }
    [[nodiscard]] blk_count_t slab_size() const { return m_slab_size; }
    void refilled();

    [[nodiscard]] blk_cap_t open_session(const uint64_t session_id, const bool fill_entire_cache);
    void close_session(const uint64_t session_id);

    [[nodiscard]] SlabMetrics& metrics() { return m_metrics; }

private:
    blk_count_t m_slab_size; // Slab size in-terms of number of pages
    std::vector< std::unique_ptr< folly::MPMCQueue< blk_cache_entry > > > m_level_queues;
    std::atomic< uint64_t > m_refill_session{0}; // Is a refill pending for this slab
    blk_cap_t m_total_capacity{0};
    blk_cap_t m_refill_threshold_limits; // For every level whats their threshold limit size
    SlabMetrics m_metrics;
};

class FreeBlkCacheQueue : public FreeBlkCache {
public:
    FreeBlkCacheQueue(const SlabCacheConfig& cfg, BlkAllocMetrics* metrics);
    virtual ~FreeBlkCacheQueue() override = default;
    FreeBlkCacheQueue(FreeBlkCacheQueue&&) noexcept = delete;
    FreeBlkCacheQueue& operator=(const FreeBlkCacheQueue&) = delete;
    FreeBlkCacheQueue& operator=(FreeBlkCacheQueue&&) noexcept = delete;

    [[nodiscard]] BlkAllocStatus try_alloc_blks(const blk_cache_alloc_req& req, blk_cache_alloc_resp& resp) override;
    [[maybe_unused]] blk_count_t try_free_blks(const blk_cache_entry& entry,
                                               std::vector< blk_cache_entry >& excess_blks) override;
    [[maybe_unused]] blk_count_t try_free_blks(const std::vector< blk_cache_entry >& blks,
                                               std::vector< blk_cache_entry >& excess_blks) override;
    [[nodiscard]] blk_cap_t try_fill_cache(const blk_cache_fill_req& fill_req,
                                           blk_cache_fill_session& fill_session) override;

    [[nodiscard]] blk_cap_t total_free_blks() const override;

    [[nodiscard]] std::shared_ptr< blk_cache_fill_session > create_cache_fill_session(const bool fill_entire_cache);
    void close_cache_fill_session(blk_cache_fill_session& fill_session);

private:
    [[nodiscard]] BlkAllocStatus break_up(const slab_idx_t slab_idx, const blk_cache_alloc_req& req,
                                          blk_cache_alloc_resp& resp);
    [[nodiscard]] BlkAllocStatus merge_down(const slab_idx_t slab_idx, const blk_cache_alloc_req& req,
                                            blk_cache_alloc_resp& resp);
    [[nodiscard]] BlkAllocStatus try_alloc_in_slab(const slab_idx_t slab_num, const blk_cache_alloc_req& req,
                                                   blk_cache_alloc_resp& resp);

    [[nodiscard]] std::optional< blk_temp_t > push_slab(const slab_idx_t slab_idx, const blk_cache_entry& entry,
                                                        const bool only_this_level);
    [[nodiscard]] std::optional< blk_temp_t > pop_slab(const slab_idx_t slab_idx, const blk_temp_t level,
                                                       const bool only_this_level, blk_cache_entry& out_entry);

    [[nodiscard]] inline SlabMetrics& slab_metrics(const slab_idx_t slab_idx) const {
        return m_slab_queues[slab_idx]->metrics();
    }

private:
    std::vector< std::unique_ptr< SlabCacheQueue > > m_slab_queues;
    SlabCacheConfig m_cfg;
    BlkAllocMetrics* m_metrics;
};

} // namespace homestore
