//
// Created by Kadayam, Hari on Sep 20 2020
//

#include "engine/common/homestore_assert.hpp"
#include "varsize_blk_allocator.h"

#include "blk_cache_queue.h"

namespace homestore {
FreeBlkCacheQueue::FreeBlkCacheQueue(const SlabCacheConfig& cfg, BlkAllocMetrics* const metrics) :
        m_cfg{cfg}, m_metrics{metrics} {
#ifndef NDEBUG
    blk_count_t slab_size{1};
#endif

    m_slab_queues.reserve(cfg.m_per_slab_cfg.size());
    for (const auto& slab_cfg : cfg.m_per_slab_cfg) {
        std::vector< blk_cap_t > level_limits;
        level_limits.reserve(slab_cfg.m_level_distribution_pct.size());
#ifndef NDEBUG
        HS_DBG_ASSERT_EQ(slab_cfg.slab_size, slab_size, "Slab config size is not contiguous power of 2");
        slab_size *= 2;
#endif

        blk_cap_t sum{0};
        for (const auto& p : slab_cfg.m_level_distribution_pct) {
            const blk_cap_t limit{static_cast< blk_cap_t >((static_cast< double >(slab_cfg.max_entries) * p) / 100.0)};
            sum += limit;
            level_limits.push_back(limit);
        }
        HS_DBG_ASSERT_GE(slab_cfg.max_entries, sum, "Slab config distribution does not add to 100%");
        if (sum < slab_cfg.max_entries) {
            level_limits[0] += slab_cfg.max_entries - sum; // Put the remaining to the first priority
        }

        auto ptr{std::make_unique< SlabCacheQueue >(slab_cfg.slab_size, level_limits, slab_cfg.refill_threshold_pct,
                                                    metrics)};
        m_slab_queues.push_back(std::move(ptr));
    }
}

BlkAllocStatus FreeBlkCacheQueue::try_alloc_blks(const blk_cache_alloc_req& req, blk_cache_alloc_resp& resp) {
    const auto slab_idx{std::min(FreeBlkCache::find_slab(req.nblks), req.max_slab_idx)};

    COUNTER_INCREMENT(slab_metrics(slab_idx), num_slab_alloc, 1);
    BlkAllocStatus status{try_alloc_in_slab(slab_idx, req, resp)};
    if (status == BlkAllocStatus::SUCCESS) {
        BLKALLOC_LOG(TRACE, "Alloced in slab {}", resp.out_blks.front().to_string());
        return status;
    } else {
        // free any partial result if contiguous
        if ((status == BlkAllocStatus::PARTIAL) && req.is_contiguous) {
            resp.nblks_zombied = try_free_blks(resp.out_blks, resp.excess_blks);
            resp.out_blks.clear();
        }
    }

    // We were not able to secure all blocks in this slab, try to break higher slabs
    status = break_up(slab_idx, req, resp);
    if (status == BlkAllocStatus::SUCCESS) {
        BLKALLOC_LOG(TRACE, "Alloced break up {}", resp.out_blks.front().to_string());
        COUNTER_INCREMENT(slab_metrics(slab_idx), num_slab_alloc_with_split, 1);
        return status;
    }

    // We were not able to still secure anything on higher slab, try to merge lower slab entries.
    if (!req.is_contiguous) {
        status = merge_down(slab_idx, req, resp);
        if (status == BlkAllocStatus::SUCCESS) {
            BLKALLOC_LOG(TRACE, "Alloced merge down {}", resp.out_blks.front().to_string());
            COUNTER_INCREMENT(slab_metrics(slab_idx), num_slab_alloc_with_merge, 1);
            return status;
        }
    }

    COUNTER_INCREMENT(slab_metrics(slab_idx), num_slab_alloc_failure, 1);

    return status;
}

blk_count_t FreeBlkCacheQueue::try_free_blks(const blk_cache_entry& entry,
                                             std::vector< blk_cache_entry >& excess_blks) {
    auto ret{BlkAllocStatus::SUCCESS};
    blk_cache_entry e{entry};
    blk_count_t num_zombied{0};

    while (e.get_nblks() > 0) {
        const auto [slab_idx, excess]{FreeBlkCache::find_round_down_slab(e.get_nblks())};
#ifndef NDEBUG
        if (slab_idx >= m_slab_queues.size()) {
            BLKALLOC_LOG(ERROR, "Entry=[{}] slab_idx={} exceeds max slab queues {}", entry.to_string(), slab_idx,
                         m_slab_queues.size());
        }
#endif

        e.set_nblks(m_slab_queues[slab_idx]->m_slab_size);
        if (!push_slab(slab_idx, e, false /* only_this_level */)) {
            excess_blks.push_back(e);
            num_zombied += e.get_nblks();
        }

        if (excess == 0) { break; }
        e.set_blk_num(e.get_blk_num() + m_slab_queues[slab_idx]->m_slab_size);
        e.set_nblks(excess);
    }

    return num_zombied;
}

blk_count_t FreeBlkCacheQueue::try_free_blks(const std::vector< blk_cache_entry >& blks,
                                             std::vector< blk_cache_entry >& excess_blks) {
    auto ret{BlkAllocStatus::SUCCESS};
    blk_count_t num_zombied{0};

    for (const auto& e : blks) {
        num_zombied += try_free_blks(e, excess_blks);
    }
    return num_zombied;
}

blk_cap_t FreeBlkCacheQueue::try_fill_cache(const blk_cache_fill_req& fill_req, blk_cache_fill_session& fill_session) {
    blk_cap_t nblks_added{0};
    slab_idx_t slabs_pending_refill{static_cast< slab_idx_t >(m_slab_queues.size())};

    auto slab_idx{FreeBlkCache::find_slab(fill_req.nblks)};
    if (slab_idx >= m_slab_queues.size()) { slab_idx = m_slab_queues.size() - 1; }

    // Try to fill from the maximum blocks.
    auto blk_num{fill_req.start_blk_num};
    auto nblks_remain{fill_req.nblks};

    do {
        const auto slab_size{m_slab_queues[slab_idx]->slab_size()};
        while ((nblks_remain >= slab_size) && fill_session.slab_requirements[slab_idx].need_refill()) {
            // Try to push the cache entry to slab and keep accounting as to how much
            const blk_cache_entry e{blk_num, slab_size, fill_req.preferred_level};
            if (!push_slab(slab_idx, e, fill_req.only_this_level)) {
                fill_session.slab_requirements[slab_idx].mark_refill_done();
                break;
            }

            COUNTER_INCREMENT(slab_metrics(slab_idx), num_slab_refills, 1);
            ++(fill_session.slab_requirements[slab_idx].slab_refilled_count);
            fill_session.overall_refilled_num_blks += slab_size;
            nblks_remain -= slab_size;
            blk_num += slab_size;
        }

        if (fill_session.slab_requirements[slab_idx].is_refill_done()) { --slabs_pending_refill; }
    } while ((slab_idx-- > 0) && nblks_remain);

    fill_session.overall_refill_done = (slabs_pending_refill == 0);

    BLKALLOC_LOG(DEBUG, "Refill session now: [{}], fill_req range: [{}-{}], nblks_remain={}", fill_session.to_string(),
                 fill_req.start_blk_num, fill_req.start_blk_num + fill_req.nblks, nblks_remain);
    return (fill_req.nblks - nblks_remain);
}

blk_cap_t FreeBlkCacheQueue::total_free_blks() const {
    blk_cap_t count{0};
    for (const auto& sq : m_slab_queues) {
        count += sq->entry_count() * sq->slab_size();
    }
    return count;
}

BlkAllocStatus FreeBlkCacheQueue::try_alloc_in_slab(const slab_idx_t slab_idx, const blk_cache_alloc_req& req,
                                                    blk_cache_alloc_resp& resp) {
    if (resp.nblks_alloced >= req.nblks) { return BlkAllocStatus::SUCCESS; }

    const blk_count_t blks_needed{static_cast< blk_count_t >(req.nblks - resp.nblks_alloced)};
    const auto nentries{m_slab_queues[slab_idx]->entries_needed(blks_needed)};
    if (req.is_contiguous && (nentries > 1)) { return BlkAllocStatus::FAILED; }

    auto free_excess{[this, &req, &resp, &slab_idx](const blk_count_t num_allocated) {
        resp.nblks_alloced += num_allocated;

        // We allocated whats asked but a given entry may be bigger than whats needed, any trailing blocks need to be
        // freed
        if (resp.nblks_alloced > req.nblks) {
            const blk_count_t residue_nblks{static_cast< blk_count_t >(resp.nblks_alloced - req.nblks)};
            HS_DBG_ASSERT_LT(residue_nblks, m_slab_queues[slab_idx]->slab_size(),
                             "Residue block count are not expected to exceed last entry");
            const blk_count_t needed_blocks{
                static_cast< blk_count_t >(m_slab_queues[slab_idx]->slab_size() - residue_nblks)};
            resp.out_blks.back().set_nblks(needed_blocks);
            resp.nblks_alloced -= residue_nblks;

            // Create the trail residue entry and use that to free them.
            auto residue_e{resp.out_blks.back()};
            residue_e.set_blk_num(residue_e.get_blk_num() + needed_blocks);
            residue_e.set_nblks(residue_nblks);
            BLKALLOC_LOG(TRACE, "Residue blocks {}", residue_e.to_string());
            resp.nblks_zombied += try_free_blks(residue_e, resp.excess_blks);
        }
    }};

    blk_count_t num_allocated{0};
    for (blk_num_t i{0}; i < nentries; ++i) {
        blk_cache_entry e;
        if (const auto popped_level{pop_slab(slab_idx, req.preferred_level, false /* only_this_level */, e)}) {
            resp.out_blks.push_back(e);
            num_allocated += m_slab_queues[slab_idx]->slab_size();

            // If we didn't get the level we requested for, its time to refill this slab
            if (popped_level.value() != req.preferred_level) { resp.need_refill = true; }
        } else {
            free_excess(num_allocated);
            return ((i == 0) && (num_allocated == 0)) ? BlkAllocStatus::FAILED : BlkAllocStatus::PARTIAL;
        }
    }

    free_excess(num_allocated);
    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus FreeBlkCacheQueue::break_up(const slab_idx_t slab_idx, const blk_cache_alloc_req& req,
                                           blk_cache_alloc_resp& resp) {
    if (slab_idx >= m_slab_queues.size() - 1) {
        return (resp.nblks_alloced > 0) ? BlkAllocStatus::PARTIAL : BlkAllocStatus::FAILED;
    }
    const auto status{try_alloc_in_slab(slab_idx + 1, req, resp)};
    if (status == BlkAllocStatus::SUCCESS) {
        COUNTER_INCREMENT(slab_metrics(slab_idx + 1), num_slab_splits, 1);
        return BlkAllocStatus::SUCCESS;
    } else {
        // free any partial result if contiguous
        if ((status == BlkAllocStatus::PARTIAL) && req.is_contiguous) {
            resp.nblks_zombied = try_free_blks(resp.out_blks, resp.excess_blks);
            resp.out_blks.clear();
        }
    }
    return break_up(slab_idx + 1, req, resp);
}

BlkAllocStatus FreeBlkCacheQueue::merge_down(const slab_idx_t slab_idx, const blk_cache_alloc_req& req,
                                             blk_cache_alloc_resp& resp) {
    if (slab_idx == req.min_slab_idx) {
        return (resp.nblks_alloced > 0) ? BlkAllocStatus::PARTIAL : BlkAllocStatus::FAILED;
    }
    const auto status{try_alloc_in_slab(slab_idx - 1, req, resp)};
    if (status == BlkAllocStatus::SUCCESS) {
        COUNTER_INCREMENT(slab_metrics(slab_idx - 1), num_slab_merges, 1);
        return status;
    }
    return merge_down(slab_idx - 1, req, resp);
}

std::shared_ptr< blk_cache_fill_session > FreeBlkCacheQueue::create_cache_fill_session(const bool fill_entire_cache) {
    const auto ptr{std::make_shared< blk_cache_fill_session >(m_slab_queues.size(), fill_entire_cache)};
    for (auto& sq : m_slab_queues) {
        const auto needed_count{sq->open_session(ptr->session_id, fill_entire_cache)};
        if (needed_count > 0) { ptr->slab_requirements.push_back(blk_cache_refill_status{needed_count, 0}); }
    }
    return ptr;
}

void FreeBlkCacheQueue::close_cache_fill_session(blk_cache_fill_session& fill_session) {
    for (auto& sq : m_slab_queues) {
        sq->close_session(fill_session.session_id);
    }
}

std::optional< blk_temp_t > FreeBlkCacheQueue::push_slab(const slab_idx_t slab_idx, const blk_cache_entry& entry,
                                                         const bool only_this_level) {
    const auto ret{m_slab_queues[slab_idx]->push(entry, only_this_level)};
    if (ret) {
        BLKALLOC_LOG(TRACE, "BlkCache: Pushed entry=[{}] to level=[{}.{}], slab_queue size={}", entry.to_string(),
                     m_slab_queues[slab_idx]->slab_size(), *ret, m_slab_queues[slab_idx]->num_level_entries(*ret));
    }
    return ret;
}

std::optional< blk_temp_t > FreeBlkCacheQueue::pop_slab(const slab_idx_t slab_idx, const blk_temp_t level,
                                                        const bool only_this_level, blk_cache_entry& out_entry) {
    const auto ret{m_slab_queues[slab_idx]->pop(level, only_this_level, out_entry)};
    if (ret) {
        BLKALLOC_LOG(TRACE, "BlkCache: Popped entry=[{}] from level=[{}.{}], slab_queue size={}", out_entry.to_string(),
                     m_slab_queues[slab_idx]->slab_size(), *ret, m_slab_queues[slab_idx]->num_level_entries(*ret));
    }
    return ret;
}

SlabCacheQueue::SlabCacheQueue(const blk_count_t slab_size, const std::vector< blk_cap_t >& level_limits,
                               const float refill_pct, BlkAllocMetrics* parent_metrics) :
        m_slab_size{slab_size}, m_metrics{m_slab_size, this, parent_metrics} {
    for (auto& limit : level_limits) {
        auto ptr{std::make_unique< folly::MPMCQueue< blk_cache_entry > >(limit)};
        m_level_queues.push_back(std::move(ptr));
        m_total_capacity += limit;
    }
    m_refill_threshold_limits = (static_cast< uint64_t >(m_total_capacity) * refill_pct) / 100;
    GAUGE_UPDATE(m_metrics, slab_total_entries, m_total_capacity);
}

std::optional< blk_temp_t > SlabCacheQueue::push(const blk_cache_entry& entry, const bool only_this_level) {
    const blk_temp_t start_level{
        static_cast< blk_temp_t >((entry.m_temp >= m_level_queues.size()) ? m_level_queues.size() - 1 : entry.m_temp)};
    blk_temp_t level{start_level};
    bool pushed{m_level_queues[start_level]->write(entry)};

    if (!pushed && !only_this_level) {
        do {
            level = (level + 1) % m_level_queues.size();
            if (level == start_level) break;
            pushed = m_level_queues[level]->write(entry);
        } while (!pushed);
    }
    return pushed ? std::optional< blk_temp_t >{level} : std::nullopt;
}

std::optional< blk_temp_t > SlabCacheQueue::pop(const blk_temp_t input_level, const bool only_this_level,
                                                blk_cache_entry& out_entry) {
    const blk_temp_t start_level{
        static_cast< blk_temp_t >((input_level >= m_level_queues.size()) ? m_level_queues.size() - 1 : input_level)};
    blk_temp_t level{start_level};
    bool popped{m_level_queues[start_level]->read(out_entry)};

    if (!popped && !only_this_level) {
        do {
            level = (level + 1) % m_level_queues.size();
            if (level == start_level) break;
            popped = m_level_queues[level]->read(out_entry);
        } while (!popped);
    }
    return popped ? std::optional< blk_temp_t >{start_level} : std::nullopt;
}

blk_cap_t SlabCacheQueue::entry_count() const {
    blk_cap_t sz{0};
    for (size_t l{0}; l < m_level_queues.size(); ++l) {
        sz += num_level_entries(l);
    }
    return sz;
}

blk_cap_t SlabCacheQueue::entry_capacity() const { return m_total_capacity; }

blk_cap_t SlabCacheQueue::num_level_entries(const blk_temp_t level) const { return m_level_queues[level]->sizeGuess(); }

blk_cap_t SlabCacheQueue::open_session(const uint64_t session_id, const bool fill_entire_cache) {
    blk_cap_t count{0};

    uint64_t id{m_refill_session.load(std::memory_order_acquire)};
    if (id == 0) {
        // If no running session, calculate how much we need to fill in this slab and try to start this session
        const auto nentries{entry_count()};
        if (fill_entire_cache || (nentries < m_refill_threshold_limits)) {
            count = (nentries > m_total_capacity) ? 0 : (m_total_capacity - nentries);
            if (!m_refill_session.compare_exchange_strong(id, session_id, std::memory_order_acq_rel)) { count = 0; }
        }
    }
    return count;
}

void SlabCacheQueue::close_session(const uint64_t session_id) {
    uint64_t expected_session_id{session_id};
    m_refill_session.compare_exchange_strong(expected_session_id, 0, std::memory_order_acq_rel);
}

SlabMetrics::SlabMetrics(const blk_count_t slab_size, SlabCacheQueue* const slab_queue, BlkAllocMetrics* const parent) :
        sisl::MetricsGroup{"SlabMetrics", fmt::format("{}_slab_{:03d}", parent->instance_name(), slab_size)},
        m_slab_queue{slab_queue} {
    REGISTER_COUNTER(num_slab_alloc, "Number of alloc attempts in this slab");
    REGISTER_COUNTER(num_slab_alloc_with_split, "Number of alloc served only by splitting higher slabs");
    REGISTER_COUNTER(num_slab_alloc_with_merge, "Number of alloc served only by merging lower slabs");
    REGISTER_COUNTER(num_slab_alloc_failure, "Number of alloc failures for this slab");
    REGISTER_COUNTER(num_slab_splits, "Number of split in this slab to serve lower slab alloc");
    REGISTER_COUNTER(num_slab_merges, "Number of merges in this slab to serve higher slab alloc");
    REGISTER_COUNTER(num_slab_refills, "Number of entries refilled in this slab");

    REGISTER_GAUGE(slab_available_entries, "Available entries in the slab for allocation");
    REGISTER_GAUGE(slab_total_entries, "Total entries possible in the slab for allocation");

    register_me_to_parent(parent);
    attach_gather_cb(std::bind(&SlabMetrics::on_gather, this));
}

void SlabMetrics::on_gather() { GAUGE_UPDATE(*this, slab_available_entries, m_slab_queue->entry_count()); }
} // namespace homestore
