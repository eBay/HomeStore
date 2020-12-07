/*
 * varsize_blk_allocator.cpp
 *
 *  Created on: Jun 17, 2015
 *      Author: Hari Kadayam
 */

#include "varsize_blk_allocator.h"
#include <iostream>
#include <thread>
#include <fds/utils.hpp>
#include <fmt/format.h>
#include <random>
#include "engine/homeds/btree/mem_btree.hpp"
#include <sds_logging/logging.h>
#include <utility/thread_factory.hpp>
#include "engine/common/homestore_flip.hpp"
#include "blk_cache_queue.h"

SDS_LOGGING_DECL(blkalloc)

namespace homestore {
static thread_local std::default_random_engine g_rd;

VarsizeBlkAllocator::VarsizeBlkAllocator(const VarsizeBlkAllocConfig& cfg, const bool init,
                                         const chunk_num_t chunk_id) :
        BlkAllocator{cfg, chunk_id},
        m_chunk_id{chunk_id},
        m_cfg{cfg},
        m_state{BlkAllocatorState::WAITING},
        m_rand_portion_num_generator{0, static_cast< blk_count_t >(cfg.get_total_portions() - 1)},
        m_metrics{cfg.get_name().c_str()} {
    BLKALLOC_LOG(INFO, "Creating VarsizeBlkAllocator with config: {}", cfg.to_string());

    // TODO: Raise exception when blk_size > page_size or total blks is less than some number etc...
    m_bm = std::make_unique< sisl::Bitset >(cfg.get_total_blks(), chunk_id, HS_STATIC_CONFIG(drive_attr.align_size));

    // Create segments with as many blk groups as configured.
    const blk_cap_t seg_nblks = cfg.get_total_blks() / cfg.get_total_segments();

    m_segments.reserve(cfg.get_total_segments());
    for (seg_num_t i{0U}; i < cfg.get_total_segments(); ++i) {
        const std::string seg_name = fmt::format("{}_seg_{}", cfg.get_name(), i);
        auto seg = std::make_unique< BlkAllocSegment >(seg_nblks, i, cfg.get_portions_per_segment(), seg_name);
        m_segments.push_back(std::move(seg));
    }

    // Create free blk Cache of type Queue
    m_fb_cache = std::make_unique< FreeBlkCacheQueue >(cfg.m_slab_config, &m_metrics);

    // Start a thread which will do sweeping job of free segments
    if (init) { inited(); }
}

VarsizeBlkAllocator::~VarsizeBlkAllocator() {
    {
        std::lock_guard< std::mutex > lk(m_mutex);
        if (m_state != BlkAllocatorState::EXITING) {
            BLKALLOC_LOG(DEBUG, "Allocator state change from {} to {}", m_state, BlkAllocatorState::EXITING);
            m_state = BlkAllocatorState::EXITING;
        }
    }

    m_cv.notify_all();
    if (m_thread_id.joinable()) { m_thread_id.join(); }
}

// Runs only in per sweep thread. In other words, this is a single threaded state machine.
void VarsizeBlkAllocator::allocator_state_machine() {
    BLKALLOC_LOG(INFO, "Starting new blk sweep thread, thread num = {}", sisl::ThreadLocalContext::my_thread_num());
    BlkAllocSegment* sweep_seg = nullptr;
    std::shared_ptr< blk_cache_fill_session > fill_session;
    bool sweep = false;

    // Before entering to wait state, the state machine should fill the cache first.
    request_more_blks(nullptr, true /* fill_entire_cache */);

    while (true) {
        sweep_seg = nullptr;
        sweep = false;
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (m_state == BlkAllocatorState::WAITING) {
                BLKALLOC_LOG(TRACE, "Allocator is going to Waiting State");

                auto woken = m_cv.wait_for(
                    lk, std::chrono::milliseconds(HS_DYNAMIC_CONFIG(blkallocator.free_blk_cache_refill_frequency_ms)),
                    [&]() { return (m_state != BlkAllocatorState::WAITING); });
                if (!woken) { // Timed out
                    _prepare_sweep(nullptr, false /* fill_entire_cache */);
                }
            }

            if (m_state == BlkAllocatorState::SWEEP_SCHEDULED) {
                BLKALLOC_LOG(TRACE, "Allocator state change from {} to {}", m_state, BlkAllocatorState::SWEEPING);
                m_state = BlkAllocatorState::SWEEPING;
                sweep_seg = m_sweep_segment;
                fill_session = m_cur_fill_session;
                sweep = true;
            } else if (m_state == BlkAllocatorState::EXITING) {
                BLKALLOC_LOG(TRACE, "TODO: Handle exiting message more periodically");
                break;
            } else {
                BLKALLOC_ASSERT(DEBUG, 0, "Allocator thread is woken on unexpected state = {}", m_state);
            }
        }

        if (sweep) {
            BLKALLOC_LOG(DEBUG, "Starting to sweep based on requirement {}", fill_session->to_string());
            fill_cache(sweep_seg, *fill_session);
            {
                std::unique_lock< std::mutex > lk(m_mutex);
                m_sweep_segment = nullptr;
                if (m_state != BlkAllocatorState::EXITING) { m_state = BlkAllocatorState::WAITING; }
                m_cv.notify_all();
            }
            BLKALLOC_LOG(DEBUG, "Sweep session completed with fill details {}", fill_session->to_string());
        }
    }
}

bool VarsizeBlkAllocator::is_blk_alloced(const BlkId& b) const {
    if (!m_inited) { return true; }
    if (!m_bm->is_bits_set(b.get_blk_num(), b.get_nblks())) {
        BLKALLOC_ASSERT(RELEASE, 0, "Expected bits to reset");
        return false;
    }
    return (BlkAllocator::is_blk_alloced_on_disk(b));
}

void VarsizeBlkAllocator::inited() {
    m_bm->copy(*(get_disk_bm()));
    BlkAllocator::inited();

    BLKALLOC_LOG(INFO, "VarSizeBlkAllocator initialized loading bitmap of size={} used blks={} from persistent storage",
                 m_bm->size(), get_alloced_blk_count());
    m_thread_id = sisl::named_thread("blkalloc_sweep", bind_this(VarsizeBlkAllocator::allocator_state_machine, 0));
}

// This runs on per region thread and is at present single threaded.
/* we are going through the segments which has maximum free blks so that we can ensure that all slabs are populated.
 * We might need to find a efficient way of doing it later. It stop processing the segment when any slab greater
 * then slab_indx is full.
 */
void VarsizeBlkAllocator::fill_cache(BlkAllocSegment* seg, blk_cache_fill_session& fill_session) {
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("varsize_blkalloc_bypass_cache")) {
        m_fb_cache->close_cache_fill_session(fill_session);
        return;
    }
#endif

    // Pick a segment if scan if not provided
    if (seg == nullptr) {
        // For now we are picking segment[0], we need to find a way to track allocation per segment
        seg = m_segments[0].get();
#if 0
        uint64_t max_blks{0};
        for (uint32_t i{0}; i < m_segments.size(); ++i) {
            if (m_segments[i]->get_free_blks() > max_blks) {
                seg = m_segments[i];
                max_blks = m_segments[i]->get_free_blks();
            }
        }

        if (seg == nullptr) {
            BLKALLOC_LOG(ERROR, "There are no more free blocks in bitset, everything is swept");
            return;
        }
#endif
    }

    blk_num_t start_portion_num = seg->get_seg_num() * m_cfg.get_portions_per_segment() + seg->get_clock_hand();
    auto portion_num = start_portion_num;

    do {
        BLKALLOC_ASSERT_CMP(LOGMSG, portion_num, <, m_cfg.get_total_portions());
        fill_cache_in_portion(portion_num, fill_session);

        // We have fully satisifed this session requirements
        if (fill_session.overall_refill_done) { break; }

        // Goto next group within the segment.
        seg->inc_clock_hand();
        portion_num = seg->get_clock_hand();
    } while (portion_num != start_portion_num);

    if (fill_session.overall_refilled_num_blks) {
        BLKALLOC_LOG(DEBUG, "Allocator sweep session={} added {} blks to blk cache", fill_session.session_id,
                     fill_session.overall_refilled_num_blks);
    } else {
        BLKALLOC_LOG(DEBUG, "Allocator sweep session={} failed to add any blocks to blk cache",
                     fill_session.session_id);
    }
    m_fb_cache->close_cache_fill_session(fill_session);
}

void VarsizeBlkAllocator::fill_cache_in_portion(const blk_num_t portion_num, blk_cache_fill_session& fill_session) {
    auto cur_blk_id = portion_num * m_cfg.get_blks_per_portion();
    auto end_blk_id = cur_blk_id + m_cfg.get_blks_per_portion();

    blk_cache_fill_req fill_req;
    fill_req.preferred_level = 1;

    BLKALLOC_LOG(TRACE, "Allocator sweep session={} for portion_num={} sweep blk_id_range=[{}-{}]",
                 fill_session.session_id, portion_num, cur_blk_id, end_blk_id);

    BlkAllocPortion& portion = *(get_blk_portion(portion_num));
    {
        auto lock{portion.portion_auto_lock()};
        while (!fill_session.overall_refill_done && (cur_blk_id < end_blk_id)) {
            // Get next reset bits and insert to cache and then reset those bits
            const auto b = m_bm->get_next_contiguous_n_reset_bits(cur_blk_id, end_blk_id, 1, end_blk_id - cur_blk_id);

            // If there are no free blocks are none within the assigned portion
            if (b.nbits == 0) { break; }

            HS_DEBUG_ASSERT_GE(end_blk_id, b.start_bit, "Expected start bit to be greater than end bit");
            HISTOGRAM_OBSERVE(m_metrics, frag_pct_distribution, 100 / (static_cast< double >(b.nbits)));

            // Fill the blk cache and keep accounting of number of blks added
            fill_req.start_blk_num = b.start_bit;
            fill_req.nblks = b.nbits;
            fill_req.preferred_level = portion.temperature();
            auto nblks_added = m_fb_cache->try_fill_cache(fill_req, fill_session);

            HS_DEBUG_ASSERT_LE(nblks_added, b.nbits);

            // Set the bitmap indicating the blks are allocated
            m_bm->set_bits(b.start_bit, nblks_added);
            cur_blk_id = b.start_bit + b.nbits;

            BLKALLOC_LOG(DEBUG, "Sweep session={} portion_num={}, setting bit={} nblks={} set_bits_count={}",
                         fill_session.session_id, portion_num, b.start_bit, nblks_added, get_alloced_blk_count());
        }

        if (fill_session.need_notify()) {
            // If we have filled enough to satisy notification, do so
            fill_session.set_urgent_satisfied();
            m_cv.notify_all();
        }
    }
    BLKALLOC_LOG(TRACE, "Allocator Portion num={} sweep session={} completed, so far added {} blks",
                 fill_session.session_id, portion_num, fill_session.overall_refilled_num_blks);
}

BlkAllocStatus VarsizeBlkAllocator::alloc(BlkId& out_blkid) {
    static thread_local std::vector< BlkId > s_ids;
    s_ids.clear();

    auto status = alloc(1, blk_alloc_hints{}, s_ids);
    if (status == BlkAllocStatus::SUCCESS) { out_blkid = s_ids[0]; }
    return status;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(const blk_count_t nblks, const blk_alloc_hints& hints,
                                          std::vector< BlkId >& out_blkids) {
    BLKALLOC_ASSERT(LOGMSG, m_inited, "Alloc before initialized");
    BLKALLOC_ASSERT_CMP(LOGMSG, nblks % hints.multiplier, ==, 0);
    BLKALLOC_LOG(TRACE, "nblks={}, hints multiplier={}", nblks, hints.multiplier);

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("varsize_blkalloc_no_blks", nblks)) { return BlkAllocStatus::SPACE_FULL; }

#if 0
    auto split_cnt = homestore_flip->get_test_flip< int >("blkalloc_split_blk");
    if (!hints.is_contiguous && split_cnt && nblks > split_cnt.get()) {
        nblks = sisl::round_up((nblks / split_cnt.get()), hints.multiplier);
        BLKALLOC_LOG(DEBUG, "nblks={}, split_cnt={}",  nblks, split_cnt.get());
    }
#endif

    if (homestore_flip->test_flip("varsize_blkalloc_bypass_cache")) {
        return alloc_blks_direct(nblks, hints, out_blkids);
    }
#endif

    // Allocate from blk cache
    static thread_local blk_cache_alloc_resp s_alloc_resp;
    blk_cache_alloc_req alloc_req{nblks, hints.desired_temp, hints.is_contiguous,
                                  FreeBlkCache::find_slab(hints.multiplier)};

    uint32_t retry{0};
    auto status{BlkAllocStatus::FAILED};
    COUNTER_INCREMENT(m_metrics, num_alloc, 1);

    do {
        s_alloc_resp.reset();
        status = m_fb_cache->try_alloc_blks(alloc_req, s_alloc_resp);

        // If there are some excess blks which are removed from cache, but couldn't put it back in to the cache it is
        // reported in the response as excess blks, we need to put that back to bitmap.
        for (const auto& e : s_alloc_resp.excess_blks) {
            BLKALLOC_LOG(DEBUG, "Freeing in bitmap of entry={} - excess of alloc_blks size={}", e.to_string(),
                         s_alloc_resp.excess_blks.size());
            free_on_bitmap(blk_cache_entry_to_blkid(e));
        }

        if (status == BlkAllocStatus::SUCCESS) {
            // If the cache has depleted a bit, kick of sweep thread to fill the cache.
            if (s_alloc_resp.need_refill) { request_more_blks(nullptr, false /* fill_entire_cache */); }
            BLKALLOC_LOG(TRACE, "Alloced blk_num={}", s_alloc_resp.out_blks[0].to_string());

            // Convert the resp blk cache entries to blkids
            blk_cache_entries_to_blkids(s_alloc_resp.out_blks, out_blkids);
#ifndef NDEBUG
            blk_count_t alloced_nblks = 0;
            for (const auto& b : out_blkids) {
                BLKALLOC_ASSERT(DEBUG, is_set_on_bitmap(b), "Expected blkid={} to be already set in bitmap",
                                b.to_string());
                alloced_nblks += b.get_nblks();
            }
            BLKALLOC_ASSERT(DEBUG, (nblks == alloced_nblks), "Requested blks={} alloced_blks={}", nblks,
                            alloced_nblks);
#endif
            incr_alloced_blk_count(nblks);
            break;
        }

        BLKALLOC_LOG(DEBUG, "nblks={} failed to alloc from fb cache, trying to alloc from bitset directly", nblks);
        status = alloc_blks_direct(nblks, hints, out_blkids);
        if (status == BlkAllocStatus::SUCCESS) {
            BLKALLOC_LOG(TRACE, "Alloced blk_num={} directly", s_alloc_resp.out_blks[0].to_string());
            break;
        }

        // If we come here cache is not having any data. This is not normal case. Hence ask only upto twice the
        // biggest slab to allow concurrent blk allocator just doesn't gobble up the new blks alloced
        if (++retry < HS_DYNAMIC_CONFIG(blkallocator.max_varsize_blk_alloc_attempt)) {
            COUNTER_INCREMENT(m_metrics, num_retries, 1);
            const auto min_nblks = m_cfg.highest_slab_blks_count() * 2;
            BLKALLOC_LOG(DEBUG,
                         "Failed to allocate {} blks from blk cache, requesting refill atleast {} blks and retry={}",
                         nblks, min_nblks, retry);
            request_more_blks_wait(nullptr /* seg */, min_nblks);
        } else {
            break;
        }

#if 0
        // If we come here cache is not having any data. This is not normal case. Hence ask only upto twice the
        // biggest slab to allow concurrent blk allocator just doesn't gobble up the new blks alloced
        if (++retry < HS_DYNAMIC_CONFIG(blkallocator.max_varsize_blk_alloc_attempt)) {
            COUNTER_INCREMENT(m_metrics, num_retries, 1);
            const auto min_nblks = m_cfg.highest_slab_blks_count() * 2;
            BLKALLOC_LOG(DEBUG,
                         "Failed to allocate {} blks from blk cache, requesting refill atleast {} blks and retry={}",
                         nblks, min_nblks, retry);
            request_more_blks_wait(nullptr /* seg */, min_nblks);
        } else {
            BLKALLOC_LOG(
                DEBUG, "nblks={} failed to alloc after retries={} from blk cache, trying to alloc from bitset directly",
                nblks, retry);
            status = alloc_blks_direct(nblks, hints, out_blkids);
            break;
        }
#endif
    } while (true);

    if (status != BlkAllocStatus::SUCCESS) {
        BLKALLOC_LOG(ERROR, "nblks={} failed to alloc cache and direct after retries={}, giving up", nblks, retry);
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        status = BlkAllocStatus::SPACE_FULL;
    }
    return status;
}

void VarsizeBlkAllocator::free(const BlkId& b) {
    if (!m_inited) {
        BLKALLOC_LOG(DEBUG, "Free not required for blk num = {}", b.get_blk_num());
        return;
    }

    static thread_local std::vector< blk_cache_entry > excess_blks;
    excess_blks.clear();
    uint16_t num_zombied{0};

    if (m_fb_cache->try_free_blks(blkid_to_blk_cache_entry(b), excess_blks, num_zombied) != BlkAllocStatus::SUCCESS) {
        for (const auto& e : excess_blks) {
            BLKALLOC_LOG(TRACE, "Freeing in bitmap of entry={} - excess of free_blks size={}", e.to_string(),
                         excess_blks.size());
            free_on_bitmap(blk_cache_entry_to_blkid(e));
        }
    }
    decr_alloced_blk_count(b.get_nblks());
    BLKALLOC_LOG(TRACE, "Freed blk_num={}", blkid_to_blk_cache_entry(b).to_string());
}

blk_cap_t VarsizeBlkAllocator::get_available_blks() const { return m_cfg.get_total_blks() - get_used_blks(); }
blk_cap_t VarsizeBlkAllocator::get_used_blks() const { return get_alloced_blk_count(); }

void VarsizeBlkAllocator::free_on_bitmap(const BlkId& b) {
    BlkAllocPortion* portion = blknum_to_portion(b.get_blk_num());
    {
        // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache bm.
        auto lock{portion->portion_auto_lock()};
        BLKALLOC_ASSERT(RELEASE, m_bm->is_bits_set(b.get_blk_num(), b.get_nblks()), "Expected bits to be set");
        m_bm->reset_bits(b.get_blk_num(), b.get_nblks());
    }
    BLKALLOC_LOG(DEBUG, "Freeing directly to portion={} blkid={} set_bits_count={}",
                 blknum_to_portion_num(b.get_blk_num()), b.to_string(), get_alloced_blk_count());
}

#ifndef NDEBUG
bool VarsizeBlkAllocator::is_set_on_bitmap(const BlkId& b) {
    BlkAllocPortion* portion = blknum_to_portion(b.get_blk_num());
    {
        // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache bm.
        auto lock{portion->portion_auto_lock()};
        return m_bm->is_bits_set(b.get_blk_num(), b.get_nblks());
    }
}
#endif

/**
 * @brief Request more blocks to be filled into cache from optionally a specified segment. This method can be run on
 * any thread and concurrently.
 *
 * @param seg [OPTIONAL] If seg is nullptr, then it picks the 1st segment to allocate from.
 * @param fill_entire_cache Should entire blk cache be filled or we need to fill upto the limit requested
 */
void VarsizeBlkAllocator::request_more_blks(BlkAllocSegment* seg, const bool fill_entire_cache) {
    bool notify = false;
    {
        std::unique_lock< std::mutex > lk(m_mutex);
        if (m_state == BlkAllocatorState::WAITING) {
            _prepare_sweep(seg, fill_entire_cache);
            notify = true;
            BLKALLOC_LOG(DEBUG, "Allocator is requested to refill blk cache and move to {} state", m_state);
        } else {
            BLKALLOC_LOG(TRACE,
                         "Allocator is requested to refill blk cache but it is in {} state, ignoring this request",
                         m_state);
        }
    }

    if (notify) { m_cv.notify_all(); }
}

void VarsizeBlkAllocator::request_more_blks_wait(BlkAllocSegment* seg, const blk_cap_t wait_for_blks_count) {
    std::unique_lock< std::mutex > lk(m_mutex);
    if (m_state == BlkAllocatorState::WAITING) {
        _prepare_sweep(seg, false /* fill_entire_cache */);
        m_cv.notify_all();
    }

    if ((m_state == BlkAllocatorState::SWEEP_SCHEDULED) || (m_state == BlkAllocatorState::SWEEPING)) {
        // Wait for notification that it is either done sweeping or if it is sweeping it satisfies the requirement
        // to wait for blks
        m_cur_fill_session->urgent_need_atleast(wait_for_blks_count);
        m_cv.wait(lk, [this]() {
            return (((m_state != BlkAllocatorState::SWEEPING) && (m_state != BlkAllocatorState::SWEEP_SCHEDULED)) ||
                    (!m_cur_fill_session->is_urgent_req_pending()));
        });
        BLKALLOC_LOG(DEBUG, "Refill session={} refilled {} blks overall and atleast {} blks since waiting",
                     m_cur_fill_session->session_id, m_cur_fill_session->overall_refilled_num_blks,
                     wait_for_blks_count);
    } else {
        BLKALLOC_LOG(DEBUG,
                     "Allocator is requested to refill blk cache but it is in {} state, so ignoring this request",
                     m_state);
    }
}

BlkAllocStatus VarsizeBlkAllocator::alloc_blks_direct(const blk_count_t nblks, const blk_alloc_hints& hints,
                                                      std::vector< BlkId >& out_blkids) {
    // Search all segments starting with some random portion num within each segment
    const blk_num_t start_portion_num = m_rand_portion_num_generator(g_rd);
    auto portion_num = start_portion_num;
    const blk_count_t min_blks = hints.is_contiguous ? nblks : hints.multiplier;
    const auto out_blk_idx = out_blkids.size();
    blk_count_t nblks_remain = nblks;

    do {
        BlkAllocPortion& portion = *(get_blk_portion(portion_num));
        auto cur_blk_id = portion_num * m_cfg.get_blks_per_portion();
        auto end_blk_id = cur_blk_id + m_cfg.get_blks_per_portion();
        {
            auto lock{portion.portion_auto_lock()};
            while (nblks_remain && (cur_blk_id < end_blk_id)) {
                // Get next reset bits and insert to cache and then reset those bits
                const auto b = m_bm->get_next_contiguous_n_reset_bits(cur_blk_id, end_blk_id,
                                                                      std::min(min_blks, nblks_remain), nblks_remain);
                if (b.nbits == 0) { break; }
                HS_DEBUG_ASSERT_GE(end_blk_id, b.start_bit, "Expected start bit to be greater than end bit");
                HS_DEBUG_ASSERT_LE(b.nbits, nblks_remain);

                nblks_remain -= b.nbits;
                out_blkids.emplace_back(b.start_bit, b.nbits, m_chunk_id);

                // Set the bitmap indicating the blks are allocated
                m_bm->set_bits(b.start_bit, b.nbits);
                cur_blk_id = b.start_bit + b.nbits;

                BLKALLOC_LOG(DEBUG,
                             "Allocated directly from portion={} nnblks={} Blk_num={} nblks={} set_bit_count={}",
                             portion_num, nblks, b.start_bit, b.nbits, get_alloced_blk_count());
            }
        }
        if (++portion_num == m_cfg.get_total_portions()) { portion_num = 0; }
        BLKALLOC_LOG(TRACE, "alloc direct unable to find in prev portion, searching in portion={}, start_portion={}",
                     portion_num, start_portion_num);
    } while (nblks_remain && (portion_num != start_portion_num));

    if (nblks_remain) {
        for (auto i{out_blk_idx}; i < out_blkids.size(); ++i) {
            free_on_bitmap(out_blkids[i]);
        }
        out_blkids.erase(std::next(std::begin(out_blkids), out_blk_idx), std::end(out_blkids));
        return BlkAllocStatus::SPACE_FULL;
    }
    COUNTER_INCREMENT(m_metrics, num_blks_alloc_direct, 1);
    incr_alloced_blk_count(nblks);
    return BlkAllocStatus::SUCCESS;
}

/* This method assumes that mutex to protect state is already taken. */
void VarsizeBlkAllocator::_prepare_sweep(BlkAllocSegment* seg, const bool fill_entire_cache) {
    m_sweep_segment = seg;
    m_cur_fill_session = m_fb_cache->create_cache_fill_session(fill_entire_cache);
    m_state = BlkAllocatorState::SWEEP_SCHEDULED;
}

void VarsizeBlkAllocator::blk_cache_entries_to_blkids(const std::vector< blk_cache_entry >& entries,
                                                      std::vector< BlkId >& out_blkids) {
    for (const auto& e : entries) {
        out_blkids.emplace_back(e.get_blk_num(), e.get_nblks(), m_chunk_id);
    }
}

BlkId VarsizeBlkAllocator::blk_cache_entry_to_blkid(const blk_cache_entry& e) {
    return BlkId{e.get_blk_num(), e.get_nblks(), m_chunk_id};
}

blk_cache_entry VarsizeBlkAllocator::blkid_to_blk_cache_entry(const BlkId& bid) {
    return blk_cache_entry{bid.get_blk_num(), bid.get_nblks(), 0};
}

std::string VarsizeBlkAllocator::to_string() const {
    return fmt::format("BlkAllocator={} state={} total_blks={} cached_blks={} alloced_blks={}", m_cfg.get_name(),
                       m_state, m_cfg.get_total_blks(), m_fb_cache->total_free_blks(), get_alloced_blk_count());
}

nlohmann::json VarsizeBlkAllocator::get_metrics_in_json() { return m_metrics.get_result_in_json(true); }
} // namespace homestore