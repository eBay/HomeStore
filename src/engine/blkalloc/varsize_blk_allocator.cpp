/*
 * varsize_blk_allocator.cpp
 *
 *  Created on: Jun 17, 2015
 *      Author: Hari Kadayam
 */

#include <iostream>
#include <random>
#include <thread>

#include <fds/utils.hpp>
#include <fmt/format.h>
#include <sds_logging/logging.h>
#include <utility/thread_factory.hpp>

#include "blk_cache_queue.h"
#include "engine/homeds/btree/mem_btree.hpp"
#include "engine/common/homestore_flip.hpp"

#include "varsize_blk_allocator.h"

SDS_LOGGING_DECL(blkalloc)

namespace homestore {

VarsizeBlkAllocator::VarsizeBlkAllocator(const VarsizeBlkAllocConfig& cfg, const bool init,
                                         const chunk_num_t chunk_id) :
        BlkAllocator{cfg, chunk_id},
        m_cfg{cfg},
        m_state{BlkAllocatorState::WAITING},
        m_rand_portion_num_generator{0, static_cast< blk_count_t >(cfg.get_total_portions() - 1)},
        m_metrics{cfg.get_name().c_str()} {

    BLKALLOC_LOG(INFO, "Creating VarsizeBlkAllocator with config: {}", cfg.to_string());

    // TODO: Raise exception when blk_size > page_size or total blks is less than some number etc...
    m_cache_bm =
        std::make_unique< sisl::Bitset >(cfg.get_total_blks(), chunk_id, HS_STATIC_CONFIG(drive_attr.align_size));

    // NOTE: Number of blocks must be modulo word size so locks do not fall on same word
    HS_RELEASE_ASSERT_EQ(m_cfg.get_blks_per_portion() % m_cache_bm->word_size(), 0,
                         "Blocks per portion must be multiple of bitmpa word size.")

    // Create segments with as many blk groups as configured.
    const blk_cap_t seg_nblks{cfg.get_total_blks() / cfg.get_total_segments()};

    m_segments.reserve(cfg.get_total_segments());
    for (seg_num_t i{0U}; i < cfg.get_total_segments(); ++i) {
        const std::string seg_name{fmt::format("{}_seg_{}", cfg.get_name(), i)};
        auto seg{std::make_unique< BlkAllocSegment >(seg_nblks, i, cfg.get_portions_per_segment(), seg_name)};
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
    bool sweep{false};

    // Before entering to wait state, the state machine should fill the cache first.
    request_more_blks(nullptr, true /* fill_entire_cache */);

    while (true) {
        sweep_seg = nullptr;
        sweep = false;
        {
            std::unique_lock< std::mutex > lk(m_mutex);
            if (m_state == BlkAllocatorState::WAITING) {
                BLKALLOC_LOG(TRACE, "Allocator is going to Waiting State");

                const auto woken{m_cv.wait_for(
                    lk, std::chrono::milliseconds(HS_DYNAMIC_CONFIG(blkallocator.free_blk_cache_refill_frequency_ms)),
                    [&]() { return (m_state != BlkAllocatorState::WAITING); })};
                if (!woken) { // Timed out
                    prepare_sweep(nullptr, false /* fill_entire_cache */);
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
            }
            m_cv.notify_all();
            BLKALLOC_LOG(DEBUG, "Sweep session completed with fill details {}", fill_session->to_string());
        }
    }
}

bool VarsizeBlkAllocator::is_blk_alloced(const BlkId& b, const bool use_lock) const {
    if (!m_inited) { return true; }
    auto bits_set{[this, &b]() {
        // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache
        // bm.
        if (!m_cache_bm->is_bits_set(b.get_blk_num(), b.get_nblks())) {
            BLKALLOC_ASSERT(RELEASE, 0, "Expected bits to set");
            return false;
        }
        return true;
    }};
    if (use_lock) {
        const BlkAllocPortion* const portion{blknum_to_portion_const(b.get_blk_num())};
        auto lock{portion->portion_auto_lock()};
        if (!bits_set()) return false;
    } else {
        if (!bits_set()) return false;
    }
    return true;
}

void VarsizeBlkAllocator::inited() {
    m_cache_bm->copy(*(get_disk_bm()));
    BlkAllocator::inited();

    BLKALLOC_LOG(INFO, "VarSizeBlkAllocator initialized loading bitmap of size={} used blks={} from persistent storage",
                 m_cache_bm->size(), get_alloced_blk_count());
    m_thread_id = sisl::named_thread("blkalloc_sweep", bind_this(VarsizeBlkAllocator::allocator_state_machine, 0));
}

// This runs on per region thread and is at present single threaded.
/* we are going through the segments which has maximum free blks so that we can ensure that all slabs are populated.
 * We might need to find a efficient way of doing it later. It stop processing the segment when any slab greater
 * then slab_indx is full.
 */
void VarsizeBlkAllocator::fill_cache(BlkAllocSegment* const in_seg, blk_cache_fill_session& fill_session) {
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("varsize_blkalloc_bypass_cache")) {
        m_fb_cache->close_cache_fill_session(fill_session);
        return;
    }
#endif

    // Pick a segment if scan if not provided
    BlkAllocSegment* seg{in_seg};
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

    const blk_num_t start_portion_num{seg->get_seg_num() * m_cfg.get_portions_per_segment() + seg->get_clock_hand()};
    auto portion_num{start_portion_num};

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
    auto cur_blk_id{portion_num * m_cfg.get_blks_per_portion()};
    const auto end_blk_id{cur_blk_id + m_cfg.get_blks_per_portion() - 1};

    blk_cache_fill_req fill_req;
    fill_req.preferred_level = 1;

    BLKALLOC_LOG(TRACE, "Allocator sweep session={} for portion_num={} sweep blk_id_range=[{}-{}]",
                 fill_session.session_id, portion_num, cur_blk_id, end_blk_id);

    BlkAllocPortion& portion{*(get_blk_portion(portion_num))};
    {
        auto lock{portion.portion_auto_lock()};
        while (!fill_session.overall_refill_done && (cur_blk_id <= end_blk_id)) {
            // Get next reset bits and insert to cache and then reset those bits
            const auto b{
                m_cache_bm->get_next_contiguous_n_reset_bits(cur_blk_id, end_blk_id, 1, end_blk_id - cur_blk_id + 1)};

            // If there are no free blocks within the assigned portion
            if (b.nbits == 0) { break; }

            HS_DEBUG_ASSERT_GE(end_blk_id, b.start_bit, "Expected start bit to be smaller than portion end bit");
            HS_DEBUG_ASSERT_GE(end_blk_id, (b.start_bit + b.nbits - 1),
                               "Expected end bit to be smaller than portion end bit");
            HISTOGRAM_OBSERVE(m_metrics, frag_pct_distribution, 100 / (static_cast< double >(b.nbits)));

            // Fill the blk cache and keep accounting of number of blks added
            fill_req.start_blk_num = b.start_bit;
            fill_req.nblks = b.nbits;
            fill_req.preferred_level = portion.temperature();
            const auto nblks_added{m_fb_cache->try_fill_cache(fill_req, fill_session)};

            HS_DEBUG_ASSERT_LE(nblks_added, b.nbits);

            BLKALLOC_LOG(DEBUG, "Sweep session={} portion_num={}, setting bit={} nblks={} set_bits_count={}",
                         fill_session.session_id, portion_num, b.start_bit, nblks_added, get_alloced_blk_count());

            // Set the bitmap indicating the blocks are allocated
            if (nblks_added > 0) {
                m_cache_bm->set_bits(b.start_bit, nblks_added);
                if (portion.decrease_available_blocks(nblks_added) == 0) break;
            }
            cur_blk_id = b.start_bit + b.nbits;
        }
    }
    if (fill_session.need_notify()) {
        // If we have filled enough to satisfy notification, do so
        fill_session.set_urgent_satisfied();
        m_cv.notify_all();
    }

    BLKALLOC_LOG(TRACE, "Allocator Portion num={} sweep session={} completed, so far added {} blks",
                 fill_session.session_id, portion_num, fill_session.overall_refilled_num_blks);
}

BlkAllocStatus VarsizeBlkAllocator::alloc(BlkId& out_blkid) {
    static thread_local std::vector< BlkId > s_ids;
    s_ids.clear();

    const auto status{alloc(1, blk_alloc_hints{}, s_ids)};
    if (status == BlkAllocStatus::SUCCESS) { out_blkid = s_ids[0]; }
    return status;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(const blk_count_t nblks, const blk_alloc_hints& hints,
                                          std::vector< BlkId >& out_blkids) {
    BLKALLOC_ASSERT(LOGMSG, m_inited, "Alloc before initialized");
    BLKALLOC_ASSERT_CMP(LOGMSG, nblks % hints.multiplier, ==, 0);
    BLKALLOC_LOG(TRACE, "nblks={}, hints multiplier={}", nblks, hints.multiplier);

#ifdef _PRERELEASE
    if (hints.error_simulate && homestore_flip->test_flip("varsize_blkalloc_no_blks", nblks)) {
        return BlkAllocStatus::SPACE_FULL;
    }

    // NOTE: There is a small chance this can fail if all the blocks have already been allocated to slabs
    if (homestore_flip->test_flip("varsize_blkalloc_bypass_cache")) {
        blk_count_t num_alllocated{0};
        const auto status{alloc_blks_direct(nblks, hints, out_blkids, num_alllocated)};
        if ((status == BlkAllocStatus::SUCCESS) || (status == BlkAllocStatus::PARTIAL)) {
            incr_alloced_blk_count(num_alllocated);
        }
        return status;
    }
#endif

    // Allocate from blk cache
    static thread_local blk_cache_alloc_resp s_alloc_resp;
    const blk_cache_alloc_req alloc_req{nblks, hints.desired_temp, hints.is_contiguous,
                                        FreeBlkCache::find_slab(hints.multiplier),
                                        FreeBlkCache::find_slab(hints.max_blks_per_entry)};

    auto status{BlkAllocStatus::FAILED};
    COUNTER_INCREMENT(m_metrics, num_alloc, 1);

    auto free_excess_blocks{[this]() {
        // put excess blocks back on bitmap
        for (const auto& e : s_alloc_resp.excess_blks) {
            BLKALLOC_LOG(DEBUG, "Freeing in bitmap of entry={} - excess of alloc_blks size={}", e.to_string(),
                         s_alloc_resp.excess_blks.size());
            free_on_bitmap(blk_cache_entry_to_blkid(e));
        }
    }};

    auto discard_current_allocation{[this, &free_excess_blocks]() {
        if (!s_alloc_resp.out_blks.empty()) {
            s_alloc_resp.nblks_zombied = m_fb_cache->try_free_blks(s_alloc_resp.out_blks, s_alloc_resp.excess_blks);
        }
        free_excess_blocks();
        s_alloc_resp.reset();
    }};

    s_alloc_resp.reset();
    blk_count_t total_allocated{0};
    // retries must be at least two to allow slab refill logic to run
    const uint32_t max_retries{std::max< uint32_t >(HS_DYNAMIC_CONFIG(blkallocator.max_varsize_blk_alloc_attempt), 2)};
    for (uint32_t retry{0}; (retry < max_retries); ++retry) {
        status = m_fb_cache->try_alloc_blks(alloc_req, s_alloc_resp);
        if ((status == BlkAllocStatus::SUCCESS) || ((status == BlkAllocStatus::PARTIAL) && !hints.is_contiguous)) {
            // If the cache has depleted a bit, kick of sweep thread to fill the cache.
            if (s_alloc_resp.need_refill) { request_more_blks(nullptr, false /* fill_entire_cache */); }
            BLKALLOC_LOG(TRACE, "Alloced first blk_num={}", s_alloc_resp.out_blks[0].to_string());

            // Convert the response block cache entries to blkids
            blk_cache_entries_to_blkids(s_alloc_resp.out_blks, out_blkids);
            total_allocated = s_alloc_resp.nblks_alloced;
            break;
        } else {
            discard_current_allocation();
            if ((retry + 1) < max_retries) {
                COUNTER_INCREMENT(m_metrics, num_retries, 1);
                const auto min_nblks{std::max< blk_count_t >(m_cfg.highest_slab_blks_count() * 2, nblks)};
                BLKALLOC_LOG(
                    DEBUG, "Failed to allocate {} blks from blk cache, requesting refill at least {} blks and retry={}",
                    nblks, min_nblks, retry);
                request_more_blks_wait(nullptr /* seg */, min_nblks);
            }
        }
    }
    free_excess_blocks();

    if (hints.is_contiguous) {
        // failed to allocate in slab try direct.
        if (status != BlkAllocStatus::SUCCESS) {
            blk_count_t num_allocated{0};
            status = alloc_blks_direct(nblks, hints, out_blkids, num_allocated);
            if (status == BlkAllocStatus::SUCCESS) {
                total_allocated += num_allocated;
                BLKALLOC_LOG(TRACE, "Alloced blk_num={} directly", out_blkids.back().to_string());
            }
        }
    } else {
        if (status != BlkAllocStatus::SUCCESS) {
            // try to allocate remainder
            const blk_count_t nblks_remaining{static_cast< blk_count_t >(nblks - total_allocated)};
            BLKALLOC_LOG(DEBUG, "nblks={} failed to alloc all from fb cache, trying to alloc rest from bitset directly",
                         nblks_remaining);
            blk_count_t num_allocated{0};
            auto status2{alloc_blks_direct(nblks_remaining, hints, out_blkids, num_allocated)};
            if ((status2 == BlkAllocStatus::SUCCESS) || (status2 == BlkAllocStatus::PARTIAL)) {
                total_allocated += num_allocated;
                BLKALLOC_LOG(TRACE, "Alloced additional blk_num={} directly", out_blkids.back().to_string());
            } else {
                // failure to get more is really partial if we have some
                BLKALLOC_LOG(TRACE, "Failed to alloc additional blks directly with code {}", status2);
                if (status == BlkAllocStatus::PARTIAL) status2 = BlkAllocStatus::PARTIAL;
            }
            status = status2;
        }
    }

    switch (status) {
    case BlkAllocStatus::FAILED:
    case BlkAllocStatus::SPACE_FULL:
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        BLKALLOC_LOG(ERROR, "nblks={} failed to alloc any number of blocks", nblks);
        break;
    case BlkAllocStatus::PARTIAL:
        COUNTER_INCREMENT(m_metrics, num_alloc_partial, 1);
        BLKALLOC_LOG(INFO, "nblks={} allocated={} partial allocation", nblks, total_allocated);
        break;
    case BlkAllocStatus::SUCCESS:
        break;
    default:
        BLKALLOC_LOG(ERROR, "Unexpected status", status);
    }

    if ((status == BlkAllocStatus::SUCCESS) || (status == BlkAllocStatus::PARTIAL)) {
        incr_alloced_blk_count(total_allocated);
#ifndef NDEBUG
        alloc_sanity_check(total_allocated, hints, out_blkids);
#endif
    }

    return status;
}

void VarsizeBlkAllocator::free(const std::vector< BlkId >& blk_ids) {
    for (const auto& blk_id : blk_ids) {
        free(blk_id);
    }
}

void VarsizeBlkAllocator::free(const BlkId& b) {
    if (!m_inited) {
        BLKALLOC_LOG(DEBUG, "Free not required for blk num = {}", b.get_blk_num());
        return;
    }

    static thread_local std::vector< blk_cache_entry > excess_blks;
    excess_blks.clear();

    [[maybe_unused]] const blk_count_t num_zombied{
        m_fb_cache->try_free_blks(blkid_to_blk_cache_entry(b, 2), excess_blks)};
    for (const auto& e : excess_blks) {
        BLKALLOC_LOG(TRACE, "Freeing in bitmap of entry={} - excess of free_blks size={}", e.to_string(),
                     excess_blks.size());
        free_on_bitmap(blk_cache_entry_to_blkid(e));
    }

    decr_alloced_blk_count(b.get_nblks());
    BLKALLOC_LOG(TRACE, "Freed blk_num={}", blkid_to_blk_cache_entry(b).to_string());
}

blk_cap_t VarsizeBlkAllocator::get_available_blks() const { return m_cfg.get_total_blks() - get_used_blks(); }
blk_cap_t VarsizeBlkAllocator::get_used_blks() const { return get_alloced_blk_count(); }

void VarsizeBlkAllocator::free_on_bitmap(const BlkId& b) {
    BlkAllocPortion* const portion{blknum_to_portion(b.get_blk_num())};
    {
        const auto start_blk_id{portion->get_portion_num() * m_cfg.get_blks_per_portion()};
        const auto end_blk_id{start_blk_id + m_cfg.get_blks_per_portion() - 1};
        auto lock{portion->portion_auto_lock()};
        HS_DEBUG_ASSERT_LE(start_blk_id, b.get_blk_num(), "Expected start bit to be greater than portion start bit");
        HS_DEBUG_ASSERT_GE(end_blk_id, (b.get_blk_num() + b.get_nblks() - 1),
                           "Expected end bit to be smaller than portion end bit");
        BLKALLOC_ASSERT(RELEASE, m_cache_bm->is_bits_set(b.get_blk_num(), b.get_nblks()), "Expected bits to be set");
        m_cache_bm->reset_bits(b.get_blk_num(), b.get_nblks());
        portion->increase_available_blocks(b.get_nblks());
    }
    BLKALLOC_LOG(DEBUG, "Freeing directly to portion={} blkid={} set_bits_count={}",
                 blknum_to_portion_num(b.get_blk_num()), b.to_string(), get_alloced_blk_count());
}

#ifndef NDEBUG
bool VarsizeBlkAllocator::is_set_on_bitmap(const BlkId& b) const {
    const BlkAllocPortion* const portion{blknum_to_portion_const(b.get_blk_num())};
    {
        // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache bm.
        auto lock{portion->portion_auto_lock()};
        return m_cache_bm->is_bits_set(b.get_blk_num(), b.get_nblks());
    }
}

void VarsizeBlkAllocator::alloc_sanity_check(const blk_count_t nblks, const blk_alloc_hints& hints,
                                             const std::vector< BlkId >& out_blkids) const {
    blk_count_t alloced_nblks{0};
    for (const auto& b : out_blkids) {
        const BlkAllocPortion* const portion{blknum_to_portion_const(b.get_blk_num())};
        auto lock{portion->portion_auto_lock()};

        BLKALLOC_ASSERT(DEBUG, m_cache_bm->is_bits_set(b.get_blk_num(), b.get_nblks()),
                        "Expected blkid={} to be already set in cache bitmap", b.to_string());
        if (get_disk_bm_const()) {
            BLKALLOC_ASSERT(DEBUG, !is_blk_alloced_on_disk(b), "Expected blkid={} to be already free in disk bitmap",
                            b.to_string());
        }
        alloced_nblks += b.get_nblks();
    }
    BLKALLOC_ASSERT(DEBUG, (nblks == alloced_nblks), "Requested blks={} alloced_blks={} num_pieces={}", nblks,
                    alloced_nblks, out_blkids.size());
    BLKALLOC_ASSERT(DEBUG, (!hints.is_contiguous || (out_blkids.size() == 1)),
                    "Multiple blkids allocated for contiguous request");
}
#endif

/**
 * @brief Request more blocks to be filled into cache from optionally a specified segment. This method can be run on
 * any thread and concurrently.
 *
 * @param seg [OPTIONAL] If seg is nullptr, then it picks the 1st segment to allocate from.
 * @param fill_entire_cache Should entire blk cache be filled or we need to fill upto the limit requested
 */
void VarsizeBlkAllocator::request_more_blks(BlkAllocSegment* const seg, const bool fill_entire_cache) {
    bool notify{false};
    {
        std::unique_lock< std::mutex > lk(m_mutex);
        if (m_state == BlkAllocatorState::WAITING) {
            prepare_sweep(seg, fill_entire_cache);
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

void VarsizeBlkAllocator::request_more_blks_wait(BlkAllocSegment* const seg, const blk_count_t wait_for_blks_count) {
    request_more_blks(seg, false);

    {
        std::unique_lock< std::mutex > lk(m_mutex);
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
}

BlkAllocStatus VarsizeBlkAllocator::alloc_blks_direct(const blk_count_t nblks, const blk_alloc_hints& hints,
                                                      std::vector< BlkId >& out_blkids, blk_count_t& num_allocated) {
    // Search all segments starting with some random portion num within each segment
    static thread_local std::random_device rd{};
    static thread_local std::default_random_engine re{rd()};
    const blk_num_t start_portion_num{m_rand_portion_num_generator(re)};

    auto portion_num{start_portion_num};
    const blk_count_t min_blks{hints.is_contiguous ? nblks : std::min< blk_count_t >(nblks, hints.multiplier)};
    blk_count_t nblks_remain{nblks};
    do {
        BlkAllocPortion& portion{*(get_blk_portion(portion_num))};
        auto cur_blk_id{portion_num * m_cfg.get_blks_per_portion()};
        const auto end_blk_id{cur_blk_id + m_cfg.get_blks_per_portion() - 1};
        {
            auto lock{portion.portion_auto_lock()};
            while (nblks_remain && (cur_blk_id <= end_blk_id) && (portion.get_available_blocks() > 0)) {
                // Get next reset bits and insert to cache and then reset those bits
                const auto b{m_cache_bm->get_next_contiguous_n_reset_bits(
                    cur_blk_id, end_blk_id, std::min(min_blks, nblks_remain), nblks_remain)};
                if (b.nbits == 0) { break; }
                HS_DEBUG_ASSERT_GE(end_blk_id, b.start_bit, "Expected start bit to be smaller than end bit");
                HS_DEBUG_ASSERT_LE(b.nbits, nblks_remain);
                HS_DEBUG_ASSERT_GE(b.nbits, std::min(min_blks, nblks_remain));
                HS_DEBUG_ASSERT_GE(end_blk_id, (b.start_bit + b.nbits - 1),
                                   "Expected end bit to be smaller than portion end bit");

                nblks_remain -= b.nbits;
                out_blkids.emplace_back(b.start_bit, b.nbits, m_chunk_id);

                BLKALLOC_LOG(DEBUG, "Allocated directly from portion={} nnblks={} Blk_num={} nblks={} set_bit_count={}",
                             portion_num, nblks, b.start_bit, b.nbits, get_alloced_blk_count());

                // Set the bitmap indicating the blocks are allocated
                m_cache_bm->set_bits(b.start_bit, b.nbits);
                if (portion.decrease_available_blocks(b.nbits) == 0) break;
                cur_blk_id = b.start_bit + b.nbits;
            }
        }
        if (++portion_num == m_cfg.get_total_portions()) { portion_num = 0; }
        BLKALLOC_LOG(TRACE, "alloc direct unable to find in prev portion, searching in portion={}, start_portion={}",
                     portion_num, start_portion_num);
    } while (nblks_remain && (portion_num != start_portion_num) && !hints.is_contiguous);

    COUNTER_INCREMENT(m_metrics, num_blks_alloc_direct, 1);
    num_allocated = nblks - nblks_remain;
    if (nblks_remain) {
        if (nblks_remain == nblks) {
            // allocated no blocks. NOTE: if contiguous we may or may not be full. Don't really know without
            // searching for a single free block
            return hints.is_contiguous ? BlkAllocStatus::FAILED : BlkAllocStatus::SPACE_FULL;
        } else {
            // allocated some blocks
            return BlkAllocStatus::PARTIAL;
        }
    }
    return BlkAllocStatus::SUCCESS;
}

/* This method assumes that mutex to protect state is already taken. */
void VarsizeBlkAllocator::prepare_sweep(BlkAllocSegment* const seg, const bool fill_entire_cache) {
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

blk_cache_entry VarsizeBlkAllocator::blkid_to_blk_cache_entry(const BlkId& bid, const blk_temp_t preferred_level) {
    return blk_cache_entry{bid.get_blk_num(), bid.get_nblks(), preferred_level};
}

std::string VarsizeBlkAllocator::to_string() const {
    return fmt::format("BlkAllocator={} state={} total_blks={} cached_blks={} alloced_blks={}", m_cfg.get_name(),
                       m_state, m_cfg.get_total_blks(), m_fb_cache->total_free_blks(), get_alloced_blk_count());
}

nlohmann::json VarsizeBlkAllocator::get_metrics_in_json() { return m_metrics.get_result_in_json(true); }
} // namespace homestore
