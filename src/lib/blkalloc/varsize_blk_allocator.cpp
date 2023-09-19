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
#include <iostream>
#include <iterator>
#include <random>
#include <thread>

#include <fmt/format.h>
#include <sisl/logging/logging.h>
#include <sisl/utility/thread_factory.hpp>
#include <sisl/utility/thread_buffer.hpp>
#include <iomgr/iomgr_flip.hpp>

#include "blk_cache_queue.h"

#include "varsize_blk_allocator.h"

SISL_LOGGING_DECL(blkalloc)

template <>
struct fmt::formatter< std::thread::id > {
    constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator { return ctx.begin(); }
    auto format(std::thread::id const& i, format_context& ctx) const -> format_context::iterator {
        return fmt::format_to(ctx.out(), "{}", std::hash< std::thread::id >{}(i));
    }
};

namespace homestore {

// initialize static variables
std::atomic< size_t > VarsizeBlkAllocator::s_sweeper_thread_references{0};
std::vector< std::thread > VarsizeBlkAllocator::s_sweeper_threads;
std::mutex VarsizeBlkAllocator::s_sweeper_mutex;
std::mutex VarsizeBlkAllocator::s_sweeper_create_delete_mutex;
std::atomic< bool > VarsizeBlkAllocator::s_sweeper_threads_stop{false};
std::condition_variable VarsizeBlkAllocator::s_sweeper_cv;
std::queue< VarsizeBlkAllocator* > VarsizeBlkAllocator::s_sweeper_queue;
std::unordered_set< VarsizeBlkAllocator* > VarsizeBlkAllocator::s_block_allocators;

VarsizeBlkAllocator::VarsizeBlkAllocator(VarsizeBlkAllocConfig const& cfg, bool init, chunk_num_t chunk_id) :
        BlkAllocator{cfg, chunk_id},
        m_state{BlkAllocatorState::INIT},
        m_cfg{cfg},
        m_rand_portion_num_generator{0, s_cast< blk_count_t >(get_num_portions() - 1)},
        m_metrics{get_name().c_str()} {
    BLKALLOC_LOG(INFO, "Creating VarsizeBlkAllocator with config: {}", cfg.to_string());

    HS_REL_ASSERT_LT(get_num_portions(), INVALID_PORTION_NUM);

    // TODO: Raise exception when blk_size > page_size or total blks is less than some number etc...
    m_cache_bm = std::make_unique< sisl::Bitset >(get_total_blks(), chunk_id, get_align_size());

    // NOTE: Number of blocks must be modulo word size so locks do not fall on same word
    HS_REL_ASSERT_EQ(get_blks_per_portion() % m_cache_bm->word_size(), 0,
                     "Blocks per portion must be multiple of bitmap word size.")

    // Create segments with as many blk groups as configured.
    m_blks_per_seg = get_total_blks() / cfg.m_nsegments;
    m_segments.reserve(cfg.m_nsegments);
    m_portions_per_seg = get_num_portions() / cfg.m_nsegments;

    for (seg_num_t i{0U}; i < m_cfg.m_nsegments; ++i) {
        const std::string seg_name = fmt::format("{}_seg_{}", get_name(), i);
        auto seg = std::make_unique< BlkAllocSegment >(i, m_portions_per_seg, seg_name);
        m_segments.push_back(std::move(seg));
    }

    // Create free blk Cache of type Queue
    if (m_cfg.m_use_slabs) {
        m_fb_cache = std::make_unique< FreeBlkCacheQueue >(cfg.get_slab_config(), &m_metrics);
        LOGINFO("m_fb_cache total free blks: {}", m_fb_cache->total_free_blks());
    }

    // Start a thread which will do sweeping job of free segments
    if (init) { inited(); }
}

VarsizeBlkAllocator::~VarsizeBlkAllocator() {
    // remove from queue of
    if (m_cfg.m_use_slabs) {
        bool in_sweep_list{false};
        {
            std::unique_lock< std::mutex > lock{s_sweeper_mutex};
            // remove this block allocator from list
            if (s_block_allocators.erase(this) == 1) { in_sweep_list = true; }
        }

        if (in_sweep_list) {
            {
                // mark state as exiting
                std::unique_lock< std::mutex > lock{m_mutex};
                if (m_state != BlkAllocatorState::EXITING) {
                    BLKALLOC_LOG(DEBUG, "Allocator state change from {} to {}", m_state, BlkAllocatorState::EXITING);
                    m_state = BlkAllocatorState::EXITING;
                }
            }

            {
                // signal exiting state
                std::unique_lock< std::mutex > lock{s_sweeper_mutex};

                // emplace this block allocator on the sweeper queue
                s_sweeper_queue.emplace(this);
                s_sweeper_cv.notify_one();
            }

            {
                // wait for done state
                std::unique_lock< std::mutex > lock{m_mutex};
                BLKALLOC_LOG(DEBUG, "Allocator waiting for {} state", BlkAllocatorState::DONE);
                m_cv.wait(lock, [this]() { return m_state == BlkAllocatorState::DONE; });
            }

            {
                std::unique_lock< std::mutex > create_delete_lock{s_sweeper_create_delete_mutex};
                assert(s_sweeper_thread_references > 0);
                if (--s_sweeper_thread_references == 0) {
                    {
                        std::unique_lock< std::mutex > lock{s_sweeper_mutex};
                        assert(s_sweeper_queue.empty());
                        assert(s_block_allocators.empty());
                    }
                    s_sweeper_threads_stop = true;
                    s_sweeper_cv.notify_all();
                    for (auto& sweeper_thread : s_sweeper_threads) {
                        BLKALLOC_LOG(INFO, "Destroying new blk sweep thread, thread num = {}", sweeper_thread.get_id());
                        if (sweeper_thread.joinable()) sweeper_thread.join();
                    }
                    s_sweeper_threads.clear();
                }
            }
        }
    }
}

void VarsizeBlkAllocator::sweeper_thread(size_t thread_num) {
    const size_t num_sweeper_threads = HS_DYNAMIC_CONFIG(blkallocator.num_slab_sweeper_threads);

    while (!s_sweeper_threads_stop) {
        VarsizeBlkAllocator* allocator_ptr{nullptr};
        {
            std::unique_lock< std::mutex > lock{s_sweeper_mutex};
            auto const woken{s_sweeper_cv.wait_for(
                lock, std::chrono::milliseconds(HS_DYNAMIC_CONFIG(blkallocator.free_blk_cache_refill_frequency_ms)),
                [&]() { return !s_sweeper_queue.empty() || s_sweeper_threads_stop; })};
            if (s_sweeper_threads_stop) continue;
            if (woken) {
                // pull allocator to process
                allocator_ptr = s_sweeper_queue.front();
                s_sweeper_queue.pop();
            }
        }

        if (allocator_ptr) {
            bool requeue{false};
            {
                std::unique_lock< std::mutex > alloc_lock{allocator_ptr->m_mutex};
                switch (allocator_ptr->m_state) {
                case BlkAllocatorState::INIT:
                    // fill the cache
                    allocator_ptr->request_more_blks(nullptr, true /* fill_entire_cache */);
                    allocator_ptr->m_state = BlkAllocatorState::WAITING;
                    break;
                case BlkAllocatorState::EXITING:
                    allocator_ptr->m_state = BlkAllocatorState::DONE;
                    allocator_ptr->m_cv.notify_one();
                    break;
                default:
                    // process normally
                    requeue = allocator_ptr->allocator_state_machine();
                    break;
                }
            }

            if (requeue) {
                {
                    std::unique_lock< std::mutex > lock{s_sweeper_mutex};
                    s_sweeper_queue.emplace(allocator_ptr);
                }
                s_sweeper_cv.notify_one();
            }
        } else {
            {
                // timed out, so process all block allocators
                std::unique_lock< std::mutex > lock{s_sweeper_mutex};
                size_t pos = thread_num;
                for (auto itr{std::cbegin(s_block_allocators)}; itr != std::cend(s_block_allocators); ++itr, ++pos) {
                    if ((pos % num_sweeper_threads) == 0) { s_sweeper_queue.emplace(*itr); }
                }
            }
            s_sweeper_cv.notify_all();
        }
    }
}

// returns true if state change, and must be called under external lock
bool VarsizeBlkAllocator::allocator_state_machine() {
    bool active_state{false};

    switch (m_state) {
    case BlkAllocatorState::WAITING:
        BLKALLOC_LOG(TRACE, "Allocator is going to Waiting State");
        active_state = prepare_sweep(nullptr, false /* fill_entire_cache */);
        break;
    case BlkAllocatorState::SWEEP_SCHEDULED:
        BLKALLOC_LOG(TRACE, "Allocator state change from {} to {}", m_state, BlkAllocatorState::SWEEPING);
        m_state = BlkAllocatorState::SWEEPING;
        BLKALLOC_LOG(DEBUG, "Starting to sweep based on requirement {}", m_cur_fill_session->to_string());
        fill_cache(m_sweep_segment, *m_cur_fill_session);
        BLKALLOC_LOG(TRACE, "Allocator is going to Waiting State");
        m_state = BlkAllocatorState::WAITING;
        m_cv.notify_all();
        BLKALLOC_LOG(DEBUG, "Sweep session completed with fill details {}", m_cur_fill_session->to_string());
        break;
    default:
        break;
    }

    return active_state;
}

void VarsizeBlkAllocator::inited() {
    m_cache_bm->copy(*(get_disk_bm_const()));
    BlkAllocator::inited();

    BLKALLOC_LOG(INFO, "VarSizeBlkAllocator initialized loading bitmap of size={} used blks={} from persistent storage",
                 in_bytes(m_cache_bm->size()), get_alloced_blk_count());

    // if use slabs then add to sweeper threads queue
    if (m_cfg.m_use_slabs) {
        {
            std::unique_lock< std::mutex > create_delete_lock{s_sweeper_create_delete_mutex};
            if (s_sweeper_thread_references++ == 0) {
                s_sweeper_threads_stop = false;
                {
                    for (size_t thread_num{0}; thread_num < HS_DYNAMIC_CONFIG(blkallocator.num_slab_sweeper_threads);
                         ++thread_num) {
                        s_sweeper_threads.emplace_back(sisl::named_thread("blkalloc_sweep" + std::to_string(thread_num),
                                                                          VarsizeBlkAllocator::sweeper_thread,
                                                                          thread_num));
                        BLKALLOC_LOG(INFO, "Starting new blk sweep thread, thread num = {}",
                                     s_sweeper_threads.back().get_id());
                    }
                }
            }
        }

        {
            std::unique_lock< std::mutex > lock{s_sweeper_mutex};
            // add this to the list of allocators to sweep
            s_block_allocators.emplace(this);

            // emplace this block allocator on the sweeper queue
            s_sweeper_queue.emplace(this);
        }
        s_sweeper_cv.notify_one();
    }
}

// This runs on per region thread and is at present single threaded.
/* we are going through the segments which has maximum free blks so that we can ensure that all slabs are populated.
 * We might need to find a efficient way of doing it later. It stop processing the segment when any slab greater
 * then slab_indx is full.
 */
void VarsizeBlkAllocator::fill_cache(BlkAllocSegment* in_seg, blk_cache_fill_session& fill_session) {
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("varsize_blkalloc_bypass_cache")) {
        m_fb_cache->close_cache_fill_session(fill_session);
        return;
    }
#endif

    // Pick a segment if scan if not provided
    BlkAllocSegment* seg = in_seg;
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

    const blk_num_t start_portion_num = seg->get_seg_num() * m_portions_per_seg + seg->get_clock_hand();
    auto portion_num = start_portion_num;

    do {
        BLKALLOC_LOG_ASSERT_CMP(portion_num, <, get_num_portions());
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

void VarsizeBlkAllocator::fill_cache_in_portion(blk_num_t portion_num, blk_cache_fill_session& fill_session) {
    auto cur_blk_id = portion_num * get_blks_per_portion();
    auto const end_blk_id = cur_blk_id + get_blks_per_portion() - 1;

    blk_cache_fill_req fill_req;
    fill_req.preferred_level = 1;

    BLKALLOC_LOG(TRACE, "Allocator sweep session={} for portion_num={} sweep blk_id_range=[{}-{}]",
                 fill_session.session_id, portion_num, cur_blk_id, end_blk_id);

    BlkAllocPortion& portion = get_blk_portion(portion_num);
    {
        auto lock{portion.portion_auto_lock()};
        while (!fill_session.overall_refill_done && (cur_blk_id <= end_blk_id)) {
            // Get next reset bits and insert to cache and then reset those bits
            auto const b{
                m_cache_bm->get_next_contiguous_n_reset_bits(cur_blk_id, end_blk_id, 1, end_blk_id - cur_blk_id + 1)};

            // If there are no free blocks within the assigned portion
            if (b.nbits == 0) { break; }

            HS_DBG_ASSERT_GE(end_blk_id, b.start_bit, "Expected start bit to be smaller than portion end bit");
            HS_DBG_ASSERT_GE(end_blk_id, (b.start_bit + b.nbits - 1),
                             "Expected end bit to be smaller than portion end bit");
            HISTOGRAM_OBSERVE(m_metrics, frag_pct_distribution, 100 / (static_cast< double >(b.nbits)));

            // Fill the blk cache and keep accounting of number of blks added
            fill_req.start_blk_num = b.start_bit;
            fill_req.nblks = b.nbits;
            fill_req.preferred_level = portion.temperature();
            auto const nblks_added = m_fb_cache->try_fill_cache(fill_req, fill_session);

            HS_DBG_ASSERT_LE(nblks_added, b.nbits);

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

BlkAllocStatus VarsizeBlkAllocator::alloc_contiguous(BlkId& out_blkid) {
    return alloc_contiguous(1, blk_alloc_hints{}, out_blkid);
}

BlkAllocStatus VarsizeBlkAllocator::alloc_contiguous(blk_count_t nblks, blk_alloc_hints const& hints,
                                                     BlkId& out_blkid) {
    MultiBlkId mbid;
    auto const status = alloc(nblks, hints, mbid);
    if (status == BlkAllocStatus::SUCCESS) { out_blkid = mbid; }
    return status;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) {
    bool use_slabs = m_cfg.m_use_slabs;

#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("varsize_blkalloc_no_blks", nblks)) { return BlkAllocStatus::SPACE_FULL; }
    if (iomgr_flip::instance()->test_flip("varsize_blkalloc_bypass_cache")) { use_slabs = false; }
#endif

    if (!hints.is_contiguous && !out_blkid.is_multi()) {
        HS_DBG_ASSERT(false, "Invalid Input: Non contiguous allocation needs MultiBlkId to store");
        return BlkAllocStatus::INVALID_INPUT;
    }

    MultiBlkId tmp_blkid;
    MultiBlkId& out_mbid = out_blkid.is_multi() ? r_cast< MultiBlkId& >(out_blkid) : tmp_blkid;
    BlkAllocStatus status;
    blk_count_t num_allocated{0};
    blk_count_t nblks_remain;

    if (use_slabs && (nblks <= m_cfg.highest_slab_blks_count())) {
        num_allocated = alloc_blks_slab(nblks, hints, out_mbid);
        if (num_allocated >= nblks) {
            status = BlkAllocStatus::SUCCESS;
            goto out;
        }
        // Fall through to alloc_blks_direct
    }

    nblks_remain = nblks - num_allocated;
    num_allocated += alloc_blks_direct(nblks_remain, hints, out_mbid);
    if (num_allocated == nblks) {
        status = BlkAllocStatus::SUCCESS;
        BLKALLOC_LOG(TRACE, "Alloced blks [{}] directly", out_mbid.to_string());
    } else if ((num_allocated != 0) && hints.partial_alloc_ok) {
        status = BlkAllocStatus::PARTIAL;
    } else {
        free_blks_direct(out_mbid);
        status = hints.is_contiguous ? BlkAllocStatus::FAILED : BlkAllocStatus::SPACE_FULL;
    }

out:
    if ((status == BlkAllocStatus::SUCCESS) || (status == BlkAllocStatus::PARTIAL)) {
        incr_alloced_blk_count(num_allocated);

        // update real time bitmap
        if (realtime_bm_on()) { alloc_on_realtime(out_mbid); }

#ifdef _PRERELEASE
        alloc_sanity_check(num_allocated, hints, out_mbid);
#endif
    }

    if (!out_blkid.is_multi()) { out_blkid = out_mbid.to_single_blkid(); }
    return status;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(blk_count_t nblks, blk_alloc_hints const& hints,
                                          std::vector< BlkId >& out_blkids) {
    // Regular alloc blks will allocate in MultiBlkId, but there is an upper limit on how many it can accomodate in a
    // single MultiBlkId, if caller is ok to generate multiple MultiBlkids, this method is called.
    auto h = hints;
    h.partial_alloc_ok = true;
    blk_count_t nblks_remain = nblks;
    BlkAllocStatus status;

    do {
        MultiBlkId mbid;
        status = alloc(nblks_remain, h, mbid);
        if ((status != BlkAllocStatus::SUCCESS) && (status != BlkAllocStatus::PARTIAL)) { break; }

        blk_count_t nblks_this_iter{0};
        auto it = mbid.iterate();
        while (auto const bid = it.next()) {
            out_blkids.push_back(*bid);
            nblks_this_iter += bid->blk_count();
        }

        if (status == BlkAllocStatus::SUCCESS) {
            HS_DBG_ASSERT_GE(nblks_this_iter, nblks_remain,
                             "alloc_blks returned success, but return id doesn't have reqd blks");
            break;
        }

        if (nblks_this_iter >= nblks_remain) {
            HS_DBG_ASSERT(false, "alloc_blks returns partial, while it has fully allocated reqd blks");
            status = BlkAllocStatus::SUCCESS;
            break;
        }
        nblks_remain -= nblks_this_iter;
    } while (nblks_remain);

    return status;
}

blk_count_t VarsizeBlkAllocator::alloc_blks_slab(blk_count_t nblks, blk_alloc_hints const& hints,
                                                 MultiBlkId& out_blkid) {
    blk_count_t num_allocated{0};

    // Allocate from blk cache
    static thread_local blk_cache_alloc_resp s_alloc_resp;
    const blk_cache_alloc_req alloc_req{nblks, hints.desired_temp, hints.is_contiguous,
                                        FreeBlkCache::find_slab(hints.min_blks_per_piece),
                                        s_cast< slab_idx_t >(m_cfg.get_slab_cnt() - 1)};
    COUNTER_INCREMENT(m_metrics, num_alloc, 1);

    auto free_excess_blocks = [this]() {
        // put excess blocks back on bitmap
        for (auto const& e : s_alloc_resp.excess_blks) {
            BLKALLOC_LOG(DEBUG, "Freeing in bitmap of entry={} - excess of alloc_blks size={}", e.to_string(),
                         s_alloc_resp.excess_blks.size());
            free_blks_direct(MultiBlkId{blk_cache_entry_to_blkid(e)});
        }
    };

    auto discard_current_allocation = [this, &free_excess_blocks]() {
        if (!s_alloc_resp.out_blks.empty()) {
            s_alloc_resp.nblks_zombied = m_fb_cache->try_free_blks(s_alloc_resp.out_blks, s_alloc_resp.excess_blks);
        }
        free_excess_blocks();
        s_alloc_resp.reset();
    };

    s_alloc_resp.reset();
    // retries must be at least two to allow slab refill logic to run
    const uint32_t max_retries = std::max< uint32_t >(HS_DYNAMIC_CONFIG(blkallocator.max_varsize_blk_alloc_attempt), 2);
    for (uint32_t retry{0}; ((retry < max_retries) && out_blkid.has_room()); ++retry) {
        auto status = m_fb_cache->try_alloc_blks(alloc_req, s_alloc_resp);

        // If the blk allocation is only partially completed, then we are ok in proceeding further for cases where
        // caller does not want a contiguous allocation. In that case, return these partial results and then caller will
        // use direct allocation to allocate remaining blks. In case where caller is also ok with partial allocation,
        // then it doesn't matter if request is for contiguous allocation or not, we can return the partial results.
        if ((status == BlkAllocStatus::SUCCESS) ||
            ((status == BlkAllocStatus::PARTIAL) && (hints.partial_alloc_ok || !hints.is_contiguous))) {
            // If the cache has depleted a bit, kick of sweep thread to fill the cache.
            if (s_alloc_resp.need_refill) { request_more_blks(nullptr, false /* fill_entire_cache */); }
            BLKALLOC_LOG(TRACE, "Alloced first blk_num={}", s_alloc_resp.out_blks[0].to_string());

            // Convert the response block cache entries to blkids
            for (size_t piece{0}; piece < s_alloc_resp.out_blks.size(); ++piece) {
                auto& e = s_alloc_resp.out_blks[piece];
                if (out_blkid.has_room()) {
                    out_blkid.add(e.get_blk_num(), e.blk_count(), m_chunk_id);
                    num_allocated += e.blk_count();
                } else {
                    // We are not able to put all of the response to out_blkid, because it doesn't have room,
                    // If caller is ok with partial allocation, we can free remaining entry and send partial result.
                    // If caller is not ok with partial allocation, we should discard entire allocation and retry
                    if (hints.partial_alloc_ok) {
                        s_alloc_resp.excess_blks.insert(s_alloc_resp.excess_blks.end(),
                                                        s_alloc_resp.out_blks.begin() + piece,
                                                        s_alloc_resp.out_blks.end());
                    } else {
                        num_allocated = 0;
                        out_blkid = MultiBlkId{};
                        status = BlkAllocStatus::TOO_MANY_PIECES;
                    }
                    break;
                }
            }

            if (status != BlkAllocStatus::TOO_MANY_PIECES) { break; }
        }

        discard_current_allocation();
        if ((retry + 1) < max_retries) {
            COUNTER_INCREMENT(m_metrics, num_retries, 1);
            auto const min_nblks = std::max< blk_count_t >(m_cfg.highest_slab_blks_count() * 2, nblks);
            BLKALLOC_LOG(DEBUG,
                         "Failed to allocate {} blks from blk cache, requesting refill at least {} blks "
                         "and retry={}",
                         nblks, min_nblks, retry);
            request_more_blks_wait(nullptr /* seg */, min_nblks);
        }
    }

    free_excess_blocks();

    return num_allocated;
}

blk_count_t VarsizeBlkAllocator::alloc_blks_direct(blk_count_t nblks, blk_alloc_hints const& hints,
                                                   MultiBlkId& out_blkid) {
    // Search all segments starting with some random portion num within each segment
    static thread_local std::random_device rd{};
    static thread_local std::default_random_engine re{rd()};

    if (m_start_portion_num == INVALID_PORTION_NUM) { m_start_portion_num = m_rand_portion_num_generator(re); }

    auto portion_num = m_start_portion_num;
    auto const max_pieces = hints.is_contiguous ? 1u : MultiBlkId::max_pieces;

    blk_count_t const min_blks = hints.is_contiguous ? nblks : std::min< blk_count_t >(nblks, hints.min_blks_per_piece);
    blk_count_t nblks_remain = nblks;
    do {
        BlkAllocPortion& portion = get_blk_portion(portion_num);
        auto cur_blk_id = portion_num * get_blks_per_portion();
        auto const end_blk_id = cur_blk_id + get_blks_per_portion() - 1;
        {
            auto lock{portion.portion_auto_lock()};
            while (nblks_remain && (cur_blk_id <= end_blk_id) && portion.get_available_blocks() &&
                   out_blkid.has_room()) {
                // Get next reset bits and insert to cache and then reset those bits
                auto const b = m_cache_bm->get_next_contiguous_n_reset_bits(
                    cur_blk_id, end_blk_id, std::min(min_blks, nblks_remain), nblks_remain);
                if (b.nbits == 0) { break; }
                HS_DBG_ASSERT_GE(end_blk_id, b.start_bit, "Expected start bit to be smaller than end bit");
                HS_DBG_ASSERT_LE(b.nbits, nblks_remain);
                HS_DBG_ASSERT_GE(b.nbits, std::min(min_blks, nblks_remain));
                HS_DBG_ASSERT_GE(end_blk_id, (b.start_bit + b.nbits - 1),
                                 "Expected end bit to be smaller than portion end bit");

                nblks_remain -= b.nbits;
                out_blkid.add(b.start_bit, b.nbits, m_chunk_id);

                BLKALLOC_LOG(DEBUG, "Allocated directly from portion={} nnblks={} Blk_num={} nblks={} set_bit_count={}",
                             portion_num, nblks, b.start_bit, b.nbits, get_alloced_blk_count());

                // Set the bitmap indicating the blocks are allocated
                m_cache_bm->set_bits(b.start_bit, b.nbits);
                if (portion.decrease_available_blocks(b.nbits) == 0) break;
                cur_blk_id = b.start_bit + b.nbits;
            }
        }
        if (++portion_num == get_num_portions()) { portion_num = 0; }
        BLKALLOC_LOG(TRACE, "alloc direct unable to find in prev portion, searching in portion={}, start_portion={}",
                     portion_num, m_start_portion_num);
    } while (nblks_remain && (portion_num != m_start_portion_num) && !hints.is_contiguous && out_blkid.has_room());

    // save which portion we were at for next allocation;
    m_start_portion_num = portion_num;

    COUNTER_INCREMENT(m_metrics, num_blks_alloc_direct, 1);
    return (nblks - nblks_remain);
}

void VarsizeBlkAllocator::free(BlkId const& bid) {
    if (!m_inited) {
        BLKALLOC_LOG(DEBUG, "Free not required for blk num = {}", bid.blk_num());
        return;
    }

    blk_count_t n_freed = (m_cfg.m_use_slabs && (bid.blk_count() <= m_cfg.highest_slab_blks_count()))
        ? free_blks_slab(r_cast< MultiBlkId const& >(bid))
        : free_blks_direct(r_cast< MultiBlkId const& >(bid));
    decr_alloced_blk_count(n_freed);
    BLKALLOC_LOG(TRACE, "Freed blk_num={}", bid.to_string());
}

blk_count_t VarsizeBlkAllocator::free_blks_slab(MultiBlkId const& bid) {
    static thread_local std::vector< blk_cache_entry > excess_blks;
    excess_blks.clear();

    auto const do_free = [this](BlkId const& b) {
        m_fb_cache->try_free_blks(blkid_to_blk_cache_entry(b, 2), excess_blks);
        return b.blk_count();
    };

    blk_count_t n_freed{0};
    if (bid.is_multi()) {
        auto it = bid.iterate();
        while (auto const b = it.next()) {
            n_freed += do_free(*b);
        }
    } else {
        n_freed += do_free(bid);
    }

    for (auto const& e : excess_blks) {
        BLKALLOC_LOG(TRACE, "Freeing in bitmap of entry={} - excess of free_blks size={}", e.to_string(),
                     excess_blks.size());
        free_blks_direct(MultiBlkId{blk_cache_entry_to_blkid(e)});
    }
    return n_freed;
}

blk_count_t VarsizeBlkAllocator::free_blks_direct(MultiBlkId const& bid) {
    auto const do_free = [this](BlkId const& b) {
        BlkAllocPortion& portion = blknum_to_portion(b.blk_num());
        {
            auto const start_blk_id = portion.get_portion_num() * get_blks_per_portion();
            auto const end_blk_id = start_blk_id + get_blks_per_portion() - 1;
            auto lock{portion.portion_auto_lock()};
            HS_DBG_ASSERT_LE(start_blk_id, b.blk_num(), "Expected start bit to be greater than portion start bit");
            HS_DBG_ASSERT_GE(end_blk_id, (b.blk_num() + b.blk_count() - 1),
                             "Expected end bit to be smaller than portion end bit");
            BLKALLOC_REL_ASSERT(m_cache_bm->is_bits_set(b.blk_num(), b.blk_count()), "Expected bits to be set");
            m_cache_bm->reset_bits(b.blk_num(), b.blk_count());
            portion.increase_available_blocks(b.blk_count());
        }
        BLKALLOC_LOG(TRACE, "Freeing directly to portion={} blkid={} set_bits_count={}",
                     blknum_to_portion_num(b.blk_num()), b.to_string(), get_alloced_blk_count());
        return b.blk_count();
    };

    blk_count_t n_freed{0};
    if (bid.is_multi()) {
        auto it = bid.iterate();
        while (auto const b = it.next()) {
            n_freed += do_free(*b);
        }
    } else {
        n_freed += do_free(bid);
    }
    return n_freed;
}

bool VarsizeBlkAllocator::is_blk_alloced(BlkId const& b, bool use_lock) const {
    if (!m_inited) { return true; }
    auto bits_set{[this, &b]() {
        // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache
        // bm.
        if (!m_cache_bm->is_bits_set(b.blk_num(), b.blk_count())) {
            BLKALLOC_REL_ASSERT(0, "Expected bits to set");
            return false;
        }
        return true;
    }};
    if (use_lock) {
        BlkAllocPortion const& portion = blknum_to_portion_const(b.blk_num());
        auto lock{portion.portion_auto_lock()};
        if (!bits_set()) return false;
    } else {
        if (!bits_set()) return false;
    }
    return true;
}

blk_num_t VarsizeBlkAllocator::available_blks() const { return get_total_blks() - get_used_blks(); }
blk_num_t VarsizeBlkAllocator::get_used_blks() const { return get_alloced_blk_count(); }

bool VarsizeBlkAllocator::is_blk_alloced(BlkId const& bid, bool use_lock) const {
    if (!m_inited) { return true; }

    auto check_bits_set = [this](BlkId const& b, bool use_lock) {
        if (use_lock) {
            BlkAllocPortion const& portion = blknum_to_portion_const(b.blk_num());
            auto lock{portion.portion_auto_lock()};
            return m_cache_bm->is_bits_set(b.blk_num(), b.blk_count());
        } else {
            return m_cache_bm->is_bits_set(b.blk_num(), b.blk_count());
        }
    };

    bool ret;
    if (bid.is_multi()) {
        auto& mbid = r_cast< MultiBlkId const& >(bid);
        auto it = mbid.iterate();
        while (auto const b = it.next()) {
            ret = check_bits_set(*b, use_lock);
            if (!ret) { break; }
        }
    } else {
        ret = check_bits_set(bid, use_lock);
    }
    return ret;
}

blk_num_t VarsizeBlkAllocator::available_blks() const { return get_total_blks() - get_used_blks(); }
blk_num_t VarsizeBlkAllocator::get_used_blks() const { return get_alloced_blk_count(); }

#ifdef _PRERELEASE
void VarsizeBlkAllocator::alloc_sanity_check(blk_count_t nblks, blk_alloc_hints const& hints,
                                             MultiBlkId const& out_blkid) const {
    if (HS_DYNAMIC_CONFIG(generic.sanity_check_level)) {
        blk_count_t alloced_nblks{0};
        auto it = out_blkid.iterate();
        while (auto const b = it.next()) {
            BlkAllocPortion const& portion = blknum_to_portion_const(b->blk_num());
            auto lock{portion.portion_auto_lock()};

            BLKALLOC_REL_ASSERT(m_cache_bm->is_bits_set(b->blk_num(), b->blk_count()),
                                "Expected blkid={} to be already set in cache bitmap", b->to_string());
            if (get_disk_bm_const()) {
                BLKALLOC_REL_ASSERT(!is_blk_alloced_on_disk(*b), "Expected blkid={} to be already free in disk bitmap",
                                    b->to_string());
            }
            alloced_nblks += b->blk_count();
        }
        BLKALLOC_REL_ASSERT((nblks == alloced_nblks), "Requested blks={} alloced_blks={} num_pieces={}", nblks,
                            alloced_nblks, out_blkid.num_pieces());
        BLKALLOC_REL_ASSERT((!hints.is_contiguous || (out_blkid.num_pieces() == 1)),
                            "Multiple blkids allocated for contiguous request");
    }
}
#endif

/**
 * @brief Request more blocks to be filled into cache from optionally a specified segment. This method can be run on
 * any thread and concurrently.
 *
 * @param seg [OPTIONAL] If seg is nullptr, then it picks the 1st segment to allocate from.
 * @param fill_entire_cache Should entire blk cache be filled or we need to fill upto the limit requested
 *
 * This function must be called under a lock acquired externally for m_mutex
 */
void VarsizeBlkAllocator::request_more_blks(BlkAllocSegment* seg, bool fill_entire_cache) {
    if (m_state == BlkAllocatorState::WAITING) {
        if (prepare_sweep(seg, fill_entire_cache)) {
            {
                std::unique_lock< std::mutex > lock{s_sweeper_mutex};
                s_sweeper_queue.emplace(this);
            }
            s_sweeper_cv.notify_one();
        }
        m_cv.notify_all();
        BLKALLOC_LOG(DEBUG, "Allocator is requested to refill blk cache and move to {} state", m_state);
    } else {
        BLKALLOC_LOG(TRACE, "Allocator is requested to refill blk cache but it is in {} state, ignoring this request",
                     m_state);
    }
}

void VarsizeBlkAllocator::request_more_blks_wait(BlkAllocSegment* seg, blk_count_t wait_for_blks_count) {
    std::unique_lock< std::mutex > lock{m_mutex};
    request_more_blks(seg, false);

    if ((m_state == BlkAllocatorState::SWEEP_SCHEDULED) || (m_state == BlkAllocatorState::SWEEPING)) {
        // Wait for notification that it is either done sweeping or if it is sweeping it satisfies the requirement
        // to wait for blks
        m_cur_fill_session->urgent_need_atleast(wait_for_blks_count);
        m_cv.wait(lock, [this]() {
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

/* This method assumes that mutex to protect state is already taken. */
bool VarsizeBlkAllocator::prepare_sweep(BlkAllocSegment* seg, bool fill_entire_cache) {
    m_sweep_segment = seg;
    m_cur_fill_session = m_fb_cache->create_cache_fill_session(fill_entire_cache);
    if (!(m_cur_fill_session->slab_requirements.empty())) {
        m_state = BlkAllocatorState::SWEEP_SCHEDULED;
        return true;
    } else {
        BLKALLOC_LOG(TRACE, "no slabs need filling");
        return false;
    }
}

#if 0
blk_num_t VarsizeBlkAllocator::blk_cache_entries_to_blkids(const std::vector< blk_cache_entry >& entries,
                                                           MultiBlkId& out_blkid) {
    uint32_t num_added{0};
    for (auto const& e : entries) {
        if (out_blkid.has_room()) {
            out_blkid.add(e.get_blk_num(), e.blk_count(), m_chunk_id);
            ++num_added;
        } else {
            break;
        }
    }

    return num_added;
}
#endif

BlkId VarsizeBlkAllocator::blk_cache_entry_to_blkid(blk_cache_entry const& e) {
    return BlkId{e.get_blk_num(), e.blk_count(), m_chunk_id};
}

blk_cache_entry VarsizeBlkAllocator::blkid_to_blk_cache_entry(BlkId const& bid, blk_temp_t preferred_level) {
    return blk_cache_entry{bid.blk_num(), bid.blk_count(), preferred_level};
}

std::string VarsizeBlkAllocator::to_string() const {
    return fmt::format("BlkAllocator={} state={} total_blks={} cached_blks={} alloced_blks={}", get_name(), m_state,
                       get_total_blks(), m_fb_cache->total_free_blks(), get_alloced_blk_count());
}

nlohmann::json VarsizeBlkAllocator::get_metrics_in_json() { return m_metrics.get_result_in_json(true); }
} // namespace homestore
