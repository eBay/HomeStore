/*
 * varsize_blk_allocator.cpp
 *
 *  Created on: Jun 17, 2015
 *      Author: Hari Kadayam
 */

#include "varsize_blk_allocator.h"
#include <iostream>
#include <cassert>
#include <thread>
#include <fds/utils.hpp>
#include "engine/homeds/btree/mem_btree.hpp"
#include <sds_logging/logging.h>
#include <utility/thread_factory.hpp>

#ifndef NDEBUG
bool blk_alloc_test = false;
#endif

SDS_LOGGING_DECL(varsize_blk_alloc)

namespace homestore {

VarsizeBlkAllocator::VarsizeBlkAllocator(VarsizeBlkAllocConfig& cfg, bool init, uint32_t id) :
        BlkAllocator(cfg, id),
        m_cfg(cfg),
        m_region_state(BLK_ALLOCATOR_DONE),
        m_temp_groups(cfg.get_total_temp_group()),
        m_cache_n_entries(0),
        m_metrics(cfg.get_name().c_str()) {

    // TODO: Raise exception when blk_size > page_size or total blks is less than some number etc...
    m_cache_bm = new sisl::Bitset(cfg.get_total_blks(), id, HS_STATIC_CONFIG(disk_attr.align_size));

#ifndef NDEBUG
    for (auto i = 0U; i < cfg.get_total_temp_group(); i++) {
        m_temp_groups[i].m_temp_group_id = i;
    }

#endif

    // Initialize the slab counters
    for (auto i = 0U; i < cfg.get_slab_cnt(); i++) {
        atomwrapper< uint32_t > a_i(0);
        m_slab_entries.push_back(a_i);
        BLKALLOC_LOG(INFO, , "Capacity of slab {} = {}", i, m_slab_entries[i]._a.load(std::memory_order_acq_rel));
    }

    // Create segments with as many blk groups as configured.
    uint64_t seg_nblks = cfg.get_total_blks() / cfg.get_total_segments();
    uint64_t portions_per_seg = get_portions_per_segment();
    BLKALLOC_LOG(INFO, , "Segment Count = {}, Blocks per segment = {}, portions={}", cfg.get_total_segments(),
                 seg_nblks, portions_per_seg);
    for (auto i = 0U; i < cfg.get_total_segments(); i++) {
        std::string seg_name = cfg.get_name() + "_seg_" + std::to_string(i);
        BlkAllocSegment* seg = new BlkAllocSegment(seg_nblks, i, portions_per_seg, seg_name);
        m_segments.push_back(seg);
    }

    BtreeConfig btree_cfg(HS_DYNAMIC_CONFIG(btree->mem_btree_page_size), cfg.get_name().c_str());

    btree_cfg.set_max_objs(cfg.get_max_cache_blks());
    btree_cfg.set_max_key_size(sizeof(VarsizeAllocCacheEntry));
    btree_cfg.set_max_value_size(0);
    m_blk_cache = VarsizeBlkAllocatorBtree::create_btree(btree_cfg);

    // Start a thread which will do sweeping job of free segments
    if (init) { inited(); }
}

void VarsizeBlkAllocator::incr_counter(unsigned int index, unsigned int val) {
    switch (index) {
    case 0:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab0_capacity, val);
        break;
    case 1:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab1_capacity, val);
        break;
    case 2:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab2_capacity, val);
        break;
    case 3:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab3_capacity, val);
        break;
    case 4:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab4_capacity, val);
        break;
    case 5:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab5_capacity, val);
        break;
    case 6:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab6_capacity, val);
        break;
    case 7:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab7_capacity, val);
        break;
    case 8:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab8_capacity, val);
        break;
    case 9:
        COUNTER_INCREMENT(m_metrics, blkalloc_slab9_capacity, val);
        break;
    default:
        BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "Invalid index={} for slab counter increment", index);
    }
}

void VarsizeBlkAllocator::decr_counter(unsigned int index, unsigned int val) {
    switch (index) {
    case 0:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab0_capacity, val);
        break;
    case 1:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab1_capacity, val);
        break;
    case 2:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab2_capacity, val);
        break;
    case 3:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab3_capacity, val);
        break;
    case 4:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab4_capacity, val);
        break;
    case 5:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab5_capacity, val);
        break;
    case 6:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab6_capacity, val);
        break;
    case 7:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab7_capacity, val);
        break;
    case 8:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab8_capacity, val);
        break;
    case 9:
        COUNTER_DECREMENT(m_metrics, blkalloc_slab9_capacity, val);
        break;
    default:
        BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "Invalid index={} for slab counter decrement", index);
    }
}

uint64_t VarsizeBlkAllocator::get_portions_per_segment() {
    return (m_cfg.get_total_portions() / m_cfg.get_total_segments());
}

VarsizeBlkAllocator::~VarsizeBlkAllocator() {
    {
        std::lock_guard< std::mutex > lk(m_mutex);
        if (m_region_state != BLK_ALLOCATOR_EXITING) {
            BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "Region state = {}, set to {}", m_region_state,
                         BLK_ALLOCATOR_EXITING);
            m_region_state = BLK_ALLOCATOR_EXITING;
        }
    }

    m_cv.notify_all();
    if (m_thread_id.joinable()) { m_thread_id.join(); }
    delete (m_blk_cache);
    delete (m_cache_bm);
    for (auto i = 0U; i < m_cfg.get_total_segments(); i++) {
        delete (m_segments[i]);
        BLKALLOC_LOG(INFO, , "Deleted segment {}", i);
    }
}

// Runs only in per sweep thread. In other words, this is a single threaded state machine.
void VarsizeBlkAllocator::allocator_state_machine() {
    BLKALLOC_LOG(INFO, , "Starting new blk sweep thread, thread num = {}", sisl::ThreadLocalContext::my_thread_num());
    BlkAllocSegment* allocate_seg = nullptr;
    int slab_indx;
    bool allocate = false;

    while (true) {
        allocate_seg = nullptr;
        slab_indx = -1;
        allocate = false;
        {
            std::unique_lock< std::mutex > lk(m_mutex);

            if (m_region_state == BLK_ALLOCATOR_DONE) {
                m_cv.wait(lk);
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Region state : done");
            }

            if (m_region_state == BLK_ALLOCATOR_WAIT_ALLOC) {
                m_region_state = BLK_ALLOCATOR_ALLOCATING;
                allocate_seg = m_wait_alloc_segment;
                slab_indx = m_wait_slab_indx;
                allocate = true;
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Region state : wait-alloc -> allocating");

            } else if (m_region_state == BLK_ALLOCATOR_EXITING) {
                BLKALLOC_LOG(INFO, varsize_blk_alloc, "TODO: Handle exiting message more periodically");
                break;
            }
        }
        if (allocate) {
            BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Fill cache for segment");
            fill_cache(allocate_seg, slab_indx);
            {
                // acquire lock
                std::unique_lock< std::mutex > lk(m_mutex);
                m_wait_alloc_segment = nullptr;
                if (m_region_state != BLK_ALLOCATOR_EXITING) { m_region_state = BLK_ALLOCATOR_DONE; }
                m_cv.notify_all();
            }
            BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Done with fill cache for segment");
        }
    }
}

bool VarsizeBlkAllocator::is_blk_alloced(BlkId& b) {
    if (!m_inited) { return true; }
    BLKALLOC_ASSERT(DEBUG, m_cache_bm->is_bits_set(b.get_id(), b.get_nblks()), "Expected bits to reset");
    return true;
}

void VarsizeBlkAllocator::inited() {
    m_cache_bm->copy(*(get_disk_bm()));
    m_thread_id = sisl::named_thread("blkalloc_sweep", bind_this(VarsizeBlkAllocator::allocator_state_machine, 0));
    LOGINFO("blk allocator inited");
    BlkAllocator::inited();
}

/* Check cache to see what blks are available */
uint64_t VarsizeBlkAllocator::get_best_fit_cache(uint64_t blks_rqstd) {

    auto slab_index = get_config().get_slab(blks_rqstd).first;
    while (slab_index > 0) {
        if (m_slab_entries[slab_index]._a.load()) { return (get_config().get_slab_lower_bound(slab_index)); }
        slab_index--;
    }

    return 0;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(uint8_t nblks, const blk_alloc_hints& hints,
                                          std::vector< BlkId >& out_blkid) {
    uint8_t blks_alloced = 0;
    uint32_t retry_cnt = 0;

    uint8_t blks_rqstd = nblks;

    BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "init status={}", m_inited);
    BLKALLOC_ASSERT(LOGMSG, m_inited, "Alloc before initialized");

    BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "nblks={}, hints multiplier={}", nblks, hints.multiplier);
    BLKALLOC_ASSERT_CMP(LOGMSG, nblks % hints.multiplier, ==, 0);

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("varsize_blkalloc_no_blks", nblks)) { return BLK_ALLOC_SPACEFULL; }

    auto split_cnt = homestore_flip->get_test_flip< int >("blkalloc_split_blk");
    if (!hints.is_contiguous && split_cnt && nblks > split_cnt.get()) {
        blks_rqstd = sisl::round_up((nblks / split_cnt.get()), hints.multiplier);
        BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "blocks requested={}, nblks={}, split_cnt={}", blks_rqstd, nblks,
                     split_cnt.get());
    }
#endif

    COUNTER_INCREMENT(m_metrics, num_alloc, 1);
    while (blks_alloced != nblks && retry_cnt < HS_DYNAMIC_CONFIG(blkallocator->max_varsize_blk_alloc_attempt)) {
        BlkId blkid;
        COUNTER_INCREMENT(m_metrics, num_split, 1);
        if (blks_rqstd > HS_STATIC_CONFIG(engine.max_blk_cnt)) {
            blks_rqstd = sisl::round_down(HS_STATIC_CONFIG(engine.max_blk_cnt), hints.multiplier);
        }
        if (alloc(blks_rqstd, hints, &blkid, true) != BLK_ALLOC_SUCCESS) {
            /* check the cache to see what blocks are available and get those
             * blocks from the btree cache.
             */
            auto new_blks_rqstd = get_best_fit_cache(blks_rqstd);

            /* It is because of a bug in btree where we can keep checking for the leaf node
             * in the btree cache which doesn't have any keys. This code will go away once we
             * have the range query implemented in btree.
             */
            if (new_blks_rqstd >= blks_rqstd) {
                blks_rqstd = sisl::round_up((blks_rqstd / 2), hints.multiplier);
            } else {
                blks_rqstd = new_blks_rqstd;
            }
            if (blks_rqstd == 0) {
                /* It should never happen. It means we are running out of space */
                blks_rqstd = nblks - blks_alloced;
                BLKALLOC_LOG(ERROR, , "Could not allocate any blocks. Running out of space");
            }
        } else {
            BLKALLOC_LOG(TRACE, , "Blocks allocated={}", blks_alloced);
            blks_alloced += blkid.get_nblks();
            BLKALLOC_LOG(DEBUG, varsize_blk_alloc, "blks_alloced={}, hints multiplier={}", blks_alloced,
                         hints.multiplier);
            BLKALLOC_ASSERT_CMP(LOGMSG, blks_alloced % hints.multiplier, ==, 0);

            blks_rqstd = nblks - blks_alloced;
            assert(blkid.get_nblks() != 0);
            out_blkid.push_back(blkid);
        }
        retry_cnt++;
        BLKALLOC_LOG(TRACE, , "Retry count={}", retry_cnt);
    }

    BLKALLOC_LOG(TRACE, varsize_blk_alloc, "blks_alloced={}, blocks requested={}", blks_alloced, nblks);

    if (blks_alloced != nblks) {
        if (m_cache_n_entries.load(std::memory_order_acquire) != 0) { m_blk_cache->print_tree(); }
        BLKALLOC_LOG(ERROR, , "blks_alloced != nblks : {}  {}", blks_alloced, nblks);
        COUNTER_INCREMENT(m_metrics, alloc_fail, 1);
        /* free blks */
        for (uint32_t i = 0; i < out_blkid.size(); ++i) {
            free(out_blkid[i]);
        }
        out_blkid.clear();
        return BLK_ALLOC_SPACEFULL;
    }
    return BLK_ALLOC_SUCCESS;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(uint8_t nblks, const blk_alloc_hints& hints, BlkId* out_blkid,
                                          bool best_fit) {
    BlkAllocStatus ret = BLK_ALLOC_SUCCESS;
    bool found = false;

    // TODO: Instead of given value, try to have leeway like 10% of both sides as range for desired_temp or bkt.
    VarsizeAllocCacheEntry start_entry(BLKID_RANGE_FIRST, PAGEID_RANGE_FIRST, nblks, hints.desired_temp);
    VarsizeAllocCacheEntry end_entry(BLKID_RANGE_LAST, PAGEID_RANGE_LAST, BLKCOUNT_RANGE_LAST, TEMP_RANGE_LAST);
    VarsizeAllocCacheEntry actual_entry;

    BtreeSearchRange regex(start_entry, true, /* start_incl */ end_entry, false, /* end incl */
                           _MultiMatchSelector::BEST_FIT_TO_CLOSEST_FOR_REMOVE);

    EmptyClass dummy_val;
    uint32_t attempt = 1;
    while (true) {
        auto status = m_blk_cache->remove_any(regex, &actual_entry, &dummy_val);
        found = (status == btree_status_t::success);
        if (found) {
#ifdef _PRERELEASE
            if (homestore_flip->test_flip("blkalloc_no_blks_cache", nblks)) {
                EmptyClass dummy;
                m_blk_cache->put(actual_entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                found = false;
            }
#endif
            if (best_fit) {
                if (actual_entry.get_blk_count() < hints.multiplier) {
                    /* it should be atleast equal to hints multiplier. If not then wait for cache to populate */
                    EmptyClass dummy;
                    m_blk_cache->put(actual_entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                    found = false;
                } else {
                    /* trigger blk allocator to populate cache */
                    if (actual_entry.get_blk_count() != nblks) {
                        auto slab_indx = get_config().get_slab(nblks).first;
                        request_more_blks(nullptr, slab_indx);
                    }
                    break;
                }
            } else {
                if (actual_entry.get_blk_count() < nblks) {
                    found = false;
                    EmptyClass dummy;
                    m_blk_cache->put(actual_entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                } else {
                    break;
                }
            }
        }

        // Wait for cache to refill and then retry original request
        if (attempt > HS_DYNAMIC_CONFIG(blkallocator->max_cache_fill_varsize_blk_alloc_attempt)) {
            BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Exceeding max retries {} to allocate. Failing the alloc",
                         HS_DYNAMIC_CONFIG(blkallocator->max_cache_fill_varsize_blk_alloc_attempt));
            for (auto i = 0U; i < m_slab_entries.size(); i++) {
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Capacity of slab {} = {}", i,
                             m_slab_entries[i]._a.load(std::memory_order_acq_rel));
            }
            COUNTER_INCREMENT(m_metrics, num_attempts_failed, 1);
            break;
        } else {
            BLKALLOC_LOG(TRACE, varsize_blk_alloc,
                         "Attempt #{} to allocate nblks={} temperature={} failed. Waiting for cache to be filled",
                         attempt, (uint32_t)nblks, hints.desired_temp);
            COUNTER_INCREMENT(m_metrics, num_retry, 1);
        }

        auto slab_indx = get_config().get_slab(nblks).first;
        request_more_blks_wait(nullptr, slab_indx);
        attempt++;
    }

    if (!found) { return BLK_ALLOC_SPACEFULL; }

    /* get excess blks */
    int excess_nblks = actual_entry.get_blk_count() - nblks;
    if (excess_nblks < 0) {
        BLKALLOC_ASSERT_CMP(LOGMSG, best_fit, ==, true);
        /* it has to be multiplier of hints */
        excess_nblks = actual_entry.get_blk_count() % hints.multiplier;
    }
    BLKALLOC_ASSERT_CMP(LOGMSG, excess_nblks, >=, 0);

    auto slab_index = get_config().get_slab(actual_entry.get_blk_count()).first;
    m_slab_entries[slab_index]._a.fetch_sub(actual_entry.get_blk_count(), std::memory_order_acq_rel);
    decr_counter(slab_index, actual_entry.get_blk_count());

    /* If we have more blks than what we need, insert the remaining blks to
       the bitmap. We can give either the leading blocks or trailing blocks.
       In case one of them is part of less number of pages than others, it
       is better to pick the lesser ones.
     */
    uint64_t alloc_blks = actual_entry.get_blk_count() - excess_nblks;
    if (excess_nblks > 0) {
        uint64_t blknum = actual_entry.get_blk_num();
        int leading_npages = (int)(blknum_to_phys_pageid(blknum + alloc_blks) - actual_entry.get_phys_page_id());
        int trailing_npages = (int)(blknum_to_phys_pageid(blknum + actual_entry.get_blk_count()) -
                                    blknum_to_phys_pageid(blknum + excess_nblks));

        VarsizeAllocCacheEntry excess_entry;
        if (leading_npages <= trailing_npages) {
            out_blkid->set(blknum, alloc_blks);
            gen_cache_entry(blknum + alloc_blks, (uint32_t)excess_nblks, &excess_entry);
        } else {
            out_blkid->set(blknum + excess_nblks, alloc_blks);
            gen_cache_entry(blknum, (uint32_t)excess_nblks, &excess_entry);
        }
        EmptyClass dummy;
        m_blk_cache->put(excess_entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);

        auto slab_index = get_config().get_slab(excess_nblks).first;
        m_slab_entries[slab_index]._a.fetch_add(excess_nblks, std::memory_order_acq_rel);
        incr_counter(slab_index, excess_nblks);

    } else {
        out_blkid->set(actual_entry.get_blk_num(), alloc_blks);
    }

    m_cache_n_entries.fetch_sub(alloc_blks, std::memory_order_acq_rel);
    return ret;
}

void VarsizeBlkAllocator::free(const BlkId& b) {
    BlkAllocPortion* portion = blknum_to_portion(b.get_id());
    BlkAllocSegment* segment = blknum_to_segment(b.get_id());

    portion->lock();

    /* No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to
     * cache bm.
     */
    if (m_inited) {
        BLKALLOC_ASSERT(RELEASE, m_cache_bm->is_bits_set(b.get_id(), b.get_nblks()), "Expected bits to reset");
        segment->add_free_blks(b.get_nblks());
        m_cache_bm->reset_bits(b.get_id(), b.get_nblks());
    }
    portion->unlock();
}

// This runs on per region thread and is at present single threaded.
/* we are going through the segments which has maximum free blks so that we can ensure that all slabs are populated.
 * We might need to find a efficient way of doing it later. It stop processing the segment when any slab greater then
 * slab_indx is full.
 */
void VarsizeBlkAllocator::fill_cache(BlkAllocSegment* seg, int slab_indx) {
    uint64_t nadded_blks = 0;

    BLKALLOC_ASSERT_NULL(LOGMSG, seg);
    /* While cache is not full */
    uint32_t total_segments = 0;
    uint32_t max_blks = 0;
    for (uint32_t i = 0; i < m_segments.size(); ++i) {
        if (m_segments[i]->get_free_blks() > max_blks) {
            seg = m_segments[i];
            max_blks = m_segments[i]->get_free_blks();
        }
    }

    if (seg == nullptr) {
        LOGINFO("There are no free blocks in var size blk allocator");
        return;
    }

    uint64_t start_portion_num = seg->get_clock_hand();
    while (m_cache_n_entries.load(std::memory_order_acquire) < get_config().get_max_cache_blks()) {

        bool refill_needed = true;
        assert(slab_indx >= 0);
        if (slab_indx < 0) { slab_indx = 0; }
        for (auto i = slab_indx; i < (int)m_slab_entries.size(); ++i) {
            // Low water mark for cache slabs is half of full capacity
            auto count = m_slab_entries[i]._a.load(std::memory_order_acq_rel);
            if (count <= get_config().get_slab_capacity(i) / 2) {
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Hit low water mark for slab {} capacity = {}", i,
                             m_slab_entries[i]._a.load(std::memory_order_acq_rel));
            } else {
                // atleast one slab is full.Wake up the IO thread
                refill_needed = false;
                /* break; // commented out so that logs for all slabs can be printed
                 */
            }
        }
        if (!refill_needed) break; // Atleast one slab has sufficient blocks

        BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Refill cache");
        uint64_t portion_num = seg->get_clock_hand();
        nadded_blks += fill_cache_in_portion(portion_num, seg);
        if (nadded_blks > 0) {
            /* We got some blks. wake the IO threads if there are waiting. This thread will continue to
             * populate the desired slab.
             */
            std::unique_lock< std::mutex > lk(m_mutex);
            m_cv.notify_all();
        }

        // Goto next group within the segment.
        seg->inc_clock_hand();
        portion_num = seg->get_clock_hand();

        if (portion_num == start_portion_num) {
            // Came one full circle, no need to look more.
            break;
        }
    }

    if (nadded_blks) {
        BLKALLOC_ASSERT_CMP(LOGMSG, seg->get_free_blks(), >=, nadded_blks);
        seg->remove_free_blks(nadded_blks);
        BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Bitset sweep thread added {} blks to blk cache", nadded_blks);
    } else {
        BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Bitset sweep failed to add any blocks to blk cache");
    }
}

uint64_t VarsizeBlkAllocator::fill_cache_in_portion(uint64_t seg_portion_num, BlkAllocSegment* seg) {
    EmptyClass dummy;
    uint64_t n_added_blks = 0;
    uint64_t n_fragments = 0;

    uint64_t portion_num = seg->get_seg_num() * get_portions_per_segment() + seg_portion_num;
    BLKALLOC_ASSERT_CMP(LOGMSG, m_cfg.get_total_portions(), >, portion_num);
    BlkAllocPortion& portion = *(get_blk_portions(portion_num));
    auto num_blks_per_portion = get_config().get_blks_per_portion();
    auto cur_blk_id = portion_num * num_blks_per_portion;
    auto end_blk_id = cur_blk_id + num_blks_per_portion;
    uint32_t num_blks_per_phys_page = get_config().get_blks_per_phys_page();

    portion.lock();
    /* TODO: Consider caching the m_cache_n_entries and give some leeway
     *       to max cache blks and thus avoid atomic operations
     */
    while ((m_cache_n_entries.load(std::memory_order_acq_rel) < get_config().get_max_cache_blks()) &&
           (cur_blk_id < end_blk_id)) {

        // Get next reset bits and insert to cache and then reset those bits
        auto b = m_cache_bm->get_next_contiguous_upto_n_reset_bits(cur_blk_id, MAX_NBLKS);
        BLKALLOC_ASSERT_CMP(LOGMSG, b.nbits, <=, MAX_NBLKS);

        /* If there are no free blocks are none within the assigned portion */
        if (!b.nbits || b.start_bit >= end_blk_id) { break; }

        /* Limit cache update to within portion boundary */
        if (b.start_bit + b.nbits > end_blk_id) { b.nbits = end_blk_id - b.start_bit; }

        /* Create cache entry for start till end or upto next page boundary,
           whichever is earlier. This will be used if start is not aligned
           with a page boundary
         */
        uint64_t total_bits = 0;
        unsigned int nbits = b.start_bit % num_blks_per_phys_page;
        if (nbits) {
            nbits = std::min(num_blks_per_phys_page - nbits, b.nbits);
            auto slab_index = get_config().get_slab(nbits).first;
            if (m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel) <
                get_config().get_slab_capacity(slab_index)) {
                VarsizeAllocCacheEntry entry;
                gen_cache_entry(b.start_bit, nbits, &entry);
#ifndef NDEBUG
                BLKALLOC_ASSERT(DEBUG, m_cache_bm->is_bits_reset(b.start_bit, nbits), "Expected bits to reset");
#endif
                m_blk_cache->put(entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                // TODO: Trap the return status of insert
                m_cache_bm->set_bits(b.start_bit, nbits);
                total_bits += nbits;
                m_slab_entries[slab_index]._a.fetch_add(nbits, std::memory_order_acq_rel);
                incr_counter(slab_index, nbits);
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Freed {} blocks for slab {}, remaining slab capacity = {}",
                             nbits, slab_index, m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            } else {
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Slab {} is full, capacity = {}", slab_index,
                             m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            }
            b.nbits -= nbits;
            b.start_bit += nbits;
        }

        /* Create cache entry for end page, if end page has partial entry */
        /* At this point start is aligned with blks end point or page boundary,
           whichever occurs earlier
         */
        cur_blk_id = b.start_bit + b.nbits;
        nbits = cur_blk_id % num_blks_per_phys_page;
        if (b.nbits && nbits) {
            /* If code enters this section, it means that start is aligned to a page
               boundary
             */
            BLKALLOC_ASSERT_CMP(LOGMSG, b.start_bit % num_blks_per_phys_page, ==, 0);
            auto start = cur_blk_id - nbits;
            auto slab_index = get_config().get_slab(nbits).first;
            if (m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel) <
                get_config().get_slab_capacity(slab_index)) {
                VarsizeAllocCacheEntry entry;
                gen_cache_entry(start, nbits, &entry);
#ifndef NDEBUG
                BLKALLOC_ASSERT(DEBUG, m_cache_bm->is_bits_reset(start, nbits), "Expected cache_bm bits to reset");
#endif
                m_blk_cache->put(entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                // TODO: Trap the return status of insert
                m_cache_bm->set_bits(start, nbits);
                total_bits += nbits;
                m_slab_entries[slab_index]._a.fetch_add(nbits, std::memory_order_acq_rel);
                incr_counter(slab_index, nbits);
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Freed {} blocks for slab {}, remaining slab capacity = {}",
                             nbits, slab_index, m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            } else {
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Slab {} is full, capacity = {}", slab_index,
                             m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            }
            b.nbits -= nbits;
        }

        /* Create cache entry for complete pages between start and end */
        if (b.nbits) {
            /* If code enters this section, it means that start is aligned to a page
               boundary and nbits left is a multiple of page size
             */
            BLKALLOC_ASSERT_CMP(LOGMSG, b.start_bit % num_blks_per_phys_page, ==, 0);
            BLKALLOC_ASSERT_CMP(LOGMSG, b.nbits % num_blks_per_phys_page, ==, 0);
            auto slab_index = get_config().get_slab(b.nbits).first;
            if (m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel) <
                get_config().get_slab_capacity(slab_index)) {
                VarsizeAllocCacheEntry entry;
                gen_cache_entry(b.start_bit, b.nbits, &entry);
#ifndef NDEBUG
                BLKALLOC_ASSERT(DEBUG, m_cache_bm->is_bits_reset(b.start_bit, b.nbits),
                                "Expected cache_bm bits to reset");
#endif
                m_blk_cache->put(entry, dummy, btree_put_type::INSERT_ONLY_IF_NOT_EXISTS);
                // TODO: Trap the return status of insert
                m_cache_bm->set_bits(b.start_bit, b.nbits);
                total_bits += b.nbits;
                m_slab_entries[slab_index]._a.fetch_add(b.nbits, std::memory_order_acq_rel);
                incr_counter(slab_index, b.nbits);
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Freed {} blocks for slab {}, remaining slab capacity = {}",
                             b.nbits, slab_index, m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            } else {
                BLKALLOC_LOG(TRACE, varsize_blk_alloc, "Slab {} is full, capacity = {}", slab_index,
                             m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            }
        }

        // Update the counters
        if (total_bits) {
            n_added_blks += total_bits;
            n_fragments++;
            m_cache_n_entries.fetch_add(total_bits, std::memory_order_acq_rel);
        }
    }
    portion.unlock();
    seg->reportFragmentation(n_added_blks, n_fragments);
    return n_added_blks;
}

// Run in non-region threads. It can be called by multiple threads simultaneously.
// Request for more blocks from a specified segment. If BlkSegment is NULL, then it picks the 1st segment to allocate
// from.
void VarsizeBlkAllocator::request_more_blks(BlkAllocSegment* seg, int slab_indx) {
    bool allocate = false;
    {
        // acquire lock
        std::unique_lock< std::mutex > lk(m_mutex);
        if (m_region_state == BLK_ALLOCATOR_DONE) {
            m_wait_alloc_segment = seg;
            m_wait_slab_indx = slab_indx;
            m_region_state = BLK_ALLOCATOR_WAIT_ALLOC;
            allocate = true;
        }
    } // release lock

    if (allocate) { m_cv.notify_all(); }
}

void VarsizeBlkAllocator::request_more_blks_wait(BlkAllocSegment* seg, int slab_indx) {
    /* TODO: rishabh if segment is not NULL then this function won't work */
    std::unique_lock< std::mutex > lk(m_mutex);
    BLKALLOC_ASSERT_NULL(LOGMSG, seg);
    if (m_region_state == BLK_ALLOCATOR_DONE) {
        m_wait_alloc_segment = seg;
        m_wait_slab_indx = slab_indx;
        m_region_state = BLK_ALLOCATOR_WAIT_ALLOC;
        m_cv.notify_all();
    }
    // Wait for notification that it is done
    if (m_region_state != BLK_ALLOCATOR_DONE && m_region_state != BLK_ALLOCATOR_EXITING) { m_cv.wait(lk); }
}

std::string VarsizeBlkAllocator::state_string(BlkAllocatorState state) const {
    if (state == BLK_ALLOCATOR_DONE) {
        return "BLK_REGION_DONE";
    } else if (state == BLK_ALLOCATOR_WAIT_ALLOC) {
        return "BLK_REGION_WAIT_ALLOC";
    } else if (state == BLK_ALLOCATOR_ALLOCATING) {
        return "BLK_REGION_ALLOCATING";
    } else if (state == BLK_ALLOCATOR_EXITING) {
        return "BLK_REGION_EXITING";
    } else {
        return "STATUS_UNKNOWN";
    }
}

std::string VarsizeBlkAllocator::to_string() const {
    ostringstream oss;
    oss << "ThreadId=" << m_thread_id.get_id() << " RegionState=" << state_string(m_region_state)
        << " Total cache entries = " << m_cache_n_entries.load(std::memory_order_relaxed);
    return oss.str();
}

int VarsizeAllocCacheEntry::is_in_range(uint64_t val, uint64_t start, bool start_incl, uint64_t end,
                                        bool end_incl) const {
    if (val < start) {
        return -1;
    } else if ((val == start) && (!start_incl)) {
        return -1;
    } else if (val > end) {
        return 1;
    } else if ((val == end) && (!end_incl)) {
        return 1;
    } else {
        return 0;
    }
}

int VarsizeAllocCacheEntry::compare_range(const BtreeSearchRange& range) const {
    auto start_entry = (VarsizeAllocCacheEntry*)range.get_start_key();
    auto end_entry = (VarsizeAllocCacheEntry*)range.get_end_key();

    int ret = is_in_range(this->get_blk_count(), start_entry->get_blk_count(), range.is_start_inclusive(),
                          end_entry->get_blk_count(), range.is_end_inclusive());
    if (ret != 0) { return ret; }

    ret = is_in_range(this->get_temperature(), start_entry->get_temperature(), range.is_start_inclusive(),
                      end_entry->get_temperature(), range.is_end_inclusive());
    if (ret != 0) { return ret; }

    ret = is_in_range(this->get_phys_page_id(), start_entry->get_phys_page_id(), range.is_start_inclusive(),
                      end_entry->get_phys_page_id(), range.is_end_inclusive());
    return ret;
}

#if 0
int VarsizeAllocCacheEntry::compare_range(const VarsizeAllocCacheEntry *start, bool start_incl,
                                          const VarsizeAllocCacheEntry *end, bool end_incl) const {
    int ret = is_in_range(this->get_blk_count(), start->get_blk_count(), start_incl, end->get_blk_count(),
                          end_incl);
    if (ret != 0) {
        return ret;
    }

    ret = is_in_range(this->get_temperature(), start->get_temperature(), start_incl, end->get_temperature(),
                      end_incl);
    if (ret != 0) {
        return ret;
    }

    ret = is_in_range(this->get_page_id(), start->get_page_id(), start_incl, end->get_page_id(), end_incl);
    return ret;
}
#endif

int VarsizeAllocCacheEntry::compare(const BtreeKey* o) const {
    auto* other = (VarsizeAllocCacheEntry*)o;
    if (get_blk_count() < other->get_blk_count()) {
        return -1;
    } else if (get_blk_count() > other->get_blk_count()) {
        return 1;
    } else if (get_temperature() < other->get_temperature()) {
        return -1;
    } else if (get_temperature() > other->get_temperature()) {
        return 1;
    } else if (get_phys_page_id() < other->get_phys_page_id()) {
        return -1;
    } else if (get_phys_page_id() > other->get_phys_page_id()) {
        return 1;
    } else if (get_blk_num() < other->get_blk_num()) {
        return -1;
    } else if (get_blk_num() > other->get_blk_num()) {
        return 1;
    } else {
        return 0;
    }
}
} // namespace homestore
