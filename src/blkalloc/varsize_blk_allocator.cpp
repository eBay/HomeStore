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
#include "homeds/btree/mem_btree.hpp"
#include <sds_logging/logging.h>

namespace homestore {

void thread_func(VarsizeBlkAllocator *b) {
    b->allocator_state_machine();
}

VarsizeBlkAllocator::VarsizeBlkAllocator(VarsizeBlkAllocConfig &cfg) :
        BlkAllocator(cfg),
        m_cfg(cfg),
        m_region_state(BLK_ALLOCATOR_DONE),
        m_wait_alloc_segment(nullptr),
        m_blk_portions(cfg.get_total_portions()),
        m_temp_groups(cfg.get_total_temp_group()),
        m_cache_n_entries(0) {

    // TODO: Raise exception when blk_size > page_size or total blks is less than some number etc...
    m_alloc_bm = new homeds::Bitset(cfg.get_total_blks());

#ifndef NDEBUG
    for (auto i = 0U; i < cfg.get_total_temp_group(); i++) {
        m_temp_groups[i].m_temp_group_id = i;
    }
#endif

#ifndef NDEBUG
    for (auto i = 0U; i < cfg.get_total_portions(); i++) {
        m_blk_portions[i].m_blk_portion_id = i;
    }
#endif

    // Create segments with as many blk groups as configured.
    uint64_t seg_size = (cfg.get_total_blks() * cfg.get_blk_size())/cfg.get_total_segments();
    for (auto i = 0U; i < cfg.get_total_segments(); i++) {
        BlkAllocSegment *seg = new BlkAllocSegment(seg_size, i);
        BlkAllocSegment::SegQueue::handle_type segid = m_heap_segments.push(seg);
        seg->set_segment_id(segid);
    }

    // Create a btree to cache temperature, blks info (blk num, page id etc..)
    homeds::btree::BtreeConfig btree_cfg;
    btree_cfg.set_max_objs(cfg.get_max_cache_blks());
    btree_cfg.set_max_key_size(sizeof(VarsizeAllocCacheEntry));
    btree_cfg.set_max_value_size(0);
    m_blk_cache = VarsizeBlkAllocatorBtree::create_btree(btree_cfg, nullptr);

    // Start a thread which will do sweeping job of free segments
    m_thread_id = std::thread(thread_func, this);
}

VarsizeBlkAllocator::~VarsizeBlkAllocator() {
    {
        std::lock_guard< std::mutex > lk(m_mutex);
        if (m_region_state != BLK_ALLOCATOR_EXITING) {
            m_region_state = BLK_ALLOCATOR_EXITING;
        }
    }

    m_cv.notify_all();
    m_thread_id.join();
}

#define MAX_BLK_ALLOC_ATTEMPT 3

// Runs only in per sweep thread. In other words, this is a single threaded state machine.
void VarsizeBlkAllocator::allocator_state_machine() {
    BlkAllocSegment *allocate_seg = nullptr;
    bool allocate;

    LOGDEBUG("Starting new blk sweeep thread");
    while (true) {
        allocate_seg = nullptr;
        allocate = false;
        {
            // acquire lock
            std::unique_lock< std::mutex > lk(m_mutex);

            if (m_region_state == BLK_ALLOCATOR_DONE) {
                m_cv.wait(lk);
            }

            if (m_region_state == BLK_ALLOCATOR_WAIT_ALLOC) {
                m_region_state = BLK_ALLOCATOR_ALLOCATING;
                allocate_seg = m_wait_alloc_segment;
                allocate = true;
            } else if (m_region_state == BLK_ALLOCATOR_EXITING) {
                // TODO: Handle exiting message more periodically.
                break;
            }
        }

        if (allocate) {
            fill_cache(allocate_seg);
            {
                // acquire lock
                std::unique_lock< std::mutex > lk(m_mutex);
                m_wait_alloc_segment = nullptr;
                m_region_state = BLK_ALLOCATOR_DONE;
            	m_cv.notify_all();
            }
        }
    }
}

BlkAllocStatus VarsizeBlkAllocator::alloc(uint8_t nblks, const blk_alloc_hints &hints, BlkId *out_blkid) {
    BlkAllocStatus ret = BLK_ALLOC_SUCCESS;
    bool found = false;

    // TODO: Instead of given value, try to have leeway like 10% of both sides as range for desired_temp or bkt.
    VarsizeAllocCacheEntry start_entry(BLKID_RANGE_FIRST, PAGEID_RANGE_FIRST, nblks, hints.desired_temp);
    VarsizeAllocCacheEntry end_entry(BLKID_RANGE_LAST, PAGEID_RANGE_LAST, BLKCOUNT_RANGE_LAST, TEMP_RANGE_LAST);
    VarsizeAllocCacheEntry actual_entry;

    homeds::btree::BtreeSearchRange regex(start_entry, true, /* start_incl */
                                        end_entry, false, /* end incl */
                                        true /* lean_left */, true);
    homeds::btree::EmptyClass dummy_val;
    int attempt = 1;
    while (true) {
        found = m_blk_cache->remove_any(regex, &actual_entry, &dummy_val);
        if (found) {
            break;
        }

        // Wait for cache to refill and then retry original request
        if (attempt > MAX_BLK_ALLOC_ATTEMPT) {
            LOGERROR("Exceeding max retries {} to allocate. Failing the alloc", MAX_BLK_ALLOC_ATTEMPT);
            break;
        } else {
            LOGWARN("Attempt #{} to allocate nblks={} temperature={} failed. Waiting for cache to be filled",
                    attempt,
                    (uint32_t)nblks,
                    hints.desired_temp);
        }

        request_more_blks_wait(nullptr);
        attempt++;
    }

    if (!found) {
        return BLK_ALLOC_SPACEFULL;
    }

    int excess_nblks = actual_entry.get_blk_count() - nblks;
    assert(excess_nblks >= 0);

    if (excess_nblks) {
        uint64_t blknum = actual_entry.get_blk_num();

        // If we have more blks than what we need, just reinsert the remaining blks to the btree
        // We can give either the leading blocks or trailing blocks. In case one of them is part of less number of
        // pages than others, it is better to pick the lesser ones.
        int leading_npages = (int)(blknum_to_pageid(blknum + nblks) - actual_entry.get_page_id());
        int trailing_npages = (int)(blknum_to_pageid(blknum + actual_entry.get_blk_count()) -
                               blknum_to_pageid(blknum + excess_nblks));

        VarsizeAllocCacheEntry excess_entry;
        if (leading_npages <= trailing_npages) {
            out_blkid->set(blknum, nblks);
            gen_cache_entry(blknum + nblks, (uint32_t)excess_nblks, &excess_entry);
        } else {
            out_blkid->set(blknum + excess_nblks, nblks);
            gen_cache_entry(blknum, (uint32_t)excess_nblks, &excess_entry);
        }

        homeds::btree::EmptyClass dummy;
        m_blk_cache->put(excess_entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
    } else {
        out_blkid->set(actual_entry.get_blk_num(), nblks);
    }

    m_cache_n_entries.fetch_sub(nblks, std::memory_order_acq_rel);
    return ret;
}

void VarsizeBlkAllocator::free(const BlkId &b) {
    BlkAllocPortion *portion = blknum_to_portion(b.get_id());

    // Reset the bits
    portion->lock();
    m_alloc_bm->reset_bits(b.get_id(), b.get_nblks());
    portion->unlock();

    //std::cout << "Resetting " << p.get_blk_id() << " for nblks = " << nblks << " Bitmap state= \n";
    //m_alloc_bm->print();
}

// This runs on per region thread and is at present single threaded.
void VarsizeBlkAllocator::fill_cache(BlkAllocSegment *seg) {
    uint64_t nadded_blks = 0;
    if (seg == NULL) {
        seg = m_heap_segments.top();
    }

    uint64_t start_portion_num = seg->get_clock_hand();
    while (m_cache_n_entries.load(std::memory_order_acquire) < get_config().get_max_cache_blks()) {
        uint64_t portion_num = seg->get_clock_hand();
        nadded_blks += fill_cache_in_portion(portion_num, seg);

        // Goto next group within the segment.
        portion_num = (portion_num == (get_config().get_total_portions() - 1)) ? 0 : portion_num + 1;
        seg->set_clock_hand(portion_num);

        if (portion_num == start_portion_num) {
            // Came one full circle, no need to look more.
            break;
        }
    }

    assert(seg->get_free_blks() >= nadded_blks);
    seg->set_free_blks(seg->get_free_blks() - nadded_blks);
    m_heap_segments.update(seg->get_segment_id(), seg);

    LOGDEBUG("Bitset sweep thread added {} blks to blk cache", nadded_blks);
}

uint64_t VarsizeBlkAllocator::fill_cache_in_portion(uint64_t portion_num, BlkAllocSegment *seg) {
    homeds::btree::EmptyClass dummy;
    uint64_t n_added_blks = 0;

    BlkAllocPortion &portion = m_blk_portions[portion_num];
    uint64_t cur_blk_id = portion_num * get_config().get_blks_per_portion();
    uint64_t end_blk_id = cur_blk_id + get_config().get_blks_per_portion();

    portion.lock();
    // TODO: Consider caching the m_cache_n_entries and give some leeway to max cache blks and thus avoid atomic operations
    while ((m_cache_n_entries.load(std::memory_order_acq_rel) < get_config().get_max_cache_blks()) &&
            (cur_blk_id < end_blk_id)) {

        // Get next reset bits and insert to cache and then reset those bits
        auto b = m_alloc_bm->get_next_contiguous_reset_bits(cur_blk_id);
        if (b.nbits == 0) {
            break; // No more free blks
        }

        VarsizeAllocCacheEntry entry;
        gen_cache_entry(b.start_bit, b.nbits, &entry);
        m_blk_cache->put(entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS); // TODO: Trap the return status of insert
        m_alloc_bm->set_bits(b.start_bit, b.nbits);

        // Update the counters
        n_added_blks += b.nbits;
    	m_cache_n_entries.fetch_add(b.nbits, std::memory_order_acq_rel);
        cur_blk_id = b.start_bit + b.nbits;
    }
    portion.unlock();

    return n_added_blks;
}

// Run in non-region threads. It can be called by multiple threads simultaneously.
// Request for more blocks from a specified segment. If BlkSegment is NULL, then it picks the 1st segment to allocate from.
void VarsizeBlkAllocator::request_more_blks(BlkAllocSegment *seg) {
    bool allocate = false;
    {
        // acquire lock
        std::unique_lock< std::mutex > lk(m_mutex);
        if (m_region_state == BLK_ALLOCATOR_DONE) {
            m_wait_alloc_segment = seg;
            m_region_state = BLK_ALLOCATOR_WAIT_ALLOC;
            allocate = true;
        }
    } // release lock

    if (allocate) {
        m_cv.notify_all();
    }
}

void VarsizeBlkAllocator::request_more_blks_wait(BlkAllocSegment *seg) {
    /* TODO: rishabh if segment is not NULL then this function won't work */ 
    std::unique_lock< std::mutex > lk(m_mutex);
    assert(seg == NULL);
    if (m_region_state == BLK_ALLOCATOR_DONE) {
	    m_wait_alloc_segment = seg;
	    m_region_state = BLK_ALLOCATOR_WAIT_ALLOC;
    	    m_cv.notify_all();
    }
    // Wait for notification that it is done
    m_cv.wait(lk);
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
    oss << "ThreadId=" << m_thread_id.get_id() << " RegionState=" << state_string(m_region_state) <<
            " Total cache entries = " << m_cache_n_entries.load(std::memory_order_relaxed);
    return oss.str();
}

int VarsizeAllocCacheEntry::is_in_range(uint64_t val, uint64_t start, bool start_incl, uint64_t end, bool end_incl) const {
    if (val < start) {
        return 1;
    } else if ((val == start) && (!start_incl)) {
        return 1;
    } else if (val > end) {
        return -1;
    } else if ((val == end) && (!end_incl)) {
        return -1;
    } else {
        return 0;
    }
}

int VarsizeAllocCacheEntry::compare_range(const homeds::btree::BtreeSearchRange &range) const {
    auto start_entry = (VarsizeAllocCacheEntry *)range.get_start_key();
    auto end_entry = (VarsizeAllocCacheEntry *)range.get_end_key();

    int ret = is_in_range(this->get_blk_count(), start_entry->get_blk_count(), range.is_start_inclusive(),
                          end_entry->get_blk_count(), range.is_end_inclusive());
    if (ret != 0) {
        return ret;
    }

    ret = is_in_range(this->get_temperature(), start_entry->get_temperature(), range.is_start_inclusive(),
                      end_entry->get_temperature(), range.is_end_inclusive());
    if (ret != 0) {
        return ret;
    }

    ret = is_in_range(this->get_page_id(), start_entry->get_page_id(), range.is_start_inclusive(),
                      end_entry->get_page_id(), range.is_end_inclusive());
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

int VarsizeAllocCacheEntry::compare(const homeds::btree::BtreeKey *o) const {
    auto *other = (VarsizeAllocCacheEntry *) o;
    if (get_blk_count() < other->get_blk_count()) {
        return -1;
    } else if (get_blk_count() > other->get_blk_count()) {
        return 1;
    } else if (get_temperature() < other->get_temperature()) {
        return -1;
    } else if (get_temperature() > other->get_temperature()) {
        return 1;
    } else if (get_page_id() < other->get_page_id()) {
        return -1;
    } else if (get_page_id() > other->get_page_id()) {
        return 1;
    } else {
        return 0;
    }
}
} //namespace homestore
