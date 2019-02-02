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

#ifndef NDEBUG
bool blk_alloc_test = false;
#endif

SDS_LOGGING_DECL(varsize_blk_alloc)

namespace homestore {

void thread_func(VarsizeBlkAllocator *b) {
    b->allocator_state_machine();
}

VarsizeBlkAllocator::VarsizeBlkAllocator(VarsizeBlkAllocConfig &cfg, bool init) :
        BlkAllocator(cfg),
        m_cfg(cfg),
        m_region_state(BLK_ALLOCATOR_DONE),
        m_blk_portions(cfg.get_total_portions()),
        m_temp_groups(cfg.get_total_temp_group()),
        m_cache_n_entries(0), m_init(false) {

    // TODO: Raise exception when blk_size > page_size or total blks is less than some number etc...
    m_alloc_bm = new homeds::Bitset(cfg.get_total_blks());

#ifndef NDEBUG
    m_alloced_bm = new homeds::Bitset(cfg.get_total_blks());
    
    for (auto i = 0U; i < cfg.get_total_temp_group(); i++) {
        m_temp_groups[i].m_temp_group_id = i;
    }
    
    for (auto i = 0U; i < cfg.get_total_portions(); i++) {
        m_blk_portions[i].m_blk_portion_id = i;
    }
#endif

    // Initialize the slab counters
    for (auto i = 0U; i < cfg.get_slab_cnt(); i++) {
        atomwrapper<uint32_t> a_i(0);
        m_slab_entries.push_back(a_i);
        LOGINFOMOD(varsize_blk_alloc, 
                   "Capacity of slab {} = {}", i, m_slab_entries[i]._a.load(std::memory_order_acq_rel));
    }

    // Create segments with as many blk groups as configured.
    uint64_t seg_nblks = cfg.get_total_blks() / cfg.get_total_segments();
    uint64_t portions_per_seg = cfg.get_total_portions() / cfg.get_total_segments();
    for (auto i = 0U; i < cfg.get_total_segments(); i++) {
        BlkAllocSegment *seg = new BlkAllocSegment(seg_nblks, i, portions_per_seg);
        m_segments.push_back(seg);
    }

    // Create a btree to cache temperature, blks info (blk num, page id etc..)
    homeds::btree::BtreeConfig btree_cfg;
    btree_cfg.set_max_objs(cfg.get_max_cache_blks());
    btree_cfg.set_max_key_size(sizeof(VarsizeAllocCacheEntry));
    btree_cfg.set_max_value_size(0);
    m_blk_cache = VarsizeBlkAllocatorBtree::create_btree(btree_cfg, nullptr);

    // Start a thread which will do sweeping job of free segments
    if (init) {
        inited();
     }
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
    delete(m_blk_cache);
    delete(m_alloc_bm);
    delete(m_alloced_bm);
    for (auto i = 0U; i < m_cfg.get_total_segments(); i++) {
        delete(m_segments[0]);
    }
}

#define MAX_BLK_ALLOC_ATTEMPT 3

// Runs only in per sweep thread. In other words, this is a single threaded state machine.
void VarsizeBlkAllocator::allocator_state_machine() {
    LOGINFOMOD(varsize_blk_alloc, "Starting new blk sweep thread");
    BlkAllocSegment *allocate_seg = nullptr;
    bool allocate = false;

    while (true) {
        allocate_seg = nullptr;
        allocate = false;
        {
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
            LOGTRACEMOD(varsize_blk_alloc, "Fill cache for segment");
            fill_cache(allocate_seg);
            {
                // acquire lock
                std::unique_lock< std::mutex > lk(m_mutex);
                m_wait_alloc_segment = nullptr;
                m_region_state = BLK_ALLOCATOR_DONE;
                m_cv.notify_all();
            }
           LOGTRACEMOD(varsize_blk_alloc, "Done with fill cache for segment");
        }
    }
}

#define MAX_RETRY_CNT 1000

bool
VarsizeBlkAllocator::is_blk_alloced(BlkId &b) {
    return(m_alloced_bm->is_bits_set_reset(b.get_id(), b.get_nblks(), true));
}

BlkAllocStatus 
VarsizeBlkAllocator::alloc(BlkId &in_bid) {
    m_alloced_bm->set_bits(in_bid.get_id(), in_bid.get_nblks());
    m_alloc_bm->set_bits(in_bid.get_id(), in_bid.get_nblks());
    return BLK_ALLOC_SUCCESS;
}

void 
VarsizeBlkAllocator::inited() {
    if (!m_init) {
        m_thread_id = std::thread(thread_func, this);
    }
    m_init = true;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(uint8_t nblks, 
                   const blk_alloc_hints &hints, std::vector<BlkId> &out_blkid) {
    uint8_t blks_alloced = 0;
    int retry_cnt = 0;

    uint8_t blks_rqstd = nblks;

    assert(m_init);

    assert(nblks % hints.multiplier == 0);

#ifndef NDEBUG
    if (!hints.is_contiguous && nblks  != 1) {
        blks_rqstd = ALIGN_SIZE((nblks / 2), hints.multiplier);
    }
#endif

    while (blks_alloced != nblks && retry_cnt < MAX_RETRY_CNT) {
        BlkId blkid;
        
        if (alloc(blks_rqstd, hints, &blkid, true) != BLK_ALLOC_SUCCESS) {
            /* It should never happen. It means we are running out of space */
            assert(0);
        }
        blks_alloced += blkid.get_nblks();
        assert(blks_alloced % hints.multiplier == 0);

        blks_rqstd = nblks - blks_alloced;
        out_blkid.push_back(blkid);
        retry_cnt++;
    }
#ifndef NDEBUG
    if(blks_alloced != nblks)
        LOGERRORMOD(varsize_blk_alloc, "blks_alloced != nblks : {}  {}",blks_alloced, nblks);
#endif
    assert(blks_alloced == nblks);
    if (blks_alloced != nblks) {
        assert(blks_alloced < nblks);
        /* free blks */
        for (auto it = out_blkid.begin(); it != out_blkid.end(); ++it) {
            free(*it);
            it = out_blkid.erase(it);
        }
        return BLK_ALLOC_SPACEFULL;
    }
    return BLK_ALLOC_SUCCESS;
}

BlkAllocStatus VarsizeBlkAllocator::alloc(uint8_t nblks, const blk_alloc_hints &hints, BlkId *out_blkid, 
                                            bool best_fit) {
    BlkAllocStatus ret = BLK_ALLOC_SUCCESS;
    bool found = false;

    // TODO: Instead of given value, try to have leeway like 10% of both sides as range for desired_temp or bkt.
    VarsizeAllocCacheEntry start_entry(BLKID_RANGE_FIRST, PAGEID_RANGE_FIRST, nblks, hints.desired_temp);
    VarsizeAllocCacheEntry end_entry(BLKID_RANGE_LAST, PAGEID_RANGE_LAST, BLKCOUNT_RANGE_LAST, TEMP_RANGE_LAST);
    VarsizeAllocCacheEntry actual_entry;

    homeds::btree::BtreeSearchRange regex(start_entry, true, /* start_incl */ end_entry, false, /* end incl */
                                        (best_fit ? 
                                         homeds::btree::_MultiMatchSelector::BEST_FIT_TO_CLOSEST :
                                         homeds::btree::_MultiMatchSelector::SECOND_TO_THE_LEFT));
    
    homeds::btree::EmptyClass dummy_val;
    int attempt = 1;
    while (true) {
        found = m_blk_cache->remove_any(regex, &actual_entry, &dummy_val);
        if (found) {
            if (best_fit) {
                if (actual_entry.get_blk_count() < hints.multiplier) {
                    /* it should be atleast equal to hints multiplier. If not then wait for cache to populate */
                    VarsizeAllocCacheEntry excess_entry;
                    homeds::btree::EmptyClass dummy;
                    uint64_t blknum = actual_entry.get_blk_num();
                    gen_cache_entry(blknum, actual_entry.get_blk_count(), &excess_entry);
                    m_blk_cache->put(excess_entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
                } else {
                    /* trigger blk allocator to populate cache */
                    if (actual_entry.get_blk_count() != nblks) {
                        request_more_blks(nullptr);
                    }
                    break;
                }
            } else {
                break;
            }
        }

        // Wait for cache to refill and then retry original request
        if (attempt > MAX_BLK_ALLOC_ATTEMPT) {
            LOGTRACEMOD(varsize_blk_alloc, "Exceeding max retries {} to allocate. Failing the alloc", 
                        MAX_BLK_ALLOC_ATTEMPT);
            for (auto i = 0U; i < m_slab_entries.size(); i++) {
                LOGTRACEMOD(varsize_blk_alloc, "Capacity of slab {} = {}", i, 
                            m_slab_entries[i]._a.load(std::memory_order_acq_rel));
            }
            break;
        } else {
            LOGTRACEMOD(varsize_blk_alloc, 
                        "Attempt #{} to allocate nblks={} temperature={} failed. Waiting for cache to be filled",
                    attempt, (uint32_t)nblks, hints.desired_temp);
        }

        request_more_blks_wait(nullptr);
        attempt++;
    }

    if (!found) {
        return BLK_ALLOC_SPACEFULL;
    }

    /* get excess blks */
    int excess_nblks = actual_entry.get_blk_count() - nblks;
    if (excess_nblks < 0) {
        assert(best_fit);
        /* it has to be multiplier of hints */
        excess_nblks = actual_entry.get_blk_count() % hints.multiplier;
    }
    assert(excess_nblks >= 0);

    auto slab_index = get_config().get_slab(actual_entry.get_blk_count()).first;
    m_slab_entries[slab_index]._a.fetch_sub(actual_entry.get_blk_count(),
                                                    std::memory_order_acq_rel);

    /* If we have more blks than what we need, insert the remaining blks to
       the bitmap. We can give either the leading blocks or trailing blocks.
       In case one of them is part of less number of pages than others, it
       is better to pick the lesser ones.
     */
    uint64_t alloc_blks = actual_entry.get_blk_count() - excess_nblks;
    if (excess_nblks > 0) {
        uint64_t blknum = actual_entry.get_blk_num();
        int leading_npages =
            (int)(blknum_to_phys_pageid(blknum + alloc_blks) - actual_entry.get_phys_page_id());
        int trailing_npages =
            (int)(blknum_to_phys_pageid(blknum + actual_entry.get_blk_count()) -
                                        blknum_to_phys_pageid(blknum + excess_nblks));

        VarsizeAllocCacheEntry excess_entry;
        if (leading_npages <= trailing_npages) {
            out_blkid->set(blknum, alloc_blks);
            gen_cache_entry(blknum + alloc_blks, (uint32_t)excess_nblks, &excess_entry);
        } else {
            out_blkid->set(blknum + excess_nblks, alloc_blks);
            gen_cache_entry(blknum, (uint32_t)excess_nblks, &excess_entry);
        }
        homeds::btree::EmptyClass dummy;
        m_blk_cache->put(excess_entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);

        auto slab_index = get_config().get_slab(excess_nblks).first;
        m_slab_entries[slab_index]._a.fetch_add(excess_nblks, std::memory_order_acq_rel);

    } else {
        out_blkid->set(actual_entry.get_blk_num(), alloc_blks);
    }

#ifndef NDEBUG
    BlkAllocPortion *portion = blknum_to_portion(out_blkid->get_id());
    portion->lock();
    m_alloced_bm->set_bits(out_blkid->get_id(), out_blkid->get_nblks());
    portion->unlock();
#endif

    m_cache_n_entries.fetch_sub(alloc_blks, std::memory_order_acq_rel);
    return ret;
}

void VarsizeBlkAllocator::free(const BlkId &b) {
    BlkAllocPortion *portion = blknum_to_portion(b.get_id());
    BlkAllocSegment *segment = blknum_to_segment(b.get_id());

    // Reset the bits
    portion->lock();
    assert(m_alloc_bm->is_bits_set_reset(b.get_id(), b.get_nblks(), true));
#ifndef NDEBUG
    assert(m_alloced_bm->is_bits_set_reset(b.get_id(), b.get_nblks(), true));
    m_alloced_bm->reset_bits(b.get_id(), b.get_nblks());
#endif
    m_alloc_bm->reset_bits(b.get_id(), b.get_nblks());
    portion->unlock();

    //std::cout << "Resetting " << p.get_blk_id() << " for nblks = " << nblks << " Bitmap state= \n";
    //m_alloc_bm->print();
}

// This runs on per region thread and is at present single threaded.
void VarsizeBlkAllocator::fill_cache(BlkAllocSegment *seg) {
    uint64_t nadded_blks = 0;
    if (!seg) {
        auto max_free_blks = m_segments[0]->get_free_blks();
        seg = m_segments[0];
        for (auto i = 1U; i < m_segments.size(); i++) {
    std::atomic<uint8_t> m_refcnt; 
            auto free_blks = m_segments[i]->get_free_blks();
            if (free_blks > max_free_blks) {
                seg = m_segments[i];
                max_free_blks = free_blks;
            }
        }
       LOGTRACEMOD(varsize_blk_alloc, "Seg was not allocated. So segment chosen");
    }

    /* While cache is not full */
    uint64_t start_portion_num = seg->get_clock_hand();
    while (m_cache_n_entries.load(std::memory_order_acquire) <
                get_config().get_max_cache_blks()) {

        bool refill_needed = false;
        auto sum = 0U;
        for (auto i = 0U; i < m_slab_entries.size(); i++) {
            // Low water mark for cache slabs is half of full capacity
            auto count = m_slab_entries[i]._a.load(std::memory_order_acq_rel);
            sum += count;
            if (count && count <= get_config().get_slab_capacity(i)/2) {
                LOGTRACEMOD(varsize_blk_alloc, "Hit low water mark for slab {} capacity = {}",
                    i, m_slab_entries[i]._a.load(std::memory_order_acq_rel));
                refill_needed = true;
                break;
            }
        }
        if (!refill_needed && sum) break; // Atleast one slab has sufficient blocks

        LOGTRACEMOD(varsize_blk_alloc, "Refill cache");
        uint64_t portion_num = seg->get_clock_hand();
        nadded_blks += fill_cache_in_portion(portion_num, seg);

        // Goto next group within the segment.
        portion_num = (portion_num+1) % get_config().get_total_portions();
        seg->set_clock_hand(portion_num);

        if (portion_num == start_portion_num) {
            // Came one full circle, no need to look more.
            break;
        }
    }

    if (nadded_blks) {
        assert(seg->get_free_blks() >= nadded_blks);
        seg->remove_free_blks(nadded_blks);
        LOGTRACEMOD(varsize_blk_alloc, "Bitset sweep thread added {} blks to blk cache", nadded_blks);
    } else {
        LOGTRACEMOD(varsize_blk_alloc, "Bitset sweep failed to add any blocks to blk cache");
    }
}

uint64_t VarsizeBlkAllocator::fill_cache_in_portion(uint64_t portion_num, BlkAllocSegment *seg) {
    homeds::btree::EmptyClass dummy;
    uint64_t n_added_blks = 0;

    BlkAllocPortion &portion = m_blk_portions[portion_num];
    auto num_blks_per_portion = get_config().get_blks_per_portion();
    auto cur_blk_id = portion_num * num_blks_per_portion;
    auto end_blk_id = cur_blk_id + num_blks_per_portion;
    uint32_t num_blks_per_phys_page = get_config().get_blks_per_phys_page();

    portion.lock();
    /* TODO: Consider caching the m_cache_n_entries and give some leeway
     *       to max cache blks and thus avoid atomic operations
     */
    while ((m_cache_n_entries.load(std::memory_order_acq_rel) <
                get_config().get_max_cache_blks()) && (cur_blk_id < end_blk_id)) {

        // Get next reset bits and insert to cache and then reset those bits
        auto b = m_alloc_bm->get_next_contiguous_reset_bits(cur_blk_id);
        assert(b.nbits <= MAX_NBLKS);

        /* If there are no free blocks are none within the assigned portion */
        if (!b.nbits || b.start_bit >= end_blk_id) {
            break;
        }

        /* Limit cache update to within portion boundary */
        if (b.start_bit + b.nbits > end_blk_id) {
            b.nbits = end_blk_id - b.start_bit;
        }

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
                assert(m_alloc_bm->is_bits_set_reset(b.start_bit, nbits, false));
                assert(m_alloced_bm->is_bits_set_reset(b.start_bit, nbits,false));
#endif
                m_blk_cache->put(entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
                // TODO: Trap the return status of insert
                m_alloc_bm->set_bits(b.start_bit, nbits);
                total_bits += nbits;
                m_slab_entries[slab_index]._a.fetch_add(nbits, std::memory_order_acq_rel);
                LOGTRACEMOD(varsize_blk_alloc, "Freed {} blocks for slab {}, remaining slab capacity = {}",
                    nbits, slab_index,
                    m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            } else {
                LOGTRACEMOD(varsize_blk_alloc ,"Slab {} is full, capacity = {}", slab_index,
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
            assert(b.start_bit % num_blks_per_phys_page == 0);
            auto start = cur_blk_id - nbits;
            auto slab_index = get_config().get_slab(nbits).first;
            if (m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel) <
                                        get_config().get_slab_capacity(slab_index)) {
                VarsizeAllocCacheEntry entry;
                gen_cache_entry(start, nbits, &entry);
#ifndef NDEBUG
                assert(m_alloc_bm->is_bits_set_reset(start, nbits, false));
                assert(m_alloced_bm->is_bits_set_reset(start, nbits,false));
#endif
                m_blk_cache->put(entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
                // TODO: Trap the return status of insert
                m_alloc_bm->set_bits(start, nbits);
                total_bits += nbits;
                m_slab_entries[slab_index]._a.fetch_add(nbits, std::memory_order_acq_rel);
                LOGTRACEMOD(varsize_blk_alloc, "Freed {} blocks for slab {}, remaining slab capacity = {}",
                    nbits, slab_index,
                    m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            } else {
                LOGTRACEMOD(varsize_blk_alloc, "Slab {} is full, capacity = {}", slab_index,
                    m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            }
            b.nbits -= nbits;
        }

        /* Create cache entry for complete pages between start and end */
        if (b.nbits) {
            /* If code enters this section, it means that start is aligned to a page
               boundary and nbits left is a multiple of page size
             */
            assert(b.start_bit % num_blks_per_phys_page == 0);
            assert(b.nbits % num_blks_per_phys_page == 0);
            auto slab_index = get_config().get_slab(b.nbits).first;
            if (m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel) <
                                        get_config().get_slab_capacity(slab_index)) {
                VarsizeAllocCacheEntry entry;
                gen_cache_entry(b.start_bit, b.nbits, &entry);
#ifndef NDEBUG
                assert(m_alloc_bm->is_bits_set_reset(b.start_bit, b.nbits, false));
                assert(m_alloced_bm->is_bits_set_reset(b.start_bit, b.nbits,false));
#endif
                m_blk_cache->put(entry, dummy, homeds::btree::INSERT_ONLY_IF_NOT_EXISTS);
                // TODO: Trap the return status of insert
                m_alloc_bm->set_bits(b.start_bit, b.nbits);
                total_bits += b.nbits;
                m_slab_entries[slab_index]._a.fetch_add(b.nbits, std::memory_order_acq_rel);
                LOGTRACEMOD(varsize_blk_alloc, "Freed {} blocks for slab {}, remaining slab capacity = {}",
                    b.nbits, slab_index,
                    m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            } else {
                LOGTRACEMOD(varsize_blk_alloc, "Slab {} is full, capacity = {}", slab_index,
                    m_slab_entries[slab_index]._a.load(std::memory_order_acq_rel));
            }
        }

        // Update the counters
        n_added_blks += total_bits;
        m_cache_n_entries.fetch_add(total_bits, std::memory_order_acq_rel);
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
    assert(!seg);
    if (m_region_state == BLK_ALLOCATOR_DONE) {
            m_wait_alloc_segment = seg;
            m_region_state = BLK_ALLOCATOR_WAIT_ALLOC;
            m_cv.notify_all();
    }
    // Wait for notification that it is done
    while (m_region_state != BLK_ALLOCATOR_DONE) {
        m_cv.wait(lk);
    }
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
} //namespace homestore
