/*
 * dymanic_blk_allocator.cpp
 *
 *  Created on: Jun 17, 2015
 *      Author: Hari Kadayam
 */

#include "dynamic_blk_allocator.h"
#include <iostream>
#include <cassert>

namespace omstorage {

void thread_func(DynamicBlkAllocator *b) {
    b->allocator_state_machine();
}

DynamicBlkAllocator::DynamicBlkAllocator(BlkAllocConfig &cfg) :
        BlkAllocator(cfg) {
    // Initialize the state to done and start the thread
    m_region_state = BLK_ALLOCATOR_DONE;
    m_wait_alloc_segment = NULL;
    m_cache_entries.store(0);

    // Allocate 2 bitmaps. Every atom gets a bit in the bitmap.
    m_allocBm = new BitMapUnsafe(cfg.getTotalPages() * cfg.getAtomsPerPage());
    //m_cacheBm = new BitMapSafe(m_allocBm);
    m_cacheBm = new BitMapUnsafe(cfg.getTotalPages() * cfg.getAtomsPerPage());

    // Create blk entry table
    m_pg_entries = new DynamicPageAllocEntry[cfg.getTotalPages()];
    bzero(m_pg_entries, cfg.getTotalPages() * sizeof(DynamicPageAllocEntry));
#ifdef DEBUG
    for (uint64_t i = 0; i < cfg.getTotalPages(); i++) {
        m_pg_entries[i].m_pageid = i;
    }
#endif

    // Create blk group entry table.
    uint64_t nPageGroups = cfg.getTotalPages() / cfg.getPagesPerGroup();
    m_pg_grps = new PageAllocGroup[nPageGroups];
#ifdef DEBUG
    for (uint64_t i = 0; i < nPageGroups; i++) {
        m_pg_grps->m_pgGroupId = i;
    }
#endif

    // Create segments with as many blk groups as configured.
    uint64_t segSize = cfg.getTotalPages() / cfg.getTotalSegments() * cfg.getAtomsPerPage();
    for (uint64_t i = 0; i < cfg.getTotalSegments(); i++) {
        PageAllocSegment *seg = new PageAllocSegment(segSize, i);
        SegQueue::handle_type segId = m_heap_segments.push(seg);
        seg->set_segment_id(segId);
    }

    // Create the store to cache temperature, freeblks within page etc.
    BtreeConfig btreeCfg;
    btreeCfg.setLeafNodeType(BTREE_NODETYPE_SIMPLE);
    btreeCfg.setInteriorNodeType(BTREE_NODETYPE_SIMPLE);
    btreeCfg.setMaxObjs(cfg.getMaxCachePages());
    btreeCfg.setMaxKeySize(sizeof(DynamicPageAllocCacheEntry));
    btreeCfg.setMaxValueSize(0);
    m_blk_cache = new MemBtreeKVStore< DynamicPageAllocCacheEntry, EmptyClass >(btreeCfg);

    //m_thread_id = std::thread(&BlkRegion::BlkRegionThreadFunc);
    // Start a trhead which will do sweeping job of free segments
    m_thread_id = std::thread(thread_func, this);
}

std::thread *DynamicBlkAllocator::get_thread() {
    return &m_thread_id;
}

DynamicBlkAllocator::~DynamicBlkAllocator() {
    {
        std::unique_lock< std::mutex > lk(m_mutex);
        if (m_region_state != BLK_ALLOCATOR_EXITING) {
            m_region_state = BLK_ALLOCATOR_EXITING;
        }
    }

    m_cv.notify_all();
    m_thread_id.join();
}

// Runs only in per region thread. In other words, this
// is a single threaded state machine.
void DynamicBlkAllocator::allocator_state_machine() {
    PageAllocSegment *allocateSeg = NULL;
    bool allocate;

    fprintf(stderr, "Starting new blk region thread\n");
    while (true) {
        allocateSeg = NULL;
        allocate = false;
        {
            // acquire lock
            std::unique_lock< std::mutex > lk(m_mutex);

            if (m_region_state == BLK_ALLOCATOR_DONE) {
                m_cv.wait(lk);
            }

            if (m_region_state == BLK_ALLOCATOR_WAIT_ALLOC) {
                m_region_state = BLK_ALLOCATOR_ALLOCATING;
                allocateSeg = m_wait_alloc_segment;
                allocate = true;
            } else if (m_region_state == BLK_ALLOCATOR_EXITING) {
                // TODO: Handle exiting message more periodically.
                break;
            }
        }

        if (allocate) {
            fill_cache(allocateSeg);
            {
                // acquire lock
                std::unique_lock< std::mutex > lk(m_mutex);
                m_wait_alloc_segment = NULL;
                m_region_state = BLK_ALLOCATOR_DONE;
            }
            m_cv.notify_all();
        }
    }
}

BlkAllocStatus DynamicBlkAllocator::alloc(uint32_t size, uint32_t desired_temp, Blk *out_blk) {
    uint32_t nAtoms = (size - 1) / m_cfg.getAtomSize() + 1;
    BlkAllocStatus ret = BLK_ALLOC_SUCCESS;
    bool found = false;

    // TODO: Instead of given value, try to have leeway like 10% of both sides as range for desired_temp or bkt.
    uint32_t reqBkt = max(nAtoms, desired_temp % (m_cfg.getAtomsPerPage()));
    DynamicPageAllocCacheEntry startEntry(reqBkt, nAtoms, desired_temp, 0);
    DynamicPageAllocCacheEntry endEntry(RANGE_LAST, RANGE_LAST, RANGE_LAST, RANGE_LAST);
    DynamicPageAllocCacheEntry actualEntry;

    int miss = 0;
    while (1) {
        found = m_blk_cache->removeAny(startEntry, true /*startIncl*/, endEntry, false /*endIncl*/, &actualEntry);
        if (found) {
            break;
        }

        miss++;
        if ((miss == 1) || (miss == 3)) {
            // Unable to find anything in the range, expand the range.
            // Do this at first miss or 3rd miss (which is after request for more pieces.
            // TODO: Consider slowly expanding the range, instead of getting first available.
            startEntry.setFreeAtomsCount(0);
        } else if (miss == 2) {
            // Wait for cache to refill and then retry original request.
            requestMorePagesWait(NULL);
            startEntry.setFreeAtomsCount(reqBkt);
        } else {
            // retried enough times. report space not available.
            break;
        }
    }

    if (!found) {
        return BLK_ALLOC_SPACEFULL;
    }

    // Get the bitmap for the pages.
    uint32_t nPages = (actualEntry.getMaxContigousFreeAtoms() - 1) / m_cfg.getAtomsPerPage() + 1;
    uint64_t pageId = actualEntry.getPageId();
    BitStats bitStats;

    PageAllocGroup *pggrp = pageid_to_group(pageId);
    pggrp->lock();
    m_allocBm->getResetBitStats(pageId * m_cfg.getAtomsPerPage(),
                                (nPages * m_cfg.getAtomsPerPage()), &bitStats);
    pggrp->unlock();

    uint32_t atomSize = m_cfg.getAtomSize();
    for (auto iter = bitStats.vectReset.begin(); iter != bitStats.vectReset.end(); iter++) {
        bitgrp_details_t bg = *iter;
        out_blk->addPiece(pageId, bg.bit * atomSize, bg.nBits * atomSize);
    }
    m_cache_entries -= nPages;
    return ret;
}

#if 0
BlkAllocStatus DynamicBlkAllocator::allocBlkSeries(uint32_t minBlks, uint32_t desiredTemp, BlkSeries *blkSeries)
{
    BlkAllocStatus ret = BLK_ALLOC_SUCCESS;
    bool found = false;

    // TODO: Instead of given value, try to have leeway like 10% of both sides
    // as range for desiredTemp or bkt.
    uint32_t reqBkt = max(minBlks, desiredTemp % (m_cfg.getAtomsPerPage()));
    DynamicPageAllocCacheEntry startEntry(reqBkt, minBlks, desiredTemp, 0);
    DynamicPageAllocCacheEntry endEntry(RANGE_LAST, RANGE_LAST, RANGE_LAST, RANGE_LAST);
    DynamicPageAllocCacheEntry actualEntry;

    int miss = 0;
    while (1) {
        found = m_blk_cache->removeAny(startEntry, true /*startIncl*/, endEntry, false /*endIncl*/, &actualEntry);
        if (found) {
            break;
        }

        miss++;
        if ((miss == 1) || (miss == 3)) {
            // Unable to find anything in the range, expand the range.
            // Do this at first miss or 3rd miss (which is after request for more blks
            // TODO: Consider slowly expanding the range, instead of getting first available.
            startEntry.setFreeAtomsCount(0);
        } else if (miss == 2) {
            // Wait for cache to refill and then retry original request.
            requestMorePagesWait(NULL);
            startEntry.setFreeAtomsCount(reqBkt);
        } else {
            // retried enough times. report space not available.
            break;
        }
    }

    if (!found) {
        return BLK_ALLOC_SPACEFULL;
    }

    // Get the bitmap for the page.
    uint32_t nPages = (actualEntry.getMaxContigousFreeAtoms() - 1) / m_cfg.getAtomsPerPage() + 1;
    uint64_t pgNum = actualEntry.getPageId();

    PageAllocGroup *pgGrp = pageid_to_group(pgNum);
    pgGrp->lock();
    blkSeries->generate(m_allocBm, blkNumToPieceNum(pgNum), (nPages * m_cfg.getAtomsPerPage()),
                        false /* clone bit map */);
    pgGrp->unlock();

    m_cache_entries -= nPages;
    return ret;
}
#endif

void DynamicBlkAllocator::free(Blk &b) {
    for (auto i = 0; i < b.getPieces(); i++) {
        PageAllocGroup *pggrp = pageid_to_group(b.getPageId(i));
        pggrp->lock();

        uint64_t pgid = b.getPageId(i);
        uint64_t startBit = pageid_to_bit(pgid, b.getOffset(i));
        uint32_t nBits = size_to_nbits(b.getSize(i));

        if ((b.getSize(i) % m_cfg.getPageSize()) == 0) {
            assert(b.getOffset(i) == 0);
        } else {
            assert(nBits < m_cfg.getAtomSize());

            BitStats bitStats;
            DynamicPageAllocEntry *pgEntry = get_page_entry(pgid);

            // Get the first bit for this blk
            uint64_t pageStartBit = pageid_to_bit(pgid, 0);
            m_cacheBm->getResetBitStats(pageStartBit, m_cfg.getAtomsPerPage(), &bitStats);

            // We need to get the pieces neighbor and update the cache
            // with correct details or remove those entries altogether.
            DynamicPageAllocCacheEntry cacheEntry(bitStats.nResetBitsCount,
                                      bitStats.nMaxContigousResetCount,
                                      pgEntry->get_temperature(),
                                      pgid);
            bool found = m_blk_cache->remove(cacheEntry);
            if (!found) {
                cout << "Looks like cache bitmap is not in sync with "
                     << " cache btree. Its possible only if multiple threads "
                     << " are freeing on same blk (" << pgid
                     << ")" << endl;
            }
        }

        assert(m_cacheBm->isMultiBitSet(startBit, nBits));
        assert(m_allocBm->isMultiBitSet(startBit, nBits));
        m_cacheBm->resetMultiBit(startBit, nBits);
        m_allocBm->resetMultiBit(startBit, nBits);
        pggrp->unlock();
    }
}

#if 0
void DynamicBlkAllocator::freeBlks(uint64_t blkNum, uint32_t nBlks)
{
    BlkSeries blkSeries(getConfig());

    PageAllocGroup *pgGrp = pageid_to_group(blkNum);
    pgGrp->lock();

    if ( (nBlks % m_cfg.getAtomsPerPage()) == 0) {
        assert( (blkNum % m_cfg.getAtomsPerPage()) == 0);
    } else {
        assert(nBlks <= m_cfg.getAtomsPerPage());

        uint64_t pageNum = blkNumToPageNum(blkNum);
        DynamicPageAllocEntry *pgEntry = getPageEntry(pageNum);
        uint64_t startBlkNum = pageNum * m_cfg.getAtomsPerPage();

        // We need to get the blks neighbor and update the cache
        // with correct details or remove those entries altogether.
        // Create a blkSeries out of the existing cache bitmap for the
        // page which has the blk about to be freed.
        blkSeries.generate(m_cacheBm, startBlkNum, m_cfg.getAtomsPerPage(), false /* cloneBitMap */);

        assert(blkSeries.getFreeBlksCount() != m_cfg.getAtomsPerPage());

        // Create a cache entry with its current neighbor state and
        // remove corresponding cache entry.
        DynamicPageAllocCacheEntry cacheEntry(blkSeries.getFreeBlksCount(), blkSeries.getMaxContigousBlkCount(),
                                  pgEntry->getTemperature(), pageNum);
        bool found = m_blk_cache->remove(cacheEntry);
        if (!found) {
            cout << "Looks like cache bitmap is not in sync with "
                 << " cache btree. Its possible only if multiple threads " << " are freeing on same blk (" << blkNum
                 << ")" << endl;
        }
    }

    assert(m_cacheBm->isMultiBitSet(blkNum, nBlks));
    assert(m_allocBm->isMultiBitSet(blkNum, nBlks));
    m_cacheBm->resetMultiBit(blkNum, nBlks);
    m_allocBm->resetMultiBit(blkNum, nBlks);
    pgGrp->unlock();
}

void DynamicBlkAllocator::commitBlks(uint64_t blkNum, uint32_t nBlks)
{
    PageAllocGroup *pgGrp = pageid_to_group(blkNum);
    pgGrp->lock();

    // Cache is expected to be set and persistent bitmap should be unset
    assert(m_cacheBm->isMultiBitSet(blkNum, nBlks));
    assert(!m_allocBm->isMultiBitSet(blkNum, nBlks));

    m_allocBm->setMultiBit(blkNum, nBlks);
    pgGrp->unlock();
}
#endif

void DynamicBlkAllocator::commit(Blk &b) {
    for (auto i = 0; i < b.getPieces(); i++) {
        PageAllocGroup *pggrp = pageid_to_group(b.getPageId(i));
        uint64_t startBit = pageid_to_bit(b.getPageId(i), b.getOffset(i));
        uint32_t nBits = size_to_nbits(b.getSize(i));

        pggrp->lock();
        // Cache is expected to be set and persistent bitmap should be unset
        assert(m_cacheBm->isMultiBitSet(startBit, nBits));
        assert(!m_allocBm->isMultiBitSet(startBit, nBits));

        m_allocBm->setMultiBit(startBit, nBits);
        pggrp->unlock();
    }
}

// This runs on per region thread and is at present single threaded.
void DynamicBlkAllocator::fill_cache(PageAllocSegment *seg) {
    uint64_t nAddedAtoms = 0;
    if (seg == NULL) {
        seg = m_heap_segments.top();
    }

    uint32_t grpsPerSeg = m_cfg.getTotalGroups() / m_cfg.getTotalSegments();

    uint64_t startGrpNum = seg->get_clock_hand();
    while (m_cache_entries < m_cfg.getMaxCachePages()) {
        uint64_t grpNum = seg->get_clock_hand();
        nAddedAtoms += fill_cache_in_group(grpNum, seg);

        // Goto next group within the segment.
        grpNum = (grpNum == (grpsPerSeg - 1)) ? 0 : grpNum + 1;
        seg->set_clock_hand(grpNum);

        if (grpNum == startGrpNum) {
            // Came one full circle, no need to look more.
            break;
        }
    }
    seg->set_free_atoms(seg->get_free_atoms() - nAddedAtoms);
    m_heap_segments.update(seg->get_segment_id(), seg);
}

uint64_t DynamicBlkAllocator::fill_cache_in_group(uint64_t grp_num, PageAllocSegment *seg) {
    DynamicPageAllocCacheEntry cEntry;
    EmptyClass dummy;
    bool entryValid = false;
    uint64_t addedAtoms = 0;

    PageAllocGroup *pggrp = get_page_group(grp_num);
    pggrp->lock();

    uint64_t curPageId = grp_num * m_cfg.getPagesPerGroup();
    uint64_t endPageId = curPageId + m_cfg.getPagesPerGroup();

    // Walk through every page until we either reach end of the pagegroup or until satisfied with number of cache entries.
    while ((m_cache_entries < m_cfg.getMaxCachePages()) && (curPageId < endPageId)) {
        uint64_t startBit = pageid_to_bit(curPageId, 0);
        uint64_t nBits = size_to_nbits(m_cfg.getPageSize());

        // Find out how many bits are free.
        BitStats bitStats;
        m_cacheBm->getResetBitStats(startBit, nBits, &bitStats);

        if (bitStats.nResetBitsCount > 0) {
            if (bitStats.nResetBitsCount < m_cfg.getAtomsPerPage()) {
                // If not all bits in a blk is not free, write the previous entry
                if (entryValid == true) {
                    // Previous entry is valid. Write it to cache before updating current entry.
                    m_blk_cache->insert(cEntry, dummy);
                    m_cache_entries++;
                    addedAtoms += cEntry.getFreeAtomsCount();
                }

                // Create a new entry
                cEntry.setFreeAtomsCount(bitStats.nResetBitsCount);
                cEntry.setMaxContigousFreeAtoms(bitStats.nMaxContigousResetCount);
                cEntry.setPageId(curPageId);
                cEntry.setTemperature(get_page_entry(curPageId)->get_temperature());
                m_blk_cache->insert(cEntry, dummy);
                m_cache_entries++;
                addedAtoms += cEntry.getFreeAtomsCount();

                entryValid = false;
            } else {
                // If all atoms in a page are free
                if (entryValid == true) {
                    // If we are already have an entry, maintain the same page
                    cEntry.setFreeAtomsCount(cEntry.getFreeAtomsCount() + bitStats.nResetBitsCount);
                    cEntry.setMaxContigousFreeAtoms(cEntry.getMaxContigousFreeAtoms() + bitStats.nResetBitsCount);
                } else {
                    cEntry.setFreeAtomsCount(bitStats.nResetBitsCount);
                    cEntry.setMaxContigousFreeAtoms(bitStats.nResetBitsCount);
                    cEntry.setPageId(curPageId);
                    cEntry.setTemperature(get_page_entry(curPageId)->get_temperature());
                    entryValid = true;
                }
            }
            m_cacheBm->setMultiBit(startBit, nBits);
        }
        curPageId++;
    }

    if (entryValid == true) {
        m_blk_cache->insert(cEntry, dummy);
        m_cache_entries++;
        addedAtoms += cEntry.getFreeAtomsCount();
    }
    pggrp->unlock();

    return addedAtoms;
}

#if 0
// This runs on per region thread and is at present single threaded.
void DynamicBlkAllocator::fillCache(PageAllocSegment *seg)
{
    uint64_t nAddedBlks = 0;
    if (seg == NULL) {
        seg = m_heap_segments.top();
    }

    uint32_t grpsPerSeg = m_cfg.getTotalGroups() / m_cfg.getTotalSegments();

    uint64_t startGrpNum = seg->getClockHand();
    while (m_cache_entries < m_cfg.getMaxCachePages()) {
        uint64_t grpNum = seg->getClockHand();
        nAddedBlks += fillCacheInGroup(grpNum, seg);

        // Goto next group within the segment.
        grpNum = (grpNum == (grpsPerSeg - 1)) ? 0 : grpNum + 1;
        seg->setClockHand(grpNum);

        if (grpNum == startGrpNum) {
            // Came one full circle, no need to look more.
            break;
        }
    }
    seg->setFreeAtoms(seg->getFreeAtoms() - nAddedBlks);
    m_heap_segments.update(seg->getSegmentId(), seg);
}

uint64_t DynamicBlkAllocator::fillCacheInGroup(uint64_t grpNum, PageAllocSegment *seg)
{
    DynamicPageAllocCacheEntry cEntry;
    EmptyClass dummy;
    bool entryValid = false;
    uint64_t addedBlks = 0;

    PageAllocGroup *pgGrp = getPageGroup(grpNum);
    uint64_t b = grpNum * m_cfg.getPagesPerGroup() * m_cfg.getAtomsPerPage();
    uint64_t pgNum = blkNumToPageNum(b);
    uint64_t endPgNum = pgNum + m_cfg.getPagesPerGroup();

    // First lock the page group and start sweeping one by one.
    pgGrp->lock();
    while ( (m_cache_entries < m_cfg.getMaxCachePages()) && (pgNum < endPgNum)) {
        uint32_t nFreeBlks = 0;
        uint32_t contigousFreeBlks = 0;
        uint32_t maxContigousFreeBlks = 0;

        // get all the free blocks in a page
        do {
            // TODO: Optimize cases where entire page is free or
            // entire page is busy. Use BlkSeries to optimize this.
            if (canAllocBlock(b)) {
                setCacheUsed(b, 1);
                nFreeBlks++;
                contigousFreeBlks++;
            } else {
                if (contigousFreeBlks > maxContigousFreeBlks) {
                    maxContigousFreeBlks = contigousFreeBlks;
                }
                contigousFreeBlks = 0;
            }
            b++;
        } while (b % m_cfg.getAtomsPerPage());

        if (nFreeBlks < m_cfg.getAtomsPerPage()) {
            // If not all blks in a page is not free, write the entry
            if (entryValid == true) {
                // Previous entry is valid. Write it to cache before updating current entry.
                m_blk_cache->insert(cEntry, dummy);
                m_cache_entries++;
                addedBlks += cEntry.getFreeAtomsCount();
            }

            // Create a new entry
            cEntry.setFreeAtomsCount(nFreeBlks);
            cEntry.setMaxContigousFreePieces(maxContigousFreeBlks);
            cEntry.setPageId(pgNum);
            cEntry.setTemperature(getPageEntry(pgNum)->getTemperature());
            m_blk_cache->insert(cEntry, dummy);
            m_cache_entries++;
            addedBlks += cEntry.getFreeAtomsCount();

            entryValid = false;
        } else {
            // If all blks in a page are free
            if (entryValid == true) {
                // If we are already have an entry, maintain the same page
                cEntry.setFreeAtomsCount(cEntry.getFreeAtomsCount() + nFreeBlks);
                cEntry.setMaxContigousFreePieces(cEntry.getMaxContigousFreeAtoms() + nFreeBlks);
            } else {
                cEntry.setFreeAtomsCount(nFreeBlks);
                cEntry.setMaxContigousFreePieces(nFreeBlks);
                cEntry.setPageId(pgNum);
                cEntry.setTemperature(getPageEntry(pgNum)->getTemperature());
                entryValid = true;
            }
        }
        pgNum++;
    }

    if (entryValid == true) {
        m_blk_cache->insert(cEntry, dummy);
        m_cache_entries++;
        addedBlks += cEntry.getFreeAtomsCount();
    }
    pgGrp->unlock();

    return addedBlks;
}

bool DynamicBlkAllocator::canAllocBlock(uint64_t b)
{
    //	return (m_allocBm->isBitSet(b) && m_cacheBm->isBitSet(b));
    return (!m_cacheBm->isBitSet(b));
}

void DynamicBlkAllocator::setCacheUsed(uint64_t startBlk, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        m_cacheBm->setBit(startBlk + i);
    }
}

void DynamicBlkAllocator::setBlksUsed(uint32_t startBlk, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        m_allocBm->setBit(startBlk + i);
    }
}

void DynamicBlkAllocator::setBlksFreed(uint32_t startBlk, uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        m_allocBm->resetBit(startBlk + i);
        m_cacheBm->resetBit(startBlk + i);
    }
}
#endif

inline uint32_t DynamicBlkAllocator::pageid_to_groupid(uint64_t pgid) {
    return pgid / m_cfg.getTotalGroups();
}

PageAllocGroup *DynamicBlkAllocator::pageid_to_group(uint64_t pgid) {
    return (&m_pg_grps[pageid_to_groupid(pgid)]);
}

PageAllocGroup *DynamicBlkAllocator::get_page_group(uint64_t grp_num) {
    return &m_pg_grps[grp_num];
}

DynamicPageAllocEntry *DynamicBlkAllocator::get_page_entry(uint64_t pgid) {
    return &m_pg_entries[pgid];
}

inline uint64_t DynamicBlkAllocator::page_id_to_atom(uint64_t pgid) {
    return (pgid * m_cfg.getAtomsPerPage());
}

// Run in non-region threads. It can be called by multiple threads simultaneously.
// Request for more blocks from a specified segment.
// If BlkSegment is NULL, then
// it picks the first segment to allocate from.
void DynamicBlkAllocator::request_more_pages(PageAllocSegment *seg) {
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

void DynamicBlkAllocator::requestMorePagesWait(PageAllocSegment *seg) {
    request_more_pages(seg);
    {
        // Wait for notification that it is done
        std::unique_lock< std::mutex > lk(m_mutex);
        m_cv.wait(lk);
    } // release lock
}

string DynamicBlkAllocator::state_string(BlkAllocatorState state) {
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

string DynamicBlkAllocator::to_string() {
    ostringstream oss;
    oss << "ThreadId=" << m_thread_id.get_id() << " RegionState=" << state_string(m_region_state) << endl;
    return oss.str();
}

} //namespace omstorage