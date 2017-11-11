/*
 * VirtualDev.cpp
 *
 *  Created on: 05-Aug-2016
 *      Author: hkadayam
 */

#include "BlkDev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include "BlkAllocator.h"
#include "FixedBlkAllocator.hpp"
#include "DynamicBlkAllocator.h"

namespace omstore {

#define MAX_IO_THREAD_BUF_SIZE 65536
static __thread char __buf[MAX_IO_THREAD_BUF_SIZE];

VirtualDev::VirtualDev(uint64_t size, uint32_t nmirror, bool is_stripe, uint32_t dev_blk_size,
                       std::vector< std::unique_ptr< PhysicalDev > > &phys_dev_list) {
    m_size = size;
    m_phys_dev_list = phys_dev_list;
    m_nmirrors = nmirror;
    m_total_allocations = 0;
    m_dev_page_size = dev_blk_size;

    assert(nmirror < phys_dev_list.size()); // Mirrors should be at least one less than device list.
    m_mirrorChunks = new vector< PhysicalDevChunk * >[nmirror];
    uint32_t nChunks;

    if (is_stripe) {
        m_chunkSize = ((m_size - 1) / m_physDevList.size()) + 1;
        nChunks = m_physDevList.size();
    } else {
        m_chunkSize = m_size;
        nChunks = 1;
    }

    for (
            uint32_t i = 0;
            i < nChunks;
            i++) {
        BlkAllocator *ba = createAllocator(m_chunkSize, dynamic_alloc);
        m_primaryChunks.
                push_back(createDevChunk(i, m_chunkSize, ba));

        uint32_t nextInd = i;
        for (
                uint32_t j = 0;
                j < nmirror;
                j++) {
            if ((++nextInd) == m_physDevList.

                    size()

                    ) {
                nextInd = 0;
            }
            m_mirrorChunks[j].
                    push_back(createDevChunk(nextInd, m_chunkSize, ba));
        }
    }

}

VirtualDev::~VirtualDev() {
    for (auto it = m_primaryChunks.begin(); it != m_primaryChunks.end(); it++) {
        // Free the allocator for this chunk
        PhysicalDevChunk *c = *it;
        delete (c->get_blk_allocator());
        c->set_blk_allocator(NULL);

        // Free the chunk itself
        delete (c);
    }

    for (int i = 0; i < m_nMirrors; i++) {
        for (auto it = m_mirrorChunks[i].begin(); it != m_mirrorChunks[i].end(); it++) {
            // Free the chunk. Allocator is already freed for primary chunk
            PhysicalDevChunk *c = *it;
            delete (c);
        }
    }
    delete (m_mirrorChunks);
}

BlkAllocator *VirtualDev::createAllocator(uint64_t size, bool isDynamicAlloc) {
    BlkAllocator *ba;

    if (isDynamicAlloc) {
        m_baCfg.setTotalPages((size - 1) / m_devPageSize + 1);
        m_baCfg.setTotalSegments(8); // 8 Segments per chunk
        m_baCfg.setAtomsPerPage(1);
        m_baCfg.setMaxCachePages(m_baCfg.getTotalPages() / 2); // Cache half of the blocks
        m_baCfg.setPagesPerGroup(128);
        ba = new DynamicBlkAllocator(m_baCfg);
    } else {
        m_baCfg.setTotalPages((size - 1) / m_devPageSize + 1);
        m_baCfg.setTotalSegments(1);
        m_baCfg.setAtomsPerPage(1);
        m_baCfg.setMaxCachePages(1);
        m_baCfg.setPagesPerGroup(1);
        ba = new FixedBlkAllocator(m_baCfg);
    }

    return ba;
}

PhysicalDevChunk *VirtualDev::createDevChunk(uint32_t physInd, uint64_t chunkSize, BlkAllocator *ba) {
    PhysicalDev *pdev = m_physDevList[physInd];
    PhysicalDevChunk *c = pdev->alloc_chunk(chunkSize);
    assert(c != NULL);
    c->setVirtualDev(this);
    c->set_blk_allocator(ba);
    return c;
}

#if 0
BlkAllocStatus VirtualDev::alloc(uint32_t size, vdev_hint *pHint, BlkSeries *blkSeries)
{
    uint32_t chunkNum, startChunkNum;
    BlkAllocStatus status;
    uint32_t nBlks = (size - 1) / m_devPageSize + 1;

    if (pHint->physDevId >= m_physDevList.size()) {
        return BLK_ALLOC_INVALID_DEV;
    }

    // Pick a physical chunk based on physDevId.

    // TODO: Right now there is only one primary chunk per device in a virtualdev.
    // Need to support multiple chunks. In that case just using physDevId as
    // chunk number is not right strategy.
    chunkNum = startChunkNum = pHint->physDevId;
    PhysicalDevChunk *chunk = NULL;

    do {
        chunk = m_primaryChunks[chunkNum];
        status = chunk->getBlkAllocator()->allocBlkSeries(nBlks, pHint->temperature, blkSeries);
        if ( (status == BLK_ALLOC_SUCCESS) || (!pHint->canLookForOtherDev)) {
            break;
        }
        chunkNum = ( (++chunkNum) % m_primaryChunks.size());
    } while (chunkNum != startChunkNum);

    if (status == BLK_ALLOC_SUCCESS) {
        blkSeries->setGlobBlkOffset(chunkNum * chunk->getSize());
        pHint->physDevId = chunkNum;
    }

    return status;
}

BlkAllocStatus VirtualDev::alloc(uint32_t size, vdev_hint *pHint, pageid64_t *outBlkNum)
{
    BlkSeries blkSeries(&m_baCfg);

    // Do a round robin on chunks for allocations
    uint32_t curPhysDev = m_totalAllocations % m_primaryChunks.size();
    m_totalAllocations++;

    vdev_hint hint;
    if (pHint == nullptr) {
        hint.physDevId = curPhysDev;
        hint.temperature = 0;
        hint.canLookForOtherDev = true;
        pHint = &hint;
    }
    BlkAllocStatus status = alloc(size, pHint, &blkSeries);
    if (status == BLK_ALLOC_SUCCESS) {
        *outBlkNum = blkSeries.getBlkNum( (size - 1) / m_devPageSize + 1);
    }

    return status;
}
#endif

BlkAllocStatus VirtualDev::alloc(uint32_t size, vdev_hint *phint, Blk *out_blk) {
    uint32_t chunkNum, startChunkNum;
    BlkAllocStatus status;

    // Do a round robin on chunks for allocations
    vdev_hint hint;
    if (phint == nullptr) {
        uint32_t curPhysDev = m_totalAllocations % m_primaryChunks.size();
        hint.physDevId = curPhysDev;
        hint.temperature = 0;
        hint.canLookForOtherDev = true;
        phint = &hint;
    } else if (phint->physDevId >= m_physDevList.size()) {
        return BLK_ALLOC_INVALID_DEV;
    }

    m_totalAllocations++;

    // Pick a physical chunk based on physDevId.
    // TODO: Right now there is only one primary chunk per device in a virtualdev.
    // Need to support multiple chunks. In that case just using physDevId as
    // chunk number is not right strategy.
    chunkNum = startChunkNum = phint->physDevId;
    PhysicalDevChunk *chunk = NULL;

    do {
        chunk = m_primaryChunks[chunkNum];
        status = chunk->get_blk_allocator()->alloc(size, phint->temperature, out_blk);
        if ((status == BLK_ALLOC_SUCCESS) || (!phint->canLookForOtherDev)) {
            break;
        }
        chunkNum = ((++chunkNum) % m_primaryChunks.size());
    } while (chunkNum != startChunkNum);

    if (status == BLK_ALLOC_SUCCESS) {
        uint32_t idOffset = chunkNum * getPagesPerChunk();

        // TOD: This loop could be avoided, if we have idOffset as part of the BlKAlloc
        // itself, something like PageIdOffset for each PhysicalDevChunk.
        for (auto i = 0; i < out_blk->getPieces(); i++) {
            out_blk->setPageId(i, out_blk->getPageId(i) + idOffset);
        }
        phint->physDevId = chunkNum;
    }
    return status;
}

void VirtualDev::free(Blk &b) {
    uint32_t chunkNum = b.getBlkId() / m_chunkSize;
    PhysicalDevChunk *chunk = m_primaryChunks[chunkNum];

    uint32_t idOffset = chunkNum * getPagesPerChunk();
    for (auto i = 0; i < b.getPieces(); i++) {
        b.setPageId(i, b.getPageId(i) - idOffset);
    }
    chunk->get_blk_allocator()->free(b);
}

#if 0
void VirtualDev::free(pageid64_t blkNum, uint32_t size)
{
    uint32_t chunkNum = blkNum / m_chunkSize;
    PhysicalDevChunk *chunk = m_primaryChunks[chunkNum];

    assert(size > 0);
    uint32_t nBlks = (size - 1) / m_devPageSize + 1;
    chunk->getBlkAllocator()->freeBlks(blkNum, nBlks);
}
#endif

#if 0
int VirtualDev::createIOVPerPage(Blk &b, uint32_t bpiece, MemBlk *mbList, struct iovec *iov, int *piovcnt)
{
    uint32_t start = bpiece;
    uint32_t cur = bpiece;
    *piovcnt = 0;

    // Loop through all same page Ids.
    int maxInd = b.getPieces() - 1;
    while ((cur < maxInd) && (b.getPageId(cur) == b.getPageId(cur+1))) {
        cur++;
    }

    for (auto i = start; i <= cur; i++) {
        for (auto j = 0; j < mbList[i].getMemPieces(); j++) {
            // TODO: Also verify the sum of sizes are not greater than a page size.
            assert(mbList[i].getSize(j) < m_baCfg.getPageSize());
            iov[*piovcnt].iov_base = mbList[i].getMem(j);
            iov[*piovcnt].iov_len = mbList[i].getSize(j);
            (*piovcnt)++;
        }
        i++;
    }

    return cur - start + 1;
}
#endif

// TODO: Need to put as part of global configuration
#define samePageOnMultiplePieces(b, p) ((p < (b.getPieces()-1)) && (b.getPageId(p) == b.getPageId(p+1)))

BlkOpStatus VirtualDev::write(SSDBlk &b) {
    // From blkNum first find out the chunkNumber. Then from chunk, get its
    // startblk number and find out the offset within the physical device
    // and write to the device.
    BlkOpStatus retStatus = BLK_OP_SUCCESS;
    uint64_t chunkOffset;
    uint64_t chunkNum;
    uint32_t size = 0;
    PhysicalDevChunk *chunk = nullptr;

    uint32_t p = 0;
    while (p < b.getPieces()) {
        struct iovec iov[MAX_OBJS_IN_BLK];
        int iovcnt = 0;

        pageNumToChunk(b.getPageId(p), &chunkNum, &chunkOffset);
        if (chunk == nullptr) {
            chunk = m_primaryChunks[chunkNum];
        } else {
            // We don't support write from different chunks in the same iteration.
            assert(chunk == m_primaryChunks[chunkNum]);
        }
        uint64_t devOffset = chunk->getStartOffset() + chunkOffset;
        assert(m_baCfg.getPageSize() <= MAX_IO_THREAD_BUF_SIZE);

        if (samePageOnMultiplePieces(b, p)) {
            // If more than one piece within the same page is getting written. We
            // need to do read-modify-write once to avoid multiple small piece within the
            // same page written multiple times, thus increasing writeamp significantly.
            chunk->getPhysicalDev()->read(__buf, m_baCfg.getPageSize(), devOffset);

            // Write in the buffer all the data pieces
            uint64_t lastPageId;
            do {
                uint16_t dataOffset = b.getOffset(p);
                for (auto j = 0; j < b.getMemoryPortion(p).getPieces(); j++) {
                    assert(dataOffset <= m_baCfg.getPageSize());
                    memcpy(&__buf[dataOffset], b.getMemoryPortion(p).getMem(j), b.getMemoryPortion(p).getSize(j));
                    dataOffset += b.getMemoryPortion(p).getSize(j);
                }
                lastPageId = b.getPageId(p);
                p++;
            } while ((p < b.getPieces()) && (lastPageId == b.getPageId(p)));

            iov[0].iov_base = __buf;
            iov[0].iov_len = m_baCfg.getPageSize();
            iovcnt = 1;
            size = m_baCfg.getPageSize();
        } else {
            for (auto j = 0; j < b.getMemoryPortion(p).getPieces(); j++) {
                // TODO: Also verify the sum of sizes are not greater than a page size.
                iov[iovcnt].iov_base = b.getMemoryPortion(p).getMem(j);
                iov[iovcnt].iov_len = b.getMemoryPortion(p).getSize(j);
                iovcnt++;
            }
            // TODO: Cross validate the mbList[p] size sums equal to this size. Very
            // important, otherwise data corruption can happen.
            size = b.getSize(p);
            p++;
        }

        BlkOpStatus status = chunk->getPhysicalDev()->writev(iov, iovcnt, size, devOffset);
        if (status != BLK_OP_SUCCESS) {
            retStatus = status;
            goto done;
        }

        // Write to the mirror as well.
        for (uint32_t i = 0; i < m_nMirrors; i++) {
            PhysicalDevChunk *mc = m_mirrorChunks[i][chunkNum];
            devOffset = mc->getStartOffset() + chunkOffset;
            status = mc->getPhysicalDev()->writev(iov, iovcnt, size, devOffset);
            if (status != BLK_OP_SUCCESS) {
                retStatus = BLK_OP_PARTIAL_FAILED;
            }
        }
    }

    // Finally commit all the blocks written into bitmap.
    chunk->get_blk_allocator()->commit(b);

    done:
    return retStatus;
}

#if 0
BlkOpStatus VirtualDev::write(const char *data, pageid64_t blkNum, uint32_t size)
{
    struct iovec iov[1];
    iov[0].iov_base = (void *) data;
    iov[0].iov_len = size;

    return (writev(iov, 1, blkNum, size));
}

BlkOpStatus VirtualDev::writev(const struct iovec *iov, int iovcnt, pageid64_t blkNum, uint32_t size)
{
    // From blkNum first find out the chunkNumber. Then from chunk, get its
    // startblk number and find out the offset within the physical device
    // and write to the device.
    BlkOpStatus retStatus = BLK_OP_SUCCESS;
    uint64_t chunkOffset;
    uint64_t chunkNum;
    uint32_t nBlks;

    assert(size > 0);
    pageNumToChunk(blkNum, &chunkNum, &chunkOffset);
    PhysicalDevChunk *chunk = m_primaryChunks[chunkNum];

    uint64_t devOffset = chunk->getStartOffset() + chunkOffset;
    BlkOpStatus status = chunk->getPhysicalDev()->writev(iov, iovcnt, size, devOffset);
    if (status != BLK_OP_SUCCESS) {
        retStatus = status;
        goto done;
    }

    // Commit the block in persistent bitmap area as well.
    nBlks = (size - 1) / m_devPageSize + 1;
    chunk->getBlkAllocator()->commitBlks(blkNum, nBlks);

    // Write to the mirror as well.
    for (uint32_t i = 0; i < m_nMirrors; i++) {
        PhysicalDevChunk *mc = m_mirrorChunks[i][chunkNum];
        devOffset = mc->getStartOffset() + chunkOffset;
        status = mc->getPhysicalDev()->writev(iov, iovcnt, size, devOffset);
        if (status != BLK_OP_SUCCESS) {
            retStatus = BLK_OP_PARTIAL_FAILED;
        }
    }

    done: return retStatus;
}

BlkOpStatus VirtualDev::read(char *data, pageid64_t blkNum, uint32_t size)
{
    BlkOpStatus status;
    uint64_t chunkOffset;
    uint64_t chunkNum;

    // Convert the blkNum to chunkOffset
    pageNumToChunk(blkNum, &chunkNum, &chunkOffset);
    PhysicalDevChunk *chunk = m_primaryChunks[chunkNum];

    uint64_t devOffset = chunk->getStartOffset() + chunkOffset;
    status = chunk->getPhysicalDev()->read(data, size, devOffset);

    if (status != BLK_OP_SUCCESS) {
        // Try reading from any one of the mirror
        for (uint32_t i = 0; i < m_nMirrors; i++) {
            PhysicalDevChunk *mc = m_mirrorChunks[i][chunkNum];
            devOffset = mc->getStartOffset() + chunkOffset;
            status = mc->getPhysicalDev()->read(data, size, devOffset);
            if (status == BLK_OP_SUCCESS) {
                break;
            }
        }
    }

    return status;
}
#endif

BlkOpStatus VirtualDev::read(SSDBlk &b) {
    BlkOpStatus status;
    uint64_t chunkOffset;
    uint64_t chunkNum;

    // Convert the pagenum to chunkOffset
    assert(b.getPieces() == 1);
    uint32_t size = b.getTotalSize();
    pageid64_t pgNum = b.getPageId(0);
    pageNumToChunk(pgNum, &chunkNum, &chunkOffset);
    PhysicalDevChunk *chunk = m_primaryChunks[chunkNum];

    // Convert the input memory to iovector
    struct iovec iov[MAX_OBJS_IN_BLK];
    int iovcnt = 0;

    MemBlk &mb = b.getMemoryPortion(0);
    for (auto i = 0; i < mb.getPieces(); i++) {
        // TODO: Also verify the sum of sizes are not greater than a page size.
        iov[iovcnt].iov_base = mb.getMem(i);
        iov[iovcnt].iov_len = mb.getSize(i);
        iovcnt++;
    }

#ifdef DEBUG
    uint32_t memsize = 0;
    for (auto i = 0; i < mb.getPieces(); i++) {
        memsize += mb.getSize(i);
    }
    assert(memsize >= size);
#endif

    uint64_t devOffset = chunk->getStartOffset() + chunkOffset;
    status = chunk->getPhysicalDev()->readv(iov, iovcnt, size, devOffset);

    if (status != BLK_OP_SUCCESS) {
        // Try reading from any one of the mirror
        for (uint32_t i = 0; i < m_nMirrors; i++) {
            PhysicalDevChunk *mc = m_mirrorChunks[i][chunkNum];
            devOffset = mc->getStartOffset() + chunkOffset;
            status = mc->getPhysicalDev()->readv(iov, iovcnt, size, devOffset);
            if (status == BLK_OP_SUCCESS) {
                break;
            }
        }
    }

    return status;
}

void VirtualDev::pageNumToChunk(pageid64_t pageNum, uint64_t *chunkNum, uint64_t *chunkOffset) {
    uint64_t vdevOffset = pageNum * m_devPageSize;

    if (chunkNum) {
        *chunkNum = vdevOffset / m_chunkSize;
    }

    if (chunkOffset) {
        *chunkOffset = vdevOffset % m_chunkSize;
    }
}

} //namespace omstore