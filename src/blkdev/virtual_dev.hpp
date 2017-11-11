//
// Created by Kadayam, Hari on 08/11/17.
//

#ifndef OMSTORE_VIRTUAL_DEV_HPP_HPP
#define OMSTORE_VIRTUAL_DEV_HPP_HPP

#include "blkdev.h"
#include "blkalloc/blk_allocator.h"
#include "blkalloc/varsize_blk_allocator.h"
#include <vector>
#include <memory>
#include <boost/range/irange.hpp>

namespace omstore {
class RoundRobinSelectionPolicy {
public:
    RoundRobinSelectionPolicy(uint32_t nallocators) :
            m_nallocators(nallocators) {
    }

    uint32_t select(blk_alloc_hints &hints) {
        if (RoundRobinSelectionPolicy::last_allocator == m_nallocators) {
            RoundRobinSelectionPolicy::last_allocator = 0;
        } else {
            RoundRobinSelectionPolicy::last_allocator++;
        }

        return RoundRobinSelectionPolicy::last_allocator;
    }

private:
    static thread_local uint32_t last_allocator;
    uint32_t m_nallocators;
};
thread_local uint32_t RoundRobinSelectionPolicy::last_allocator = 0;

class VdevFixedBlkAllocatorPolicy {
public:
    typedef FixedBlkAllocator AllocatorType;

    static void get_config(uint64_t size, uint32_t blk_size, BlkAllocConfig *out_config) {
        out_config->set_blk_size(blk_size);
        out_config->set_total_blks((uint32_t)size/blk_size);
    }
};

class VdevVarSizeBlkAllocatorPolicy {
public:
    typedef VarsizeBlkAllocator AllocatorType;

    static void get_config(uint64_t size, uint32_t blk_size, BlkAllocConfig *out_config) {
        VarsizeBlkAllocConfig *vconfig = (VarsizeBlkAllocConfig *)out_config;
        vconfig->set_blk_size(blk_size);
        vconfig->set_total_blks(((uint32_t)size-1)/blk_size + 1);

        vconfig->set_page_size(8192); // SSD Page size, TODO: Get actual SSD page size and set this here
        vconfig->set_total_segments(8); // 8 Segments per chunk
        vconfig->set_pages_per_portion(1024); // Have locking etc for every 1024 pages
        vconfig->set_pages_per_temp_group(100); // TODO: Recalculate based on size set aside for temperature entries
        vconfig->set_max_cache_blks(vconfig->get_total_pages()/4); // Cache quarter of the blocks
    }
};

template <typename Allocator, typename DefaultSelectionPolicy>
class VirtualDev
{
private:
    uint64_t m_size;
    uint32_t m_nmirrors;
    uint64_t m_chunk_size;
    std::atomic< uint64_t > m_total_allocations;
    uint32_t m_dev_blk_size;

    std::vector< std::unique_ptr< PhysicalDev > > m_phys_dev_list;

    // Array of physical devices each having multiple chunks that are relevant to this virtual device
    std::vector< std::vector< PhysicalDevChunk * > > m_primary_chunks_in_physdev;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::vector< std::vector< PhysicalDevChunk * > > m_mirror_chunks;
public:
    VirtualDev(uint64_t size, uint32_t nmirror, bool is_stripe, uint32_t dev_blk_size,
                       std::vector< std::unique_ptr< PhysicalDev > > &phys_dev_list) :
            m_size(size),
            m_nmirrors(nmirror),
            m_total_allocations(0),
            m_dev_blk_size(dev_blk_size),
            m_phys_dev_list(phys_dev_list) {

        assert(nmirror < phys_dev_list.size()); // Mirrors should be at least one less than device list.
        uint32_t nchunks;

        if (is_stripe) {
            m_chunk_size = ((size - 1) / phys_dev_list.size()) + 1;
            nchunks = (uint32_t)phys_dev_list.size();
        } else {
            m_chunk_size = size;
            nchunks = 1;
        }

        // Prepare primary chunks in a physical device for future inserts.
        m_primary_chunks_in_physdev.reserve(phys_dev_list.size());
        for (auto &pdev : phys_dev_list) {
            std::vector<PhysicalDevChunk *> v;
            v.reserve(1); // We initially expect only one chunk per physical device.
            m_primary_chunks_in_physdev.push_back(v);
        }

        m_mirror_chunks.reserve(nchunks);

        for (auto i : boost::irange<uint32_t>(0, nchunks)) {
            std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size);
            auto phys_dev_id = i % phys_dev_list.size();

            // Create a chunk on selected physical device and add it to both all chunk lists and chunk per
            // physical device list.
            auto chunk = create_dev_chunk((uint32_t)phys_dev_id, m_chunk_size, ba);
            m_primary_chunks_in_physdev[phys_dev_id].push_back(chunk);

            uint32_t next_ind = i;
            std::vector< PhysicalDevChunk *> vec;
            vec.reserve(nmirror);
            for (auto j : boost::irange(0, nmirror)) {
                if ((++next_ind) == phys_dev_list.size()) {
                    next_ind = 0;
                }
                vec.push_back(create_dev_chunk(next_ind, m_chunk_size, ba));
            }
            m_mirror_chunks.push_back(vec);
        }
    }

    virtual ~VirtualDev() {
        for (auto &c : m_primary_chunks) {
            c->get_physical_dev()->free_chunk(c);
        }

        for (auto &v : m_mirror_chunks) {
            for (auto &c : v) {
                c->get_physical_dev()->free_chunk(c);
            }
        }
    }

    BlkAllocStatus alloc(uint32_t size, blk_alloc_hints &hints, SingleBlk *out_blk) {
        uint32_t dev_id;
        uint32_t chunk_num, start_chunk_num;
        BlkAllocStatus status;

        // First select a device to allocate from
        if (hints.dev_id_hint == -1) {
            dev_id = DefaultSelectionPolicy::select(hints);
        } else {
            assert(hints.dev_id_hint < m_phys_dev_list.size());
            dev_id = (uint32_t)hints.dev_id_hint;
        }
        m_total_allocations++;

        // Pick a physical chunk based on physDevId.
        // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple chunks.
        // In that case just using physDevId as chunk number is not right strategy.
        chunk_num = start_chunk_num = dev_id;
        PhysicalDevChunk *chunk = NULL;

        do {
            chunk = m_primary_chunks[chunk_num];
            status = chunk->get_blk_allocator()->alloc(size, hints, out_blk);
            if ((status == BLK_ALLOC_SUCCESS) || (!hints.can_look_for_other_dev)) {
                break;
            }
            chunk_num = (uint32_t)((++chunk_num) % m_primary_chunks.size());
        } while (chunk_num != start_chunk_num);

        if (status == BLK_ALLOC_SUCCESS) {
            // Set the id as globally unique id
            out_blk->set_id(to_glob_uniq_blkid(out_blk->get_id(), chunk));
        }
        return status;
    }

    void free(SingleBlk &b) {
        uint32_t chunkNum = b.get_id() / b.get_chunk();
        PhysicalDevChunk *chunk = m_primaryChunks[chunkNum];

        uint32_t idOffset = chunkNum * getPagesPerChunk();
        for (auto i = 0; i < b.getPieces(); i++) {
            b.setPageId(i, b.getPageId(i) - idOffset);
        }
        chunk->get_blk_allocator()->free(b);
    }

    BlkOpStatus write(SSDBlk &b);
    BlkOpStatus read(SSDBlk &b);

    uint64_t get_size() const {
        return m_size;
    }

#if 0
    BlkOpStatus write(const char *data, uint64_t blkNum, uint32_t size);
    BlkOpStatus writev(const struct iovec *iov, int iovcnt, pageid64_t blkNum, uint32_t size);
    BlkOpStatus read(char *data, uint64_t blkNum, uint32_t size);
#endif

private:
    std::shared_ptr< BlkAllocator > create_allocator(uint64_t size) {
        BlkAllocConfig cfg;
        Allocator::get_config(size, m_dev_blk_size, &cfg);

        std::shared_ptr< BlkAllocator > allocator = new std::make_shared<Allocator::AllocatorType>(cfg);
        return allocator;
    }

    PhysicalDevChunk *create_dev_chunk(uint32_t phys_ind, uint64_t chunk_size, std::shared_ptr < BlkAllocator > ba) {
        auto &pdev = m_phys_dev_list[phys_ind];
        PhysicalDevChunk *c = pdev->alloc_chunk(chunk_size);
        assert(c != NULL);

        c->set_virtual_dev(this);
        c->set_blk_allocator(ba);
        return c;
    }

    blk_id to_glob_uniq_blkid(blk_id chunk_local_blkid, PhysicalDevChunk *chunk) {
        uint64_t glob_offset = ((chunk_local_blkid.get_id() * m_dev_blk_size) + chunk->get_start_offset() +
                                chunk->get_physical_dev()->get_dev_offset());
        return blk_id(glob_offset/m_dev_blk_size, chunk->get_chunk_id());
    }

    blk_id to_chunk_specific_id(blk_id glob_uniq_id, uint16_t *out_chunk_num) {
        // Extract the chunk id from glob_uniq_id
        *out_chunk_num = glob_uniq_id.get_chunk_id();
    }

    uint32_t get_blks_per_chunk() const {
        return m_chunk_size / m_dev_blk_size;
    }

    //int createIOVPerPage(Blk &b, uint32_t bpiece, MemBlk *mbList, struct iovec *iov, int *piovcnt);

};

} //namespace omstore
#endif //OMSTORE_VIRTUAL_DEV_HPP_HPP
