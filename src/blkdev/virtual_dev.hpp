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
#include <map>
#include "main/omstore.hpp"

namespace omstore {

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

/*
 * VirtualDev: Virtual device implements a similar functionality of RAID striping, customized however. Virtual devices
 * can be created across multiple physical devices. Unlike RAID, its io is not always in a bigger strip sizes. It
 * support n-mirrored writes.
 *
 * Template parameters:
 * Allocator: The type of AllocatorPolicy to allocate blocks for writes.
 * DefaultDeviceSelector: Which device to select for allocation
 */
template <typename Allocator, typename DefaultDeviceSelector>
class VirtualDev
{
    friend typename DefaultDeviceSelector;

private:
    uint64_t m_size;       // Size of this virtual device
    uint64_t m_chunk_size; // Chunk size that will be allocated in a physical device
    uint32_t m_nmirrors;   // Total number of mirrors need to be maintained

    uint32_t m_dev_blk_size; // Block size used for this virtual device. Each vdev can have different block sizes
    std::atomic< uint64_t > m_total_allocations; // Keep track of total allocations.

    // List of physical devices this virtual device uses.
    std::vector< std::unique_ptr< PhysicalDev > > m_phys_dev_list;

    // Array of physical devices each having multiple chunks that are relevant to this virtual device
    std::vector< std::vector< PhysicalDevChunk * > > m_primary_chunks_in_physdev;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::map< PhysicalDevChunk *, std::vector< PhysicalDevChunk * > > m_mirror_chunks;

    // Instance of device selector
    DefaultDeviceSelector m_selector;

public:
    VirtualDev(uint64_t size, uint32_t nmirror, bool is_stripe, uint32_t dev_blk_size,
                       std::vector< std::unique_ptr< PhysicalDev > > &phys_dev_list) :
            m_size(size),
            m_nmirrors(nmirror),
            m_total_allocations(0),
            m_dev_blk_size(dev_blk_size),
            m_phys_dev_list(phys_dev_list),
            m_selector(this) {

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

        for (auto i : boost::irange<uint32_t>(0, nchunks)) {
            std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size);
            auto phys_dev_id = i % phys_dev_list.size();

            // Create a chunk on selected physical device and add it to both all chunk lists and chunk per
            // physical device list.
            auto chunk = create_dev_chunk((uint32_t)phys_dev_id, m_chunk_size, ba);
            m_primary_chunks_in_physdev[phys_dev_id].push_back(chunk);

            if (nmirror) {
                uint32_t next_ind = i;
                std::vector< PhysicalDevChunk * > vec;
                vec.reserve(nmirror);
                for (auto j : boost::irange(0, nmirror)) {
                    if ((++next_ind) == phys_dev_list.size()) {
                        next_ind = 0;
                    }
                    vec.push_back(create_dev_chunk(next_ind, m_chunk_size, ba));
                }
                m_mirror_chunks.emplace(std::make_pair(chunk, vec));
            }
        }
    }

    ~VirtualDev() {
        for (auto &v : m_primary_chunks_in_physdev) {
            for (auto &c : v) {
                c->get_physical_dev()->free_chunk(c);
            }
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
            dev_id = m_selector.select(hints);
        } else {
            assert(hints.dev_id_hint < m_phys_dev_list.size());
            dev_id = (uint32_t)hints.dev_id_hint;
        }
        m_total_allocations++;

        // Pick a physical chunk based on physDevId.
        // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple chunks.
        // In that case just using physDevId as chunk number is not right strategy.
        uint32_t start_dev_id = dev_id;
        PhysicalDevChunk *picked_chunk = nullptr;

        do {
            for (auto chunk : m_primary_chunks_in_physdev[dev_id]) {
                status = chunk->get_blk_allocator()->alloc(size, hints, out_blk);
                if (status == BLK_ALLOC_SUCCESS) {
                    picked_chunk = chunk;
                    break;
                }
            }

            if (!hints.can_look_for_other_dev) {
                break;
            }
            dev_id = (uint32_t)((++dev_id) % m_primary_chunks_in_physdev.size());
        } while (dev_id != start_dev_id);

        if (status == BLK_ALLOC_SUCCESS) {
            // Set the id as globally unique id
            out_blk->set_id(to_glob_uniq_blkid(out_blk->get_id(), picked_chunk));
        }
        return status;
    }

    void free(SingleBlk &b) {
        PhysicalDevChunk *chunk;

        // Convert blk id to chunk specific id and call its allocator to free
        b.set_id(to_chunk_specific_id(b.get_id(), &chunk));
        chunk->get_blk_allocator()->free(b);
    }

    void write(SingleBlk &blk) {
        // From blkNum first find out the chunkNumber. Then from chunk, get its
        // startblk number and find out the offset within the physical device
        // and write to the device.
        BlkOpStatus ret_status = BLK_OP_SUCCESS;
        uint32_t size = blk.get_size();
        struct iovec iov[MAX_OBJS_IN_BLK];
        int iovcnt = 0;

        uint32_t p = 0;
        for (auto i : boost::irange<uint32_t>(0, blk.get_mem().npieces())) {
            omds::blob b;
            blk.get_mem().get(&b, i);

            // TODO: Also verify the sum of sizes are not greater than a page size.
            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        PhysicalDevChunk *chunk;
        uint64_t dev_offset = to_dev_offset(blk.get_id(), &chunk);
        try {
            chunk->get_physical_dev()->writev(iov, iovcnt, size, dev_offset);
        } catch (std::exception &e) {
            throw e;
        }

        if (m_nmirrors) {
            uint64_t primary_chunk_offset = dev_offset - chunk->get_start_offset();

            // Write to the mirror as well
            for (auto i : boost::irange< uint32_t >(0, m_nmirrors)) {
                for (auto mchunk : m_mirror_chunks.find(chunk)->second) {
                    dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                    try {
                        mchunk->get_physical_dev()->writev(iov, iovcnt, size, dev_offset);
                    } catch (std::exception &e) {
                        throw e;
                    }
                }
            }
        }
    }

    void read(SingleBlk &blk) {
        // Convert the input memory to iovector
        struct iovec iov[MAX_OBJS_IN_BLK];
        int iovcnt = 0;
        uint32_t size = blk.get_size();

        for (auto i : boost::irange<uint32_t>(0, blk.get_mem().npieces())) {
            omds::blob b;
            blk.get_mem().get(&b, i);

            // TODO: Also verify the sum of sizes are not greater than a page size.
            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        bool failed = false;
        PhysicalDevChunk *primary_chunk;
        uint64_t primary_dev_offset = to_dev_offset(blk.get_id(), &primary_chunk);

        try {
            primary_chunk->get_physical_dev()->readv(iov, iovcnt, size, primary_dev_offset);
        } catch (std::exception &e) {
            failed = true;
        }

        if (unlikely(failed && m_nmirrors)) {
            uint64_t primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
                uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                try {
                    mchunk->get_physical_dev()->writev(iov, iovcnt, size, dev_offset);
                } catch (std::exception &e) {
                    failed = true;
                }
            }
        }

        if (unlikely(failed)) {
            // TODO: Capture the exception e as exception pointer and rethrow that.
            throw DeviceException("Unable to read");
        }
    }

    uint64_t get_size() const {
        return m_size;
    }

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

        c->set_virtual_dev(this);
        c->set_blk_allocator(ba);
        return c;
    }

    blk_id to_glob_uniq_blkid(blk_id chunk_local_blkid, PhysicalDevChunk *chunk) {
        uint64_t glob_offset = ((chunk_local_blkid.get_id() * m_dev_blk_size) + chunk->get_start_offset() +
                                chunk->get_physical_dev()->get_dev_offset());
        return blk_id(glob_offset/m_dev_blk_size, chunk->get_chunk_id());
    }

    blk_id to_chunk_specific_id(blk_id glob_uniq_id, PhysicalDevChunk **chunk) {
        // Extract the chunk id from glob_uniq_id
        auto cid = glob_uniq_id.get_chunk_id();
        *chunk = BlkDevManagerInstance.get_chunk(cid);

        // Offset within the physical device
        uint64_t offset = (glob_uniq_id.get_id() * m_dev_blk_size) - (*chunk)->get_physical_dev()->get_dev_offset();

        // Offset within the chunk
        uint64_t chunk_offset = offset - (*chunk)->get_start_offset();
        return blk_id(chunk_offset/m_dev_blk_size , 0);
    }

    uint64_t to_dev_offset(blk_id glob_uniq_id, PhysicalDevChunk **chunk) {
        *chunk = BlkDevManagerInstance.get_chunk(glob_uniq_id.get_chunk_id());

        // Offset within the physical device
        return (glob_uniq_id.get_id() * m_dev_blk_size) - (*chunk)->get_physical_dev()->get_dev_offset();
    }

    uint64_t to_chunk_offset(blk_id glob_uniq_id, PhysicalDevChunk **chunk) {
        return (to_dev_offset(glob_uniq_id, chunk) - (*chunk)->get_start_offset());
    }

        uint32_t get_blks_per_chunk() const {
        return m_chunk_size / m_dev_blk_size;
    }

    //int createIOVPerPage(Blk &b, uint32_t bpiece, MemBlk *mbList, struct iovec *iov, int *piovcnt);

};

} //namespace omstore
#endif //OMSTORE_VIRTUAL_DEV_HPP_HPP
