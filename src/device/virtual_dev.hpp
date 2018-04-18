//
// Created by Kadayam, Hari on 08/11/17.
//

#ifndef OMSTORE_VIRTUAL_DEV_HPP_HPP
#define OMSTORE_VIRTUAL_DEV_HPP_HPP

#include "device.h"
#include "blkalloc/blk_allocator.h"
#include "blkalloc/varsize_blk_allocator.h"
#include <vector>
#include <memory>
#include <boost/range/irange.hpp>
#include <map>

namespace homestore {

class VdevFixedBlkAllocatorPolicy {
public:
    typedef FixedBlkAllocator AllocatorType;
    typedef BlkAllocConfig AllocatorConfig;

    static void get_config(uint64_t size, uint32_t blk_size, BlkAllocConfig *out_config) {
        out_config->set_blk_size(blk_size);
        out_config->set_total_blks((uint32_t)size/blk_size);
    }
};

class VdevVarSizeBlkAllocatorPolicy {
public:
    typedef VarsizeBlkAllocator AllocatorType;
    typedef VarsizeBlkAllocConfig AllocatorConfig;


    static void get_config(uint64_t size, uint32_t blk_size, BlkAllocConfig *out_config) {
        VarsizeBlkAllocConfig *vconfig = (VarsizeBlkAllocConfig *)out_config;
        vconfig->set_blk_size(blk_size);
        vconfig->set_total_blks(((uint64_t)size-1)/blk_size + 1);

        vconfig->set_page_size(8192); // SSD Page size, TODO: Get actual SSD page size and set this here
        vconfig->set_total_segments(8); // 8 Segments per chunk
        vconfig->set_pages_per_portion(1024); // Have locking etc for every 1024 pages
        vconfig->set_pages_per_temp_group(100); // TODO: Recalculate based on size set aside for temperature entries
        vconfig->set_max_cache_blks(vconfig->get_total_pages()/4); // Cache quarter of the blocks
    }
};

struct pdev_chunk_map {
    PhysicalDev *pdev;
    std::vector< PhysicalDevChunk * > chunks_in_pdev;
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
class VirtualDev : public AbstractVirtualDev
{
private:
    vdev_info_block *m_vb; // This device block info
    DeviceManager *m_mgr;  // Device Manager back pointer
    uint64_t m_chunk_size; // Chunk size that will be allocated in a physical device
    std::mutex m_mgmt_mutex; // Any mutex taken for management operations (like adding/removing chunks).

    // List of physical devices this virtual device uses and its corresponding chunks for the physdev
    std::vector< pdev_chunk_map > m_primary_pdev_chunks_list;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::map< PhysicalDevChunk *, std::vector< PhysicalDevChunk * > > m_mirror_chunks;

    // Instance of device selector
    std::unique_ptr< DefaultDeviceSelector > m_selector;
    uint64_t write_time;
    uint64_t physical_time;
    uint64_t mirror_time;
    uint64_t write_cnt;

public:
    /* Create a new virtual dev for these parameters */
    VirtualDev(DeviceManager *mgr, uint64_t size, uint32_t nmirror, bool is_stripe, uint32_t dev_blk_size,
               const std::vector< PhysicalDev *> &pdev_list) {
        // Create a new vdev in persistent area and get the block of it
        m_vb = mgr->alloc_vdev(size, nmirror, dev_blk_size);
        m_mgr = mgr;

        // Now its time to allocate chunks as needed
        assert(nmirror < pdev_list.size()); // Mirrors should be at least one less than device list.
        uint32_t nchunks;

        if (is_stripe) {
            m_chunk_size = ((size - 1) / pdev_list.size()) + 1;
            nchunks = (uint32_t)pdev_list.size();
        } else {
            m_chunk_size = size;
            nchunks = 1;
        }

        // Prepare primary chunks in a physical device for future inserts.
        m_primary_pdev_chunks_list.reserve(pdev_list.size());
        for (auto pdev : pdev_list) {
            pdev_chunk_map mp;
            mp.pdev = pdev;
            mp.chunks_in_pdev.reserve(1);

            m_primary_pdev_chunks_list.push_back(mp);
        }

        for (auto i : boost::irange<uint32_t>(0, nchunks)) {
            std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size);
            auto pdev_ind = i % pdev_list.size();

            // Create a chunk on selected physical device and add it to chunks in physdev list
            auto chunk = create_dev_chunk(pdev_ind, ba);
            m_primary_pdev_chunks_list[pdev_ind].chunks_in_pdev.push_back(chunk);

            // If we have mirror, create a map between chunk and its mirrored chunks
            if (nmirror) {
                uint32_t next_ind = i;
                std::vector< PhysicalDevChunk * > vec;
                vec.reserve(nmirror);
                for (auto j : boost::irange<uint32_t>(0, nmirror)) {
                    if ((++next_ind) == m_primary_pdev_chunks_list.size()) {
                        next_ind = 0;
                    }
                    auto mchunk = create_dev_chunk(next_ind, ba);
                    mchunk->set_primary_chunk(chunk);
                    vec.push_back(mchunk);
                }
                m_mirror_chunks.emplace(std::make_pair(chunk, vec));
            }
        }

        m_selector = std::make_unique<DefaultDeviceSelector>();
        for (auto &pdev : pdev_list) {
            m_selector->add_pdev(pdev);
        }
    }

    /* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
    VirtualDev(DeviceManager *mgr, vdev_info_block *vb) :
            m_vb(vb),
            m_mgr(mgr) {
        m_selector = std::make_unique<DefaultDeviceSelector>();
        m_chunk_size = 0;
    }

    ~VirtualDev() = default;

    /* This method adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
     * takes lock for writing and not reading
     */
    virtual void add_chunk(PhysicalDevChunk *chunk) override {
        LOG(INFO) << "Adding chunk " << chunk->get_chunk_id() << " from vdev id " << chunk->get_vdev_id() <<
                  " from pdev id = " << chunk->get_physical_dev()->get_dev_id();
        std::lock_guard< decltype(m_mgmt_mutex) > lock(m_mgmt_mutex);
        (chunk->get_primary_chunk()) ? add_mirror_chunk(chunk) : add_primary_chunk(chunk);

        std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size);
        chunk->set_blk_allocator(ba);
    }

    BlkAllocStatus alloc_blk(uint8_t nblks, const blk_alloc_hints &hints, BlkId *out_blkid) {
        uint32_t dev_ind;
        uint32_t chunk_num, start_chunk_num;
        BlkAllocStatus status = BLK_ALLOC_FAILED;

        // First select a device to allocate from
        if (hints.dev_id_hint == -1) {
            dev_ind = m_selector->select(hints);
        } else {
            dev_ind = (uint32_t)hints.dev_id_hint;
        }

        //m_total_allocations++;

        // Pick a physical chunk based on physDevId.
        // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple chunks.
        // In that case just using physDevId as chunk number is not right strategy.
        uint32_t start_dev_ind = dev_ind;
        PhysicalDevChunk *picked_chunk = nullptr;

        do {
            for (auto chunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
                status = chunk->get_blk_allocator()->alloc(nblks, hints, out_blkid);
                if (status == BLK_ALLOC_SUCCESS) {
                    picked_chunk = chunk;
                    break;
                }
            }

	    if (status == BLK_ALLOC_SUCCESS) {
		break;
	    }
            if (!hints.can_look_for_other_dev) {
                break;
            }
            dev_ind = (uint32_t)((++dev_ind) % m_primary_pdev_chunks_list.size());
        } while (dev_ind != start_dev_ind);

        if (status == BLK_ALLOC_SUCCESS) {
            // Set the id as globally unique id
            *out_blkid = to_glob_uniq_blkid(*out_blkid, picked_chunk);
        }
        return status;
    }

    void free_blk(const BlkId &b) {
        PhysicalDevChunk *chunk;

        // Convert blk id to chunk specific id and call its allocator to free
        BlkId cb = to_chunk_specific_id(b, &chunk);
        chunk->get_blk_allocator()->free(cb);
    }

    void print_cntrs() {
	printf("time taken in write %lu ns\n", write_time/write_cnt);
	printf("time taken in write %lu ns\n", physical_time/write_cnt);
	printf("time taken in write %lu ns\n", mirror_time/write_cnt);
    }
 
    void init_cntrs() {
	write_time = 0;
	write_cnt = 0;
	physical_time = 0;
	mirror_time = 0;
    }
    void write(const BlkId &bid, const homeds::MemVector<BLKSTORE_BLK_SIZE> &buf) {
        BlkOpStatus ret_status = BLK_OP_SUCCESS;
        uint32_t size = bid.get_nblks() * get_blk_size();
        struct iovec iov[BlkId::max_blks_in_op()];
        int iovcnt = 0;

	Clock::time_point startTime = Clock::now();
        assert(buf.size() == bid.get_nblks() * BLKSTORE_BLK_SIZE);

        uint32_t p = 0;
        for (auto i : boost::irange<uint32_t>(0, buf.npieces())) {
            homeds::blob b;
            buf.get(&b, i);

            // TODO: Also verify the sum of sizes are not greater than a page size.
            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        PhysicalDevChunk *chunk;
        uint64_t dev_offset = to_dev_offset(bid, &chunk);
        try {
            LOG(INFO) << "Writing in device " << chunk->get_physical_dev()->get_dev_id() << " offset = " << dev_offset;
	    write_time += 
		    (std::chrono::duration_cast< std::chrono::nanoseconds >(Clock::now() - 
									    startTime)).count();
	    write_cnt++;
	    chunk->get_physical_dev_mutable()->writev(iov, iovcnt, size, dev_offset);
        } catch (std::exception &e) {
            throw e;
        }

	physical_time += (std::chrono::duration_cast< std::chrono::nanoseconds >(Clock::now() -
										startTime)).count();
        if (get_nmirrors()) {
            uint64_t primary_chunk_offset = dev_offset - chunk->get_start_offset();

            // Write to the mirror as well
            for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
                for (auto mchunk : m_mirror_chunks.find(chunk)->second) {
                    dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                    try {
                        mchunk->get_physical_dev_mutable()->writev(iov, iovcnt, size, dev_offset);
                    } catch (std::exception &e) {
                        throw e;
                    }
                }
            }
        }
	mirror_time += (std::chrono::duration_cast< std::chrono::nanoseconds >(Clock::now() -
										startTime)).count();
    }

    /* Read the data for a given BlkId. With this method signature, virtual dev can read only in block boundary
     * and nothing in-between offsets (say if blk size is 8K it cannot read 4K only, rather as full 8K. It does not
     * have offset as one of the parameter. Reason for that is its actually ok and make the interface and also
     * buf (caller buf) simple and there is no use case. However, we need to keep the blk size to be small as possible
     * to avoid read overhead */
    void read(const BlkId &bid, const homeds::MemPiece<BLKSTORE_BLK_SIZE> &mp) {
        PhysicalDevChunk *primary_chunk;
        bool failed = false;

        uint64_t primary_dev_offset = to_dev_offset(bid, &primary_chunk);
        try {
            primary_chunk->get_physical_dev_mutable()->read((char *)mp.ptr(), mp.size(), primary_dev_offset);
        } catch (std::exception &e) {
            failed = true;
        }

        if (unlikely(failed && get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            uint64_t primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
                uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                try {
                    mchunk->get_physical_dev_mutable()->read((char *)mp.ptr(), mp.size(), dev_offset);
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

    void readv(const BlkId &bid, const homeds::MemVector<BLKSTORE_BLK_SIZE> &buf) {
        // Convert the input memory to iovector
        struct iovec iov[BlkId::max_blks_in_op()];
        int iovcnt = 0;
        uint32_t size = buf.size();

        assert(buf.size() == (bid.get_nblks() * get_blk_size())); // Expected to be less than allocated blk originally.
        for (auto i : boost::irange<uint32_t>(0, buf.npieces())) {
            homeds::blob b;
            buf.get(&b, i);

            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        bool failed = false;
        PhysicalDevChunk *primary_chunk;
        uint64_t primary_dev_offset = to_dev_offset(bid, &primary_chunk);

        try {
            primary_chunk->get_physical_dev_mutable()->readv(iov, iovcnt, size, primary_dev_offset);
        } catch (std::exception &e) {
            failed = true;
        }

        if (unlikely(failed && get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            uint64_t primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
                uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                try {
                    mchunk->get_physical_dev_mutable()->readv(iov, iovcnt, size, dev_offset);
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
        return m_vb->size;
    }

    void expand(uint32_t addln_size) {
    }

    // Remove this virtualdev altogether
    void rm_device() {
        for (auto &pcm : m_primary_pdev_chunks_list) {
            for (auto &c : pcm.chunks_in_pdev) {
                m_mgr->free_chunk(c);
            }
        }

        for (auto &v : m_mirror_chunks) {
            for (auto &c : v.second) {
                m_mgr->free_chunk(c);
            }
        }

        m_mgr->free_vdev(m_vb);
    }

    std::string to_string() {

    }

private:
    /* Adds a primary chunk to the chunk list in pdev */
    void add_primary_chunk(PhysicalDevChunk *chunk) {
        auto pdev_id = chunk->get_physical_dev()->get_dev_id();

        if (m_chunk_size == 0) m_chunk_size = chunk->get_size();
        assert(m_chunk_size == chunk->get_size());

        pdev_chunk_map *found_pcm = nullptr;
        for (auto &pcm : m_primary_pdev_chunks_list) {
            if (pcm.pdev->get_dev_id() == pdev_id) {
                found_pcm = &pcm;
                break;
            }
        }

        if (found_pcm) {
            found_pcm->chunks_in_pdev.push_back(chunk);
        } else {
            // Have not seen the pdev before, so add the chunk and also add it to device selector
            pdev_chunk_map pcm;
            pcm.pdev = m_mgr->get_pdev(pdev_id);
            pcm.chunks_in_pdev.push_back(chunk);

            m_primary_pdev_chunks_list.push_back(pcm);
            m_selector->add_pdev(pcm.pdev);
        }
    }

    void add_mirror_chunk(PhysicalDevChunk *chunk) {
        auto pdev_id = chunk->get_physical_dev()->get_dev_id();
        auto pchunk = chunk->get_primary_chunk();

        // Try to find the parent chunk in the map
        auto it = m_mirror_chunks.find(pchunk);
        if (it == m_mirror_chunks.end()) {
            // Not found, just create a new entry
            std::vector< PhysicalDevChunk *> vec;
            vec.push_back(chunk);
            m_mirror_chunks.emplace(std::make_pair(pchunk, vec));
        } else {
            it->second.push_back(chunk);
        }
    }

    std::shared_ptr< BlkAllocator > create_allocator(uint64_t size) {
	typename Allocator::AllocatorConfig cfg;
        Allocator::get_config(size, get_blk_size(), &cfg);

        std::shared_ptr< BlkAllocator > allocator = std::make_shared<typename Allocator::AllocatorType>(cfg);
        return allocator;
    }

    PhysicalDevChunk *create_dev_chunk(uint32_t pdev_ind, std::shared_ptr< BlkAllocator > ba) {
        auto pdev = m_primary_pdev_chunks_list[pdev_ind].pdev;
        PhysicalDevChunk *chunk = m_mgr->alloc_chunk(pdev, m_vb->vdev_id, m_chunk_size);
        LOG(INFO) << "Allocating new chunk for vdev_id = " << m_vb->vdev_id << " pdev_id = " << pdev->get_dev_id() <<
                  " chunk: " << chunk->to_string();
        chunk->set_blk_allocator(ba);

        return chunk;
    }

    BlkId to_glob_uniq_blkid(const BlkId &chunk_local_blkid, PhysicalDevChunk *chunk) const {
        uint64_t glob_offset = ((chunk_local_blkid.get_id() * get_blk_size()) + chunk->get_start_offset() +
                                chunk->get_physical_dev()->get_dev_offset());
        return BlkId(glob_offset/get_blk_size(), chunk_local_blkid.get_nblks(), chunk->get_chunk_id());
    }

    BlkId to_chunk_specific_id(const BlkId &glob_uniq_id, PhysicalDevChunk **chunk) const {
        // Extract the chunk id from glob_uniq_id
        auto cid = glob_uniq_id.get_chunk_num();
        *chunk = m_mgr->get_chunk_mutable(cid);

        // Offset within the physical device
        uint64_t offset = (glob_uniq_id.get_id() * get_blk_size()) - (*chunk)->get_physical_dev()->get_dev_offset();

        // Offset within the chunk
        uint64_t chunk_offset = offset - (*chunk)->get_start_offset();
        return BlkId(chunk_offset/get_blk_size(), glob_uniq_id.get_nblks(), 0);
    }

    uint64_t to_dev_offset(const BlkId &glob_uniq_id, PhysicalDevChunk **chunk) const {
        *chunk = m_mgr->get_chunk_mutable(glob_uniq_id.get_chunk_num());

        // Offset within the physical device for a given chunk
        return (glob_uniq_id.get_id() * get_blk_size()) - (*chunk)->get_physical_dev()->get_dev_offset();
    }

    uint64_t to_chunk_offset(const BlkId &glob_uniq_id, PhysicalDevChunk **chunk) const {
        return (to_dev_offset(glob_uniq_id, chunk) - (*chunk)->get_start_offset());
    }

    uint32_t get_blks_per_chunk() const {
        return get_chunk_size() / get_blk_size();
    }

    uint32_t get_blk_size() const {
        return m_vb->blk_size;
    }

    uint64_t get_chunk_size() const {
        return m_chunk_size;
    }

    uint32_t get_nmirrors() const {
        return m_vb->num_mirrors;
    }

#if 0
private:
    homeds::avector< PhysicalDev *> m_phys_dev_list;

    // Array of physical devices each having multiple chunks that are relevant to this virtual device
    homeds::avector< std::vector< PhysicalDevChunk * > > m_primary_chunks_in_physdev;

    uint64_t m_size;       // Size of this virtual device
    uint32_t m_nmirrors;   // Total number of mirrors need to be maintained
    bool m_is_striped;     // If volume is striped across all physical device

    uint32_t m_dev_blk_size; // Block size used for this virtual device. Each vdev can have different block sizes

    std::atomic< uint64_t > m_total_allocations; // Keep track of total allocations.

    VirtualDev(uint64_t size, uint32_t nmirror, bool is_stripe, uint32_t dev_blk_size,
                       const std::vector< std::unique_ptr< PhysicalDev > > &phys_dev_list) :
            m_size(size),
            m_nmirrors(nmirror),
            m_is_striped(is_stripe),
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
                for (auto j : boost::irange<uint32_t>(0, nmirror)) {
                    if ((++next_ind) == phys_dev_list.size()) {
                        next_ind = 0;
                    }
                    vec.push_back(create_dev_chunk(next_ind, m_chunk_size, ba));
                }
                m_mirror_chunks.emplace(std::make_pair(chunk, vec));
            }
        }

        m_selector = std::make_unique<DefaultDeviceSelector>();
    }
#endif
};

} //namespace homestore
#endif //OMSTORE_VIRTUAL_DEV_HPP_HPP
