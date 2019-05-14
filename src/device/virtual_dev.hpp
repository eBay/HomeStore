//
// Created by Kadayam, Hari on 08/11/17.
//
#pragma once

#include <sds_logging/logging.h>

#include "device.h"
#include "blkalloc/blk_allocator.h"
#include "blkalloc/varsize_blk_allocator.h"
#include <vector>
#include <memory>
#include <boost/range/irange.hpp>
#include <map>
#include <error/error.h>
#include <metrics/metrics.hpp>
#include <utility/atomic_counter.hpp>
#include "main/homestore_header.hpp"

namespace homestore {

#define VDEV_LABEL " for Homestore Virtual Device"
#define PHYSICAL_HIST "physical"

class VdevFixedBlkAllocatorPolicy {
public:
    typedef FixedBlkAllocator AllocatorType;
    typedef BlkAllocConfig    AllocatorConfig;

    static void get_config(uint64_t size, uint32_t vpage_size, BlkAllocConfig* out_config) {
        /* for fixed block allocator page and block size is kept same as it doesn't make any
         * difference.
         */
        out_config->set_blk_size(vpage_size);
        out_config->set_total_blks(size / vpage_size);
    }
};

class VdevVarSizeBlkAllocatorPolicy {
public:
    typedef VarsizeBlkAllocator   AllocatorType;
    typedef VarsizeBlkAllocConfig AllocatorConfig;

    static void get_config(uint64_t size, uint32_t vpage_size, BlkAllocConfig* out_config) {
        VarsizeBlkAllocConfig* vconfig = (VarsizeBlkAllocConfig*)out_config;

        vconfig->set_blk_size(vpage_size);
        vconfig->set_phys_page_size(HomeStoreConfig::phys_page_size); // SSD Page size.
        vconfig->set_blks_per_portion(BLKS_PER_PORTION);              // Have locking etc for every 1024 pages
        vconfig->set_total_segments(TOTAL_SEGMENTS);                  // 8 Segments per chunk

        assert((size % MIN_CHUNK_SIZE) == 0);

        vconfig->set_total_blks(((uint64_t)size) / vpage_size);
        vconfig->set_blks_per_temp_group(100); // TODO: Recalculate based on size set aside for temperature entries
        vconfig->set_max_cache_blks(vconfig->get_total_blks() / 4); // Cache quarter of the blocks
        /* Blk sizes in slabs : nblks < 1, nblks < 2, 2 <= nblks < 4,
         * 4 <= nblks < 8, 8 <= nblks < 16, nblks >= 16
         */
        int num_slabs = 10;
        std::vector< uint32_t > slab_limits(num_slabs - 1, 0);
        std::vector< float >    slab_weights(num_slabs, 0.1); // (1 / num_slabs) = 0.1
        for (auto i = 0U; i < slab_limits.size(); i++) {
            slab_limits[i] = (1 << i);
        }
        vconfig->set_slab(slab_limits, slab_weights);
    }
};

struct pdev_chunk_map {
    PhysicalDev*                     pdev;
    std::vector< PhysicalDevChunk* > chunks_in_pdev;
};

struct virtualdev_req;

typedef std::function< void(boost::intrusive_ptr< virtualdev_req > req) > virtualdev_comp_callback;
#define to_vdev_req(req) boost::static_pointer_cast< virtualdev_req >(req)

struct virtualdev_req : public sisl::ObjLifeCounter< virtualdev_req > {
    uint64_t                    version;
    virtualdev_comp_callback    cb;
    uint64_t                    size;
    std::error_condition        err;
    bool                        is_read;
    bool                        isSyncCall;
    sisl::atomic_counter< int > refcount;
    PhysicalDevChunk*           chunk;
    Clock::time_point           io_start_time;

    void inc_ref() { intrusive_ptr_add_ref(this); }
    void dec_ref() { intrusive_ptr_release(this); }

    static boost::intrusive_ptr< virtualdev_req > make_request() {
        return boost::intrusive_ptr< virtualdev_req >(homeds::ObjectAllocator< virtualdev_req >::make_object());
    }
    virtual void free_yourself() { homeds::ObjectAllocator< virtualdev_req >::deallocate(this); }

    friend void intrusive_ptr_add_ref(virtualdev_req* req) { req->refcount.increment(1); }
    friend void intrusive_ptr_release(virtualdev_req* req) {
        if (req->refcount.decrement_testz()) {
            req->free_yourself();
        }
    }
    virtual ~virtualdev_req() { version = 0; }

protected:
    friend class homeds::ObjectAllocator< virtualdev_req >;
    virtualdev_req() : err(no_error), is_read(false), isSyncCall(false), refcount(0) {}
};

[[maybe_unused]] static void virtual_dev_process_completions(int64_t res, uint8_t* cookie) {
    int ret = 0;

    boost::intrusive_ptr< virtualdev_req > vd_req((virtualdev_req*)cookie, false);
    assert(vd_req->version == 0xDEAD);

    if (vd_req->err == no_error && res < 0) {
        /* TODO: it should have more specific errors */
        vd_req->err = std::make_error_condition(std::io_errc::stream);
    }

    auto pdev = vd_req->chunk->get_physical_dev_mutable();
    if (vd_req->err) {
        COUNTER_INCREMENT_IF_ELSE(pdev->get_metrics(), vd_req->is_read, drive_read_errors, drive_write_errors, 1);
        pdev->device_manager()->handle_error(pdev);
    } else {
        HISTOGRAM_OBSERVE_IF_ELSE(pdev->get_metrics(), vd_req->is_read, drive_read_latency, drive_write_latency,
                                  get_elapsed_time_us(vd_req->io_start_time));
    }

    vd_req->cb(vd_req);
    // NOTE: Beyond this point vd_req could be freed by the callback. So once callback is made,
    // DO NOT ACCESS vd_req beyond this point.
}

#if 0
class VirtualDevMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit VirtualDevMetrics(const char *inst_name) : sisl::MetricsGroupWrapper("VirtualDev", inst_name) {
        REGISTER_COUNTER(blkstore_reads_count, "BlkStore total reads");
        REGISTER_COUNTER(blkstore_writes_count, "BlkStore total writes");
        REGISTER_COUNTER(blkstore_cache_hits_count, "BlkStore Cache hits");

        REGISTER_HISTOGRAM(blkstore_cache_read_latency, "BlkStore cache read latency");
        REGISTER_HISTOGRAM(blkstore_cache_write_latency, "BlkStore cache write latency");
        REGISTER_HISTOGRAM(blkstore_drive_write_latency, "BlkStore driver write latency");

        register_me_to_farm();
    }
};
#endif

/*
 * VirtualDev: Virtual device implements a similar functionality of RAID striping, customized however. Virtual devices
 * can be created across multiple physical devices. Unlike RAID, its io is not always in a bigger strip sizes. It
 * support n-mirrored writes.
 *
 * Template parameters:
 * Allocator: The type of AllocatorPolicy to allocate blocks for writes.
 * DefaultDeviceSelector: Which device to select for allocation
 */

template < typename Allocator, typename DefaultDeviceSelector >
class VirtualDev : public AbstractVirtualDev {
    typedef std::function< void(boost::intrusive_ptr< virtualdev_req > req) > comp_callback;

private:
    vdev_info_block* m_vb;         // This device block info
    DeviceManager*   m_mgr;        // Device Manager back pointer
    uint64_t         m_chunk_size; // Chunk size that will be allocated in a physical device
    std::mutex       m_mgmt_mutex; // Any mutex taken for management operations (like adding/removing chunks).

    // List of physical devices this virtual device uses and its corresponding chunks for the physdev
    std::vector< pdev_chunk_map > m_primary_pdev_chunks_list;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::map< PhysicalDevChunk*, std::vector< PhysicalDevChunk* > > m_mirror_chunks;

    // Instance of device selector
    std::unique_ptr< DefaultDeviceSelector > m_selector;
    uint32_t                                 m_num_chunks;
    comp_callback                            m_comp_cb;
    uint32_t                                 m_pagesz;
    std::atomic<uint64_t>                    m_used_size;

public:
    /* Create a new virtual dev for these parameters */
    VirtualDev(DeviceManager* mgr, uint64_t context_size, uint32_t nmirror, bool is_stripe, uint32_t page_size,
               const std::vector< PhysicalDev* >& pdev_list, comp_callback cb, char* blob, uint64_t size) :
            m_comp_cb(cb), m_used_size(0) {
        m_mgr = mgr;
        m_pagesz = page_size;

        // Now its time to allocate chunks as needed
        assert(nmirror < pdev_list.size()); // Mirrors should be at least one less than device list.

        if (is_stripe) {
            m_chunk_size = ((size - 1) / pdev_list.size()) + 1;
            m_num_chunks = (uint32_t)pdev_list.size();
        } else {
            m_chunk_size = size;
            m_num_chunks = 1;
        }

        if (m_chunk_size % MIN_CHUNK_SIZE) {
            m_chunk_size = ALIGN_SIZE(m_chunk_size, MIN_CHUNK_SIZE);
            LOGINFO("size of a chunk is resized to {}", m_chunk_size);
        }

        /* make size multiple of chunk size */
        size = m_chunk_size * m_num_chunks;

        // Create a new vdev in persistent area and get the block of it
        m_vb = mgr->alloc_vdev(context_size, nmirror, page_size, m_num_chunks, blob, size);

        // Prepare primary chunks in a physical device for future inserts.
        m_primary_pdev_chunks_list.reserve(pdev_list.size());
        for (auto pdev : pdev_list) {
            pdev_chunk_map mp;
            mp.pdev = pdev;
            mp.chunks_in_pdev.reserve(1);

            m_primary_pdev_chunks_list.push_back(mp);
        }

        for (auto i : boost::irange< uint32_t >(0, m_num_chunks)) {
            std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size, i, true);
            auto                            pdev_ind = i % pdev_list.size();

            // Create a chunk on selected physical device and add it to chunks in physdev list
            auto chunk = create_dev_chunk(pdev_ind, ba, INVALID_CHUNK_ID);
            m_primary_pdev_chunks_list[pdev_ind].chunks_in_pdev.push_back(chunk);

            // If we have mirror, create a map between chunk and its mirrored chunks
            if (nmirror) {
                uint32_t                         next_ind = i;
                std::vector< PhysicalDevChunk* > vec;
                vec.reserve(nmirror);
                for (auto j : boost::irange< uint32_t >(0, nmirror)) {
                    if ((++next_ind) == m_primary_pdev_chunks_list.size()) {
                        next_ind = 0;
                    }
                    auto mchunk = create_dev_chunk(next_ind, ba, chunk->get_chunk_id());
                    vec.push_back(mchunk);
                }
                m_mirror_chunks.emplace(std::make_pair(chunk, vec));
            }
        }

        m_selector = std::make_unique< DefaultDeviceSelector >();
        for (auto& pdev : pdev_list) {
            m_selector->add_pdev(pdev);
        }
    }

    void reset_failed_state() {
        m_vb->failed = false;
        m_mgr->write_info_blocks();
    }

    void process_completions(boost::intrusive_ptr< virtualdev_req > req) {
        m_comp_cb(req);
        /* XXX:we probably have to do something if a write/read is spread
         * across the chunks from this layer.
         */
    }

    /* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
    VirtualDev(DeviceManager* mgr, vdev_info_block* vb, comp_callback cb) : m_vb(vb), m_mgr(mgr), m_comp_cb(cb) {
        m_selector = std::make_unique< DefaultDeviceSelector >();
        m_chunk_size = 0;
        m_num_chunks = 0;
        m_pagesz = vb->page_size;
        m_mgr->add_chunks(vb->vdev_id, [this](PhysicalDevChunk* chunk) { add_chunk(chunk); });

        assert((vb->num_primary_chunks * (vb->num_mirrors + 1)) == m_num_chunks);
        assert(vb->size == (vb->num_primary_chunks * m_chunk_size));
    }

    ~VirtualDev() = default;

    /* This method adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
     * takes lock for writing and not reading
     */
    virtual void add_chunk(PhysicalDevChunk* chunk) override {
        LOGINFO("Adding chunk {} from vdev id {} from pdev id = {}", chunk->get_chunk_id(), chunk->get_vdev_id(),
                chunk->get_physical_dev()->get_dev_id());
        std::lock_guard< decltype(m_mgmt_mutex) > lock(m_mgmt_mutex);
        m_num_chunks++;
        (chunk->get_primary_chunk()) ? add_mirror_chunk(chunk) : add_primary_chunk(chunk);
    }

    bool is_blk_alloced(BlkId& in_blkid) {
        PhysicalDevChunk* primary_chunk;
        uint64_t          primary_dev_offset = to_dev_offset(in_blkid, &primary_chunk);
        auto              blkid = to_chunk_specific_id(in_blkid, &primary_chunk);
        return (primary_chunk->get_blk_allocator()->is_blk_alloced(blkid));
    }

    BlkAllocStatus alloc_blk(BlkId& in_blkid) {
        PhysicalDevChunk* primary_chunk;
        uint64_t          primary_dev_offset = to_dev_offset(in_blkid, &primary_chunk);
        auto              blkid = to_chunk_specific_id(in_blkid, &primary_chunk);
        auto size = m_used_size.fetch_add(in_blkid.data_size(m_pagesz), std::memory_order_relaxed);
        assert(size <= get_size());
        return (primary_chunk->get_blk_allocator()->alloc(blkid));
    }

    BlkAllocStatus alloc_blk(uint8_t nblks, const blk_alloc_hints& hints, BlkId* out_blkid) {
        BlkAllocStatus ret;
        try {
            std::vector< BlkId > blkid;
            assert(hints.is_contiguous);
            ret = alloc_blk(nblks, hints, blkid);
            if (ret == BLK_ALLOC_SUCCESS) {
                *out_blkid = blkid[0];
                assert(blkid.size() <= HomeStoreConfig::atomic_phys_page_size);
            } else {
                assert(blkid.size() == 0);
            }
        } catch (const std::exception& e) {
            ret = BLK_ALLOC_FAILED;
            assert(0);
            LOGERROR("{}", e.what());
        }
        return ret;
    }

    BlkAllocStatus alloc_blk(uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) {
        try {
            uint32_t       dev_ind{0};
            uint32_t       chunk_num, start_chunk_num;
            BlkAllocStatus status = BLK_ALLOC_FAILED;

            // First select a device to allocate from
            if (hints.dev_id_hint == -1) {
                dev_ind = m_selector->select(hints);
            } else {
                dev_ind = (uint32_t)hints.dev_id_hint;
            }

            // m_total_allocations++;

            // Pick a physical chunk based on physDevId.
            // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple
            // chunks. In that case just using physDevId as chunk number is not right strategy.
            uint32_t          start_dev_ind = dev_ind;
            PhysicalDevChunk* picked_chunk = nullptr;

            do {
                for (auto chunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
#ifdef _PRERELEASE
                    if (auto fake_status = homestore_flip->get_test_flip<uint32_t>(
                                                                "blk_allocation_flip", nblks, chunk->get_vdev_id())) {
                            return (BlkAllocStatus)fake_status.get();
                    }
#endif

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
                dev_ind = (uint32_t)((dev_ind + 1) % m_primary_pdev_chunks_list.size());
            } while (dev_ind != start_dev_ind);

            if (status == BLK_ALLOC_SUCCESS) {
                // Set the id as globally unique id
                uint64_t tot_size = 0;
                for (uint32_t i = 0; i < out_blkid.size(); i++) {
                    out_blkid[i] = to_glob_uniq_blkid(out_blkid[i], picked_chunk);
                    tot_size += out_blkid[i].data_size(m_pagesz);
                }
                auto size = m_used_size.fetch_add(tot_size, std::memory_order_relaxed);
                assert(size <= get_size());
            }
            return status;
        } catch (const std::exception& e) {
            assert(0);
            LOGERROR("{}", e.what());
            return BLK_ALLOC_FAILED;
        }
    }

    void free_blk(const BlkId& b) {
        PhysicalDevChunk* chunk;

        // Convert blk id to chunk specific id and call its allocator to free
        BlkId cb = to_chunk_specific_id(b, &chunk);
        chunk->get_blk_allocator()->free(cb);
        m_used_size.fetch_sub(b.data_size(m_pagesz), std::memory_order_relaxed);
        assert(m_used_size.load() >= 0);
    }

    void write(const BlkId& bid, const homeds::MemVector& buf, boost::intrusive_ptr< virtualdev_req > req,
               uint32_t data_offset = 0) {
        BlkOpStatus  ret_status = BLK_OP_SUCCESS;
        uint32_t     size = bid.get_nblks() * get_page_size();
        struct iovec iov[BlkId::max_blks_in_op()];
        int          iovcnt = 0;

        uint32_t p = 0;
        uint32_t end_offset = data_offset + bid.data_size(m_pagesz);
        while (data_offset != end_offset) {
            homeds::blob b;
            buf.get(&b, data_offset);
            iov[iovcnt].iov_base = b.bytes;
            if (data_offset + b.size > end_offset) {
                iov[iovcnt].iov_len = end_offset - data_offset;
            } else {
                iov[iovcnt].iov_len = b.size;
            }
            data_offset += iov[iovcnt].iov_len;
            iovcnt++;
        }

        assert(data_offset == end_offset);
        PhysicalDevChunk* chunk;

        uint64_t dev_offset = to_dev_offset(bid, &chunk);
        if (req) {
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->chunk = chunk;
        }

        auto pdev = chunk->get_physical_dev_mutable();
        LOG(INFO) << "Writing in device " << pdev->get_dev_id() << " offset = " << dev_offset;
        COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, iovcnt);

        if (!req || req->isSyncCall) {
            auto start_time = Clock::now();
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            pdev->sync_writev(iov, iovcnt, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);

            req->inc_ref();
            req->io_start_time = Clock::now();
            pdev->writev(iov, iovcnt, size, dev_offset, (uint8_t*)req.get());
        }

        if (get_nmirrors()) {
            uint64_t primary_chunk_offset = dev_offset - chunk->get_start_offset();

            // Write to the mirror as well
            for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
                for (auto mchunk : m_mirror_chunks.find(chunk)->second) {
                    dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

                    // We do not support async mirrored writes yet.
                    assert((req == nullptr) || req->isSyncCall);
                    auto pdev = mchunk->get_physical_dev_mutable();

                    COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
                    auto start_time = Clock::now();
                    pdev->sync_writev(iov, iovcnt, size, dev_offset);
                    HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
                }
            }
        }
    }

    void read_nmirror(const BlkId& bid, std::vector< boost::intrusive_ptr< homeds::MemVector > > mp, uint64_t size,
                      uint32_t nmirror) {
        assert(nmirror <= get_nmirrors());
        uint32_t          cnt = 0;
        PhysicalDevChunk* primary_chunk;
        uint64_t          primary_dev_offset = to_dev_offset(bid, &primary_chunk);
        uint64_t          primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();

        homeds::blob b;
        mp[cnt]->get(&b, 0);
        assert(b.size == bid.data_size(m_pagesz));
        primary_chunk->get_physical_dev_mutable()->sync_read((char*)b.bytes, b.size, primary_dev_offset);
        if (cnt == nmirror) {
            return;
        }
        ++cnt;
        for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
            uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

            mp[cnt]->get(&b, 0);
            assert(b.size == bid.data_size(m_pagesz));
            mchunk->get_physical_dev_mutable()->sync_read((char*)b.bytes, b.size, dev_offset);

            if (cnt == nmirror) {
                break;
            }
        }
    }

    /* Read the data for a given BlkId. With this method signature, virtual dev can read only in block boundary
     * and nothing in-between offsets (say if blk size is 8K it cannot read 4K only, rather as full 8K. It does not
     * have offset as one of the parameter. Reason for that is its actually ok and make the interface and also
     * buf (caller buf) simple and there is no use case. However, we need to keep the blk size to be small as possible
     * to avoid read overhead */
    void read(const BlkId& bid, const homeds::MemPiece& mp, boost::intrusive_ptr< virtualdev_req > req) {
        PhysicalDevChunk* primary_chunk;

        uint64_t primary_dev_offset = to_dev_offset(bid, &primary_chunk);
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
        req->size = mp.size();
        req->chunk = primary_chunk;
        req->io_start_time = Clock::now();

        auto pdev = primary_chunk->get_physical_dev_mutable();
        if (req->isSyncCall) {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
            pdev->sync_read((char*)mp.ptr(), mp.size(), primary_dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(req->io_start_time));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);

            req->inc_ref();
            pdev->read((char*)mp.ptr(), mp.size(), primary_dev_offset, (uint8_t*)req.get());
        }

        if (hs_unlikely(get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            uint64_t primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
                uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                auto     pdev = mchunk->get_physical_dev_mutable();
                assert((req == nullptr) || req->isSyncCall);

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
                auto start_time = Clock::now();
                pdev->sync_read((char*)mp.ptr(), mp.size(), dev_offset);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start_time));
            }
        }
    }

    void readv(const BlkId& bid, const homeds::MemVector& buf, boost::intrusive_ptr< virtualdev_req > req) {
        // Convert the input memory to iovector
        struct iovec iov[BlkId::max_blks_in_op()];
        int          iovcnt = 0;
        uint32_t     size = buf.size();

        assert(buf.size() == (bid.get_nblks() * get_page_size())); // Expected to be less than allocated blk originally.
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
        for (auto i : boost::irange< uint32_t >(0, buf.npieces())) {
            homeds::blob b;
            buf.get(&b, i);

            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        PhysicalDevChunk* primary_chunk;
        uint64_t          primary_dev_offset = to_dev_offset(bid, &primary_chunk);

        auto pdev = primary_chunk->get_physical_dev_mutable();
        COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
        COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, iovcnt);

        req->size = size;
        req->inc_ref();
        req->chunk = primary_chunk;
        req->io_start_time = Clock::now();
        pdev->readv(iov, iovcnt, size, primary_dev_offset, (uint8_t*)req.get());

        if (hs_unlikely(get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            uint64_t primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
                uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;
                req->inc_ref();
                mchunk->get_physical_dev_mutable()->readv(iov, iovcnt, size, dev_offset, (uint8_t*)req.get());
            }
        }
    }

    void     update_vb_context(uint8_t* blob) { m_mgr->update_vb_context(m_vb->vdev_id, blob); }
    uint64_t get_size() const { return m_vb->size; }

    uint64_t get_used_size() const { return m_used_size.load(); }

    void expand(uint32_t addln_size) {}

    // Remove this virtualdev altogether
    void rm_device() {
        for (auto& pcm : m_primary_pdev_chunks_list) {
            for (auto& c : pcm.chunks_in_pdev) {
                m_mgr->free_chunk(c);
            }
        }

        for (auto& v : m_mirror_chunks) {
            for (auto& c : v.second) {
                m_mgr->free_chunk(c);
            }
        }

        m_mgr->free_vdev(m_vb);
    }

    auto to_string() { return std::string(); }

    uint64_t get_num_chunks() const { return m_num_chunks; }
    uint64_t get_chunk_size() const { return m_chunk_size; }

private:
    /* Adds a primary chunk to the chunk list in pdev */
    void add_primary_chunk(PhysicalDevChunk* chunk) {
        auto pdev_id = chunk->get_physical_dev()->get_dev_id();

        if (m_chunk_size == 0) {
            m_chunk_size = chunk->get_size();
        } else {
            assert(m_chunk_size == chunk->get_size());
        }

        pdev_chunk_map* found_pcm = nullptr;
        for (auto& pcm : m_primary_pdev_chunks_list) {
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
        assert(m_chunk_size <= MAX_CHUNK_SIZE);
        std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size, chunk->get_chunk_id(), false);
        chunk->set_blk_allocator(ba);

        /* set the same blk allocator to other mirror chunks */
        auto it = m_mirror_chunks.find(chunk);
        if (it != m_mirror_chunks.end()) {
            for (uint32_t i = 0; i < it->second.size(); ++i) {
                it->second[i]->set_blk_allocator(ba);
            }
        } else {
            // Not found, just create a new entry
            std::vector< PhysicalDevChunk* > vec;
            m_mirror_chunks.emplace(std::make_pair(chunk, vec));
        }
    }

    void add_mirror_chunk(PhysicalDevChunk* chunk) {
        auto pdev_id = chunk->get_physical_dev()->get_dev_id();
        auto pchunk = chunk->get_primary_chunk();

        if (m_chunk_size == 0) {
            m_chunk_size = chunk->get_size();
        } else {
            assert(m_chunk_size == chunk->get_size());
        }

        // Try to find the parent chunk in the map
        auto it = m_mirror_chunks.find(pchunk);
        if (it == m_mirror_chunks.end()) {
            // Not found, just create a new entry
            std::vector< PhysicalDevChunk* > vec;
            vec.push_back(chunk);
            m_mirror_chunks.emplace(std::make_pair(pchunk, vec));
        } else {
            it->second.push_back(chunk);
            chunk->set_blk_allocator(pchunk->get_blk_allocator());
        }
    }

    std::shared_ptr< BlkAllocator > create_allocator(uint64_t size, uint32_t unique_id, bool init) {
        typename Allocator::AllocatorConfig cfg(std::string("chunk_") + std::to_string(unique_id));
        Allocator::get_config(size, get_page_size(), &cfg);

        std::shared_ptr< BlkAllocator > allocator = std::make_shared< typename Allocator::AllocatorType >(cfg, init);
        return allocator;
    }

    PhysicalDevChunk* create_dev_chunk(uint32_t pdev_ind, std::shared_ptr< BlkAllocator > ba, uint32_t primary_id) {
        auto              pdev = m_primary_pdev_chunks_list[pdev_ind].pdev;
        PhysicalDevChunk* chunk = m_mgr->alloc_chunk(pdev, m_vb->vdev_id, m_chunk_size, primary_id);
        LOGINFO("Allocating new chunk for vdev_id = {} pdev_id = {} chunk: {}", m_vb->vdev_id, pdev->get_dev_id(),
                chunk->to_string());
        chunk->set_blk_allocator(ba);

        return chunk;
    }

    BlkId to_glob_uniq_blkid(const BlkId& chunk_local_blkid, PhysicalDevChunk* chunk) const {
        uint64_t glob_offset = ((chunk_local_blkid.get_id() * get_page_size()) + chunk->get_start_offset() +
                                chunk->get_physical_dev()->get_dev_offset());
        return BlkId(glob_offset / get_page_size(), chunk_local_blkid.get_nblks(), chunk->get_chunk_id());
    }

    BlkId to_chunk_specific_id(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const {
        // Extract the chunk id from glob_uniq_id
        auto cid = glob_uniq_id.get_chunk_num();
        *chunk = m_mgr->get_chunk_mutable(cid);

        // Offset within the physical device
        uint64_t offset = (glob_uniq_id.get_id() * get_page_size()) - (*chunk)->get_physical_dev()->get_dev_offset();

        // Offset within the chunk
        uint64_t chunk_offset = offset - (*chunk)->get_start_offset();
        return BlkId(chunk_offset / get_page_size(), glob_uniq_id.get_nblks(), 0);
    }

    uint64_t to_dev_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const {
        *chunk = m_mgr->get_chunk_mutable(glob_uniq_id.get_chunk_num());

        // Offset within the physical device for a given chunk
        return (glob_uniq_id.get_id() * get_page_size()) - (*chunk)->get_physical_dev()->get_dev_offset();
    }

    uint64_t to_chunk_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const {
        return (to_dev_offset(glob_uniq_id, chunk) - (*chunk)->get_start_offset());
    }

    uint32_t get_blks_per_chunk() const { return get_chunk_size() / get_page_size(); }
    uint32_t get_page_size() const { return m_vb->page_size; }
    uint32_t get_nmirrors() const { return m_vb->num_mirrors; }
};

} // namespace homestore
