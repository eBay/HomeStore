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
#include "main/homestore_assert.hpp"

SDS_LOGGING_DECL(device)

namespace homestore {

#define VDEV_LABEL " for Homestore Virtual Device"
#define PHYSICAL_HIST "physical"

class VdevFixedBlkAllocatorPolicy {
public:
    typedef FixedBlkAllocator AllocatorType;
    typedef BlkAllocConfig AllocatorConfig;

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
    typedef VarsizeBlkAllocator AllocatorType;
    typedef VarsizeBlkAllocConfig AllocatorConfig;

    static void get_config(uint64_t size, uint32_t vpage_size, BlkAllocConfig* out_config) {
        VarsizeBlkAllocConfig* vconfig = (VarsizeBlkAllocConfig*)out_config;

        vconfig->set_blk_size(vpage_size);
        vconfig->set_phys_page_size(HomeStoreConfig::phys_page_size); // SSD Page size.
        vconfig->set_blks_per_portion(BLKS_PER_PORTION);              // Have locking etc for every 1024 pages
        vconfig->set_total_segments(TOTAL_SEGMENTS);                  // 8 Segments per chunk

        HS_ASSERT_CMP(DEBUG, size % MIN_CHUNK_SIZE, ==, 0);

        vconfig->set_total_blks(((uint64_t)size) / vpage_size);
        vconfig->set_blks_per_temp_group(100); // TODO: Recalculate based on size set aside for temperature entries
        vconfig->set_max_cache_blks(vconfig->get_total_blks() / 4); // Cache quarter of the blocks
        /* Blk sizes in slabs : nblks < 1, nblks < 2, 2 <= nblks < 4,
         * 4 <= nblks < 8, 8 <= nblks < 16, nblks >= 16
         */
        int num_slabs = 10;
        std::vector< uint32_t > slab_limits(num_slabs - 1, 0);
        std::vector< float > slab_weights(num_slabs, 0.1); // (1 / num_slabs) = 0.1
        for (auto i = 0U; i < slab_limits.size(); i++) {
            slab_limits[i] = (1 << i);
        }
        vconfig->set_slab(slab_limits, slab_weights);
    }
};

struct pdev_chunk_map {
    PhysicalDev* pdev;
    std::vector< PhysicalDevChunk* > chunks_in_pdev;
};

struct virtualdev_req;

typedef std::function< void(boost::intrusive_ptr< virtualdev_req > req) > virtualdev_comp_callback;
#define to_vdev_req(req) boost::static_pointer_cast< virtualdev_req >(req)

struct virtualdev_req : public sisl::ObjLifeCounter< virtualdev_req > {
    uint64_t request_id;
    uint64_t version;
    virtualdev_comp_callback cb;
    uint64_t size;
    std::error_condition err;
    bool is_read;
    bool isSyncCall;
    sisl::atomic_counter< int > refcount;
    PhysicalDevChunk* chunk;
    Clock::time_point io_start_time;
    std::atomic< uint8_t > outstanding_cb = 0;

    void inc_ref() { intrusive_ptr_add_ref(this); }
    void dec_ref() { intrusive_ptr_release(this); }

    static boost::intrusive_ptr< virtualdev_req > make_request() {
        return boost::intrusive_ptr< virtualdev_req >(sisl::ObjectAllocator< virtualdev_req >::make_object());
    }
    virtual void free_yourself() { sisl::ObjectAllocator< virtualdev_req >::deallocate(this); }

    friend void intrusive_ptr_add_ref(virtualdev_req* req) { req->refcount.increment(1); }
    friend void intrusive_ptr_release(virtualdev_req* req) {
        if (req->refcount.decrement_testz()) { req->free_yourself(); }
    }
    virtual ~virtualdev_req() { version = 0; }

protected:
    friend class sisl::ObjectAllocator< virtualdev_req >;
    virtualdev_req() : request_id(0), err(no_error), is_read(false), isSyncCall(false), refcount(0) {}
};

[[maybe_unused]] static void virtual_dev_process_completions(int64_t res, uint8_t* cookie) {
    int ret = 0;

    boost::intrusive_ptr< virtualdev_req > vd_req((virtualdev_req*)cookie, false);
    HS_ASSERT_CMP(DEBUG, vd_req->version, ==, 0xDEAD);

    if (vd_req->err == no_error && res != 0) {
        LOGERROR("seeing error on request id {} error {}", vd_req->request_id, res);
        /* TODO: it should have more specific errors */
        vd_req->err = std::make_error_condition(std::io_errc::stream);
    }

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_write_comp_error_flip")) { vd_req->err = write_failed; }

    if (homestore_flip->test_flip("io_read_comp_error_flip")) { vd_req->err = read_failed; }
#endif

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
const uint32_t VIRDEV_BLKSIZE = 512;
const uint64_t CHUNK_EOF = 0xabcdabcd;
const off_t INVALID_OFFSET = std::numeric_limits< unsigned long long >::max();

template < typename Allocator, typename DefaultDeviceSelector >
class VirtualDev : public AbstractVirtualDev {
    typedef std::function< void(boost::intrusive_ptr< virtualdev_req > req) > comp_callback;

    struct Chunk_EOF_t {
        uint64_t e;
    };

    typedef union {
        struct Chunk_EOF_t eof;
        unsigned char padding[VIRDEV_BLKSIZE];
    } Chunk_EOF;

    static_assert(sizeof(Chunk_EOF) == VIRDEV_BLKSIZE, "LogDevRecordHeader must be VIRDEV_SIZE bytes");

private:
    vdev_info_block* m_vb;   // This device block info
    DeviceManager* m_mgr;    // Device Manager back pointer
    uint64_t m_chunk_size;   // Chunk size that will be allocated in a physical device
    std::mutex m_mgmt_mutex; // Any mutex taken for management operations (like adding/removing chunks).

    // List of physical devices this virtual device uses and its corresponding chunks for the physdev
    std::vector< pdev_chunk_map > m_primary_pdev_chunks_list;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::map< PhysicalDevChunk*, std::vector< PhysicalDevChunk* > > m_mirror_chunks;

    // Instance of device selector
    std::unique_ptr< DefaultDeviceSelector > m_selector;
    uint32_t m_num_chunks;
    comp_callback m_comp_cb;
    uint32_t m_pagesz;
    bool m_recovery_init;
    std::atomic< uint64_t > m_used_size;

    // data structure for append write
    uint64_t            m_reserved_sz = 0;          // write size within chunk, used to check chunk boundary;
    uint64_t            m_write_sz_in_total = 0;    // this size will be decreased by truncate and increased by append;
    off_t               m_seek_cursor = 0;          // the seek cursor

public:
    static constexpr size_t context_data_size() {
        return MAX_CONTEXT_DATA_SZ;
    }

    void init(DeviceManager* mgr, vdev_info_block* vb, comp_callback cb, uint32_t page_size) {
        m_mgr = mgr;
        m_vb = vb;
        m_comp_cb = cb;
        m_used_size = 0;
        m_chunk_size = 0;
        m_num_chunks = 0;
        m_pagesz = page_size;
        m_selector = std::make_unique< DefaultDeviceSelector >();
        m_recovery_init = false;
        // m_write_sz_in_chunk.store(0, std::memory_order_relaxed);
        m_write_sz_in_total = 0;
        m_reserved_sz = 0;
    }

    /* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
    VirtualDev(DeviceManager* mgr, vdev_info_block* vb, comp_callback cb, bool recovery_init) {
        init(mgr, vb, cb, vb->page_size);

        m_recovery_init = recovery_init;
        m_mgr->add_chunks(vb->vdev_id, [this](PhysicalDevChunk* chunk) { add_chunk(chunk); });

        HS_ASSERT_CMP(LOGMSG, vb->num_primary_chunks * (vb->num_mirrors + 1), ==,
                      m_num_chunks); // Mirrors should be at least one less than device list.
        HS_ASSERT_CMP(LOGMSG, vb->get_size(), ==, vb->num_primary_chunks * m_chunk_size);
    }

    /* Create a new virtual dev for these parameters */
    VirtualDev(DeviceManager* mgr, uint64_t context_size, uint32_t nmirror, bool is_stripe, uint32_t page_size,
               const std::vector< PhysicalDev* >& pdev_list, comp_callback cb, char* blob, uint64_t size) {
        init(mgr, nullptr, cb, page_size);

        // Now its time to allocate chunks as needed
        HS_ASSERT_CMP(LOGMSG, nmirror, <, pdev_list.size()); // Mirrors should be at least one less than device list.

        if (is_stripe) {
            m_chunk_size = ((size - 1) / pdev_list.size()) + 1;
            m_num_chunks = (uint32_t)pdev_list.size();
        } else {
            m_chunk_size = size;
            m_num_chunks = 1;
        }

        if (m_chunk_size % MIN_CHUNK_SIZE) {
            m_chunk_size = ALIGN_SIZE(m_chunk_size, MIN_CHUNK_SIZE);
            HS_LOG(INFO, device, "size of a chunk is resized to {}", m_chunk_size);
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
            auto pdev_ind = i % pdev_list.size();

            // Create a chunk on selected physical device and add it to chunks in physdev list
            auto chunk = create_dev_chunk(pdev_ind, ba, INVALID_CHUNK_ID);
            m_primary_pdev_chunks_list[pdev_ind].chunks_in_pdev.push_back(chunk);

            // If we have mirror, create a map between chunk and its mirrored chunks
            if (nmirror) {
                uint32_t next_ind = i;
                std::vector< PhysicalDevChunk* > vec;
                vec.reserve(nmirror);
                for (auto j : boost::irange< uint32_t >(0, nmirror)) {
                    if ((++next_ind) == m_primary_pdev_chunks_list.size()) { next_ind = 0; }
                    auto mchunk = create_dev_chunk(next_ind, ba, chunk->get_chunk_id());
                    vec.push_back(mchunk);
                }
                m_mirror_chunks.emplace(std::make_pair(chunk, vec));
            }
        }

        for (auto& pdev : pdev_list) {
            m_selector->add_pdev(pdev);
        }
    }

    void reset_failed_state() {
        m_vb->failed = false;
        m_mgr->write_info_blocks();
    }

    void process_completions(boost::intrusive_ptr< virtualdev_req > req) {
        if (req->outstanding_cb.load() > 0) { req->outstanding_cb.fetch_sub(1, std::memory_order_relaxed); }

        if (req->outstanding_cb.load() == 0) { m_comp_cb(req); }

        /* XXX:we probably have to do something if a write/read is spread
         *
         * across the chunks from this layer.
         */
    }

    ~VirtualDev() = default;

    /* This method adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
     * takes lock for writing and not reading
     */
    virtual void add_chunk(PhysicalDevChunk* chunk) override {
        HS_LOG(INFO, device, "Adding chunk {} from vdev id {} from pdev id = {}", chunk->get_chunk_id(),
               chunk->get_vdev_id(), chunk->get_physical_dev()->get_dev_id());
        std::lock_guard< decltype(m_mgmt_mutex) > lock(m_mgmt_mutex);
        m_num_chunks++;
        (chunk->get_primary_chunk()) ? add_mirror_chunk(chunk) : add_primary_chunk(chunk);
    }

    // start of vdev interface stubs
 
    off_t data_start_offset() { return m_vb->data_start_offset; }

    // 
    // Supposed to be called when truncate happens;
    //
    void update_data_start_offset(off_t offset) { 
        m_vb->data_start_offset = offset; 
        // call device manager to update it's in-memory copy and persist this field to disk;
        m_mgr->update_vb_data_start_offset(m_vb->vdev_id, offset);
    }

    off_t get_reserved_tail_offset() {
        return data_start_offset() + m_write_sz_in_total + m_reserved_sz;
    }

    uint64_t get_used_space() {
        return m_write_sz_in_total + m_reserved_sz;
    }

    // 
    // TODO: organize chunks in a vector so that we can get next chunk id easily;
    //
    PhysicalDevChunk* get_next_chunk(uint32_t dev_id, uint32_t chunk_id) {
        if ((chunk_id + 1) < m_primary_pdev_chunks_list[dev_id].chunks_in_pdev.size()) {
            // next chunk is within same dev;
            chunk_id++;
        } else {
            // move next dev
            dev_id = ((dev_id + 1) % m_primary_pdev_chunks_list.size());
            chunk_id = 0;
        }
        return  m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
    }

    //
    // @brief
    //
    // @param size :
    // @param chunk_overlap_ok :
    //
    // @return
    //
    // One possible calling sequence:
    //
    // offset_1 = reserve(size1);
    // offset_2 = reserve(size2);
    //
    // write_at_offset(offset_2);
    // write_at_offset(offset_1);
    //
    off_t alloc_blk(size_t size, bool chunk_overlap_ok = false) {
        HS_ASSERT_CMP(DEBUG, chunk_overlap_ok, ==, false);

        if (get_used_space() + size > get_size()) {
            // not enough space left;
            HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}",
                   m_write_sz_in_total, m_reserved_sz);
            return INVALID_OFFSET;
        }

        off_t end_offset = get_reserved_tail_offset(); 
        off_t offset_in_chunk = 0;
        uint32_t dev_id = 0, chunk_id = 0;

        auto dev_in_offset = logical_to_dev_offset(end_offset, dev_id, chunk_id, offset_in_chunk);

        if (offset_in_chunk + size <= m_chunk_size) {
            // not acrossing boundary
            // Nothing to do;
        } else if ((get_used_space() + (m_chunk_size - offset_in_chunk) + size) <= get_size()) {
            // across chunk boundary, still enough space;

            // Update the overhead to total write size;
            m_write_sz_in_total += (m_chunk_size - offset_in_chunk);
        
            // TODO: we can optimize how to avoid this two writes;
            // If across chunk boudary, update the chunk super-block of the chunk size
            auto chunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
            m_mgr->update_end_of_chunk(chunk, offset_in_chunk);

            // get next chunk handle
            chunk = get_next_chunk(dev_id, chunk_id);
            
            // Since we are re-using a new chunk, update this chunk's end as its original size;
            m_mgr->update_end_of_chunk(chunk, m_chunk_size);
        } else {
            // across chunk boundary and no space left;
            HS_LOG(ERROR, device, "No space left! m_write_sz_in_total: {}, m_reserved_sz: {}",
                   m_write_sz_in_total, m_reserved_sz);
            return INVALID_OFFSET;
            // m_reserved_sz stays sthe same;
        }

        // if we made a successful reserve, return the tail offset;
        off_t offset = get_reserved_tail_offset();

        // update reserved size;
        m_reserved_sz += size;

        return offset;
    }

    // 
    // write advances seek cursor
    //
    ssize_t write(const void* buf, size_t count, boost::intrusive_ptr< virtualdev_req > req) {
        auto bytes_written = pwrite(buf, count, m_seek_cursor, req);
        m_seek_cursor += bytes_written;
        return bytes_written;
    }

    ssize_t write(const void* buf, size_t count) {
        return write(buf, count, nullptr);
    }

    ssize_t pwrite(const void* buf, size_t count, off_t offset) {
        return pwrite(buf, count, offset, nullptr);
    }


    // 
    // Based on write offset and len:
    // 1. Make serveral assertions to validate input
    // 2. Update counter
    // 3. Return offset_in_dev, chunk_id and dev_id to caller;
    //
    off_t process_write_offset(size_t len, off_t offset, uint32_t& dev_id, uint32_t& chunk_id, boost::intrusive_ptr< virtualdev_req > req) {
        off_t offset_in_chunk = 0;

        if (req) { req->outstanding_cb.store(1); }

        HS_ASSERT_CMP(DEBUG, len, <=, m_reserved_sz, 
                "Write size:{} larger then reserved size: {} is not allowed!", len, m_reserved_sz);

        HS_ASSERT_CMP(DEBUG, get_reserved_tail_offset(), >=, offset + len,
                "Wrting at offset: {}, which is out of reserved portion is not allowed!", offset);

        // convert logical offset to dev offset
        uint64_t offset_in_dev = logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk);
        
        HS_ASSERT_CMP(DEBUG, m_chunk_size - offset_in_chunk, >=, len, "Writing size: {} acrossing chunk is not allowed!", len);

        // update reserved size
        m_reserved_sz -= len;
        m_write_sz_in_total += len;

        PhysicalDevChunk* chunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
        if (req) {
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = len;
            req->chunk = chunk;
        }

        return offset_in_dev;
    }

    // 
    // Assumption:
    // pwrite/pwritev always use offset returned from alloc_blk to do the write;
    //
    // Note:
    // 1. pwrite should not across chunk boundaries 
    //    because alloc_blk garunteens offset returned always doesn't across chunk boundary;
    //
    ssize_t pwrite(const void* buf, size_t count, off_t offset, boost::intrusive_ptr< virtualdev_req > req) {
        uint32_t dev_id = 0, chunk_id = 0;
        
        auto offset_in_dev = process_write_offset(count, offset, dev_id, chunk_id, req);

        ssize_t bytes_written = 0;
        try {
            PhysicalDevChunk* chunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
            
            auto pdev = m_primary_pdev_chunks_list[dev_id].pdev;

            HS_LOG(INFO, device, "Writing in device: {}, offset: {}", dev_id, offset_in_dev);

            bytes_written = do_pwrite_internal(pdev, chunk, (const char*)buf, count, offset_in_dev, req);

            // bytes written should always equal to requested write size, since alloc_blk handles offset 
            // which will never across chunk boundary;
            HS_ASSERT_CMP(DEBUG, bytes_written, ==, count, "Bytes written not equal to input len!");

        } catch (const std::exception& e) { HS_ASSERT(DEBUG, 0, "{}", e.what()); }

        return bytes_written;
    }

    ssize_t do_pwrite_internal(PhysicalDev* pdev, PhysicalDevChunk* chunk, const char* buf, const uint32_t len, 
                               const uint64_t offset_in_dev, boost::intrusive_ptr< virtualdev_req > req) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, 1);

        ssize_t bytes_written = 0;

        if (!req || req->isSyncCall) {
            auto start_time = Clock::now();
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            bytes_written = pdev->sync_write(buf, len, offset_in_dev);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);
            req->inc_ref();
            req->io_start_time = Clock::now();
            pdev->write(buf, len, offset_in_dev, (uint8_t*)req.get());
            // we are going to get error in callback if the size being writen in aysc is not equal to the size that was requested.
            bytes_written = len;
        }

        if (get_nmirrors()) {
            // We do not support async mirrored writes yet.
            HS_ASSERT(DEBUG, ((req == nullptr) || req->isSyncCall), "Expected null req or a sync call");
            write_nmirror(buf, len, chunk, offset_in_dev);
        }

        return bytes_written;
    }

    // 
    // sync pwritev 
    //
    ssize_t pwritev(const struct iovec *iov, int iovcnt, off_t offset) {
        return pwritev(iov, iovcnt, offset, nullptr); 
    }

    // 
    // async pwritev
    //
    // Note:
    // 1. pwritev should not across chunk boundaries 
    //    because alloc_blk garunteens offset returned always doesn't across chunk boundary;
    //
    ssize_t pwritev(const struct iovec *iov, int iovcnt, off_t offset, boost::intrusive_ptr< virtualdev_req > req) {
        uint32_t dev_id = 0, chunk_id = 0;
        auto len = get_len(iov, iovcnt);
        auto offset_in_dev = process_write_offset(len, offset, dev_id, chunk_id, req);

        ssize_t bytes_written = 0;
        try {
            PhysicalDevChunk* chunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
            auto pdev = m_primary_pdev_chunks_list[dev_id].pdev;

            HS_LOG(INFO, device, "Writing in device: {}, offset: {}", dev_id, offset_in_dev);

            bytes_written = do_pwritev_internal(pdev, chunk, iov, iovcnt, len, offset_in_dev, req);
            
            // bytes written should always equal to requested write size, since alloc_blk handles offset 
            // which will never across chunk boundary;
            HS_ASSERT_CMP(DEBUG, bytes_written, ==, len, "Bytes written not equal to input len!");

        } catch (const std::exception& e) { HS_ASSERT(DEBUG, 0, "{}", e.what()); }

        return bytes_written;
    }

    // 
    // read advances seek cursor
    //
    // read needs to take care of end of chunk and if the read size is acrossing the end of chunk:
    // 1. Only read the size before end of chunk;
    // 2. Update m_seek_cursor to next chunk;
    //
    ssize_t read(void* buf, size_t count) {
        uint32_t dev_id = 0, chunk_id = 0;
        off_t offset_in_chunk = 0;
        
        logical_to_dev_offset(m_seek_cursor, dev_id, chunk_id, offset_in_chunk);
        
        auto chunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
        auto end_of_chunk = chunk->get_end_of_chunk();
        auto chunk_size = std::min((uint64_t)end_of_chunk, m_chunk_size);

        bool across_chunk = false;
        
        HS_ASSERT_CMP(DEBUG, (uint64_t)end_of_chunk, <=, m_chunk_size, "Invalid end of chunk: {} detected on chunk num: {}", end_of_chunk, chunk->get_chunk_id());
        HS_ASSERT_CMP(DEBUG, (uint64_t)offset_in_chunk, <=, chunk_size, "Invalid m_seek_cursor: {} which falls in beyond end of chunk: {}!", m_seek_cursor, end_of_chunk);
        
        // if read size is larger then what's left in this chunk
        if (count > (chunk_size - offset_in_chunk)) {
            // truncate size to what is left;
            count = chunk_size - offset_in_chunk;
            across_chunk = true;
        }

        auto bytes_read = pread(buf, count, m_seek_cursor);
        
        if (bytes_read != -1) {
            // Update seek curosr after read;
            HS_ASSERT_CMP(DEBUG, (size_t)bytes_read, ==, count, "bytes_read returned: {} must be equal to requested size: {}!", bytes_read, count);
            m_seek_cursor += bytes_read;
            if (across_chunk) {
                m_seek_cursor += (m_chunk_size - end_of_chunk);
            }
        }

        return bytes_read;
    }

    // 
    // pread doesn't need to care about the "end of chunk", just return anything that is requested by the offset;
    //
    // Note: 
    // pread doesn't advance m_seek_curosr
    // 
    //
    ssize_t pread(void* buf, size_t count, off_t offset) {
        uint32_t dev_id = 0, chunk_id = 0;
        off_t offset_in_chunk = 0;

        uint64_t offset_in_dev = logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk);

        // if the read count is acrossing chunk, only return what's left in this chunk
        if (m_chunk_size - offset_in_chunk < count) {
            // truncate requsted rean length to end of chunk;
            count = m_chunk_size - offset_in_chunk;
        }

        auto pdev = m_primary_pdev_chunks_list[dev_id].pdev;
        auto pchunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];

        return do_read_internal(pdev, pchunk, offset_in_dev, (char*)buf, count, nullptr);
    }
    
    //
    // We don't have a use case for external caller of preadv now, meaning iov will always have only 1 element;
    //
    // return:
    //     on error, -1 is returned;
    //     on success, num of bytes read;
    // 
    // Note: if the len is acrossing chunk boundary, 
    //       we only do read on one chunk and return the num of bytes read on this chunk;
    //
    //
    ssize_t preadv(const struct iovec *iov, int iovcnt, off_t offset) {
        uint32_t dev_id = 0, chunk_id = 0;
        off_t offset_in_chunk = 0;
        uint64_t len = get_len(iov, iovcnt);

        uint64_t offset_in_dev = logical_to_dev_offset(offset, dev_id, chunk_id, offset_in_chunk);

        if (m_chunk_size - offset_in_chunk < len) {
            HS_ASSERT_CMP(DEBUG, iovcnt, ==, 1, "iovector more than 1 element is not supported when requested read len is acrossing chunk boundary. ");
            if (iovcnt > 1) {
                return -1;
            }
            
            // truncate requsted rean length to end of chunk;
            len = m_chunk_size - offset_in_chunk;

            iov[0].iov_len = len; // is this needed?
        }

        auto pdev = m_primary_pdev_chunks_list[dev_id].pdev;
        auto chunk = m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];

        return do_preadv_internal(pdev, chunk, offset_in_dev, iov, iovcnt, len, nullptr);
    }

    // 
    // async preadv
    //
    ssize_t preadv(const struct iovec *iov, int iovcnt, off_t offset, boost::intrusive_ptr< virtualdev_req > req) {
        // TODO: to be implemented;
        return 0;
    }

    off_t lseek(off_t offset, int whence = SEEK_SET) {
        switch (whence) {
            case SEEK_SET:
                m_seek_cursor = offset;
                break;
            case SEEK_CUR:
                m_seek_cursor += offset;
                break;
            case SEEK_END:
            default:
                HS_ASSERT(DEBUG, false, "Not supported seek type: {}", whence);
                break;
        }

        return m_seek_cursor;
    }

    off_t seeked_pos() const {
        return m_seek_cursor;
    }

    ssize_t do_preadv_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const uint64_t dev_offset, const struct iovec* iov,
                              int iovcnt, uint64_t size, boost::intrusive_ptr< virtualdev_req > req) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, iovcnt);
        ssize_t bytes_read = 0;
        if (!req || req->isSyncCall) {
            auto start = Clock::now();
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
            bytes_read = pdev->sync_readv(iov, iovcnt, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->inc_ref();
            req->chunk = pchunk;
            req->io_start_time = Clock::now();

            pdev->readv(iov, iovcnt, size, dev_offset, (uint8_t*)req.get());
            bytes_read = size; // no one consumes return value for async read;
        }

        if (sisl_unlikely(get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            uint64_t primary_chunk_offset = dev_offset - pchunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(pchunk)->second) {
                uint64_t dev_offset_m = mchunk->get_start_offset() + primary_chunk_offset;
                req->inc_ref();
                mchunk->get_physical_dev_mutable()->readv(iov, iovcnt, size, dev_offset_m, (uint8_t*)req.get());
            }
        }

        return bytes_read;
    }
    // end of vdev interface stubs

    //
    // convert unique offset;
    //
    uint64_t to_glob_uniq_offset(uint32_t dev_id, uint32_t chunk_id, uint64_t offset_in_chunk) {
        return m_primary_pdev_chunks_list[dev_id].pdev->get_dev_offset() + get_chunk_start_offset(dev_id, chunk_id) +
            offset_in_chunk;
    }

    uint64_t get_offset_in_dev(uint32_t dev_id, uint32_t chunk_id, uint64_t offset_in_chunk) {
        return get_chunk_start_offset(dev_id, chunk_id) + offset_in_chunk;
    }

    uint64_t get_chunk_start_offset(uint32_t dev_id, uint32_t chunk_id) {
        return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id]->get_start_offset();
    }

    uint64_t get_len(const struct iovec* iov, const int iovcnt) {
        uint64_t len = 0;
        for (int i = 0; i < iovcnt; i++) {
            len += iov[i].iov_len;
        }
        return len;
    }

    // 
    // if req is nullptr, it is sync write;
    //
    ssize_t do_pwritev_internal(PhysicalDev* pdev, PhysicalDevChunk* chunk, const struct iovec* iov, const int iovcnt,
                           const uint64_t len, const uint64_t offset_in_dev,
                           boost::intrusive_ptr< virtualdev_req > req) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, 1);

        ssize_t bytes_written = 0;

        if (!req || req->isSyncCall) {
            auto start_time = Clock::now();
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            bytes_written = pdev->sync_writev(iov, iovcnt, len, offset_in_dev);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);
            req->inc_ref();
            req->io_start_time = Clock::now();
            pdev->writev(iov, iovcnt, len, offset_in_dev, (uint8_t*)req.get());
            // we are going to get error in callback if the size being writen in aysc is not equal to the size that was requested.
            bytes_written = len;
        }

        if (get_nmirrors()) {
            // We do not support async mirrored writes yet.
            HS_ASSERT(DEBUG, ((req == nullptr) || req->isSyncCall), "Expected null req or a sync call");
            writev_nmirror(iov, iovcnt, len, chunk, offset_in_dev);
        }

        return bytes_written;
    }

    //
    // convert from logical offset to device offset
    // it handles device overloop, e.g. reach to end of the device then start from the beginning device
    //
    uint64_t logical_to_dev_offset(const off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id, 
                                   off_t& offset_in_chunk) {
        dev_id = 0;
        chunk_id = 0;
        offset_in_chunk = 0;

        uint64_t off_l = log_offset;
        for (size_t d = 0; d < m_primary_pdev_chunks_list.size(); d++) {
            for (size_t c = 0; c < m_primary_pdev_chunks_list[d].chunks_in_pdev.size(); c++) {
                if (off_l >= m_chunk_size) {
                    off_l -= m_chunk_size;
                } else {
                    dev_id = d;
                    chunk_id = c;
                    offset_in_chunk = off_l;

                    return get_offset_in_dev(dev_id, chunk_id, offset_in_chunk);
                }
            }
        }

        HS_ASSERT(DEBUG, false, "Input log_offset is invalid: {}, should be between 0 ~ {}", log_offset,
                  m_chunk_size * m_num_chunks);
        return 0;
    }

    void truncate(const uint64_t offset) {
        // to be implemented
    }

    void update_write_sz(uint64_t total_written_sz) { m_write_sz_in_total = total_written_sz; }

    bool is_blk_alloced(BlkId& in_blkid) {
        PhysicalDevChunk* primary_chunk;
        uint64_t primary_dev_offset = to_dev_offset(in_blkid, &primary_chunk);
        auto blkid = to_chunk_specific_id(in_blkid, &primary_chunk);
        return (primary_chunk->get_blk_allocator()->is_blk_alloced(blkid));
    }

    BlkAllocStatus alloc_blk(BlkId& in_blkid) {
        PhysicalDevChunk* primary_chunk;
        uint64_t primary_dev_offset = to_dev_offset(in_blkid, &primary_chunk);
        auto blkid = to_chunk_specific_id(in_blkid, &primary_chunk);
        auto size = m_used_size.fetch_add(in_blkid.data_size(m_pagesz), std::memory_order_relaxed);
        HS_ASSERT_CMP(DEBUG, size, <=, get_size());
        return (primary_chunk->get_blk_allocator()->alloc(blkid));
    }

    BlkAllocStatus alloc_blk(uint8_t nblks, const blk_alloc_hints& hints, BlkId* out_blkid) {
        BlkAllocStatus ret;
        try {
            std::vector< BlkId > blkid;
            HS_ASSERT_CMP(DEBUG, hints.is_contiguous, ==, true);
            ret = alloc_blk(nblks, hints, blkid);
            if (ret == BLK_ALLOC_SUCCESS) {
                *out_blkid = blkid[0];
                HS_ASSERT_CMP(DEBUG, blkid.size(), <=, HomeStoreConfig::atomic_phys_page_size);
            } else {
                HS_ASSERT_CMP(DEBUG, blkid.size(), ==, 0);
            }
        } catch (const std::exception& e) {
            ret = BLK_ALLOC_FAILED;
            HS_ASSERT(DEBUG, 0, "{}", e.what());
        }
        return ret;
    }

    BlkAllocStatus alloc_blk(uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) {
        try {
            uint32_t dev_ind{0};
            uint32_t chunk_num, start_chunk_num;
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
            uint32_t start_dev_ind = dev_ind;
            PhysicalDevChunk* picked_chunk = nullptr;

            do {
                for (auto chunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
#ifdef _PRERELEASE
                    if (auto fake_status = homestore_flip->get_test_flip< uint32_t >("blk_allocation_flip", nblks,
                                                                                     chunk->get_vdev_id())) {
                        return (BlkAllocStatus)fake_status.get();
                    }
#endif

                    status = chunk->get_blk_allocator()->alloc(nblks, hints, out_blkid);

                    if (status == BLK_ALLOC_SUCCESS) {
                        picked_chunk = chunk;
                        break;
                    }
                }

                if (status == BLK_ALLOC_SUCCESS) { break; }
                if (!hints.can_look_for_other_dev) { break; }
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
                HS_ASSERT_CMP(DEBUG, size, <=, get_size());
            }
            return status;
        } catch (const std::exception& e) { return BLK_ALLOC_FAILED; }
    }

    void free_blk(const BlkId& b) {
        PhysicalDevChunk* chunk;

        // Convert blk id to chunk specific id and call its allocator to free
        BlkId cb = to_chunk_specific_id(b, &chunk);
        chunk->get_blk_allocator()->free(cb);
        m_used_size.fetch_sub(b.data_size(m_pagesz), std::memory_order_relaxed);
        HS_ASSERT_CMP(DEBUG, m_used_size.load(), >=, 0);
    }

    void write(const BlkId& bid, const homeds::MemVector& buf, boost::intrusive_ptr< virtualdev_req > req,
               uint32_t data_offset = 0) {
        BlkOpStatus ret_status = BLK_OP_SUCCESS;
        uint32_t size = bid.get_nblks() * get_page_size();
        struct iovec iov[BlkId::max_blks_in_op()];
        int iovcnt = 0;

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

        HS_ASSERT_CMP(DEBUG, data_offset, ==, end_offset);
        PhysicalDevChunk* chunk;

        uint64_t dev_offset = to_dev_offset(bid, &chunk);
        if (req) {
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->chunk = chunk;
        }

        auto pdev = chunk->get_physical_dev_mutable();

        HS_LOG(INFO, device, "Writing in device: {}, offset = {}", pdev->get_dev_id(), dev_offset);

        do_pwritev_internal(pdev, chunk, iov, iovcnt, size, dev_offset, req);
    }

    void write_nmirror(const char* buf, uint32_t size, PhysicalDevChunk* chunk, uint64_t dev_offset) {
        uint64_t primary_chunk_offset = dev_offset - chunk->get_start_offset();

        // Write to the mirror as well
        for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
            for (auto mchunk : m_mirror_chunks.find(chunk)->second) {
                dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

                // We do not support async mirrored writes yet.
                auto pdev = mchunk->get_physical_dev_mutable();

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
                auto start_time = Clock::now();
                pdev->sync_write(buf, size, dev_offset);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
            }
        }
    }

    void writev_nmirror(const iovec* iov, int iovcnt, uint32_t size, PhysicalDevChunk* chunk, uint64_t dev_offset) {
        uint64_t primary_chunk_offset = dev_offset - chunk->get_start_offset();

        // Write to the mirror as well
        for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
            for (auto mchunk : m_mirror_chunks.find(chunk)->second) {
                dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

                // We do not support async mirrored writes yet.
                auto pdev = mchunk->get_physical_dev_mutable();

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
                auto start_time = Clock::now();
                pdev->sync_writev(iov, iovcnt, size, dev_offset);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
            }
        }
    }

    void read_nmirror(const BlkId& bid, std::vector< boost::intrusive_ptr< homeds::MemVector > > mp, uint64_t size,
                      uint32_t nmirror) {
        HS_ASSERT_CMP(DEBUG, nmirror, <=, get_nmirrors());
        uint32_t cnt = 0;
        PhysicalDevChunk* primary_chunk;
        uint64_t primary_dev_offset = to_dev_offset(bid, &primary_chunk);
        uint64_t primary_chunk_offset = primary_dev_offset - primary_chunk->get_start_offset();

        homeds::blob b;
        mp[cnt]->get(&b, 0);
        HS_ASSERT_CMP(DEBUG, b.size, ==, bid.data_size(m_pagesz));
        primary_chunk->get_physical_dev_mutable()->sync_read((char*)b.bytes, b.size, primary_dev_offset);
        if (cnt == nmirror) { return; }
        ++cnt;
        for (auto mchunk : m_mirror_chunks.find(primary_chunk)->second) {
            uint64_t dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

            mp[cnt]->get(&b, 0);
            HS_ASSERT_CMP(DEBUG, b.size, ==, bid.data_size(m_pagesz));
            mchunk->get_physical_dev_mutable()->sync_read((char*)b.bytes, b.size, dev_offset);

            if (cnt == nmirror) { break; }
        }
    }


    ssize_t do_read_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const uint64_t dev_offset, char* ptr,
                             const uint64_t size, boost::intrusive_ptr< virtualdev_req > req) {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, 1);
        ssize_t bytes_read = 0;

        if (!req || req->isSyncCall) {
            // if req is null (sync), or it is a sync call;
            auto start = Clock::now();
            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
            bytes_read = pdev->sync_read(ptr, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start));
        } else {
            COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
            // aysnc read
            req->version = 0xDEAD;
            req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
            req->size = size;
            req->chunk = pchunk;
            req->io_start_time = Clock::now();
            req->inc_ref();

            pdev->read(ptr, size, dev_offset, (uint8_t*)req.get());
            bytes_read = size;
        }

        if (sisl_unlikely(get_nmirrors())) {
            // If failed and we have mirrors, we can read from any one of the mirrors as well
            uint64_t primary_chunk_offset = dev_offset - pchunk->get_start_offset();
            for (auto mchunk : m_mirror_chunks.find(pchunk)->second) {
                uint64_t dev_offset_m = mchunk->get_start_offset() + primary_chunk_offset;
                auto pdev = mchunk->get_physical_dev_mutable();

                HS_ASSERT(DEBUG, ((req == nullptr) || req->isSyncCall), "Expecting null req or sync call");

                COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
                auto start_time = Clock::now();
                pdev->sync_read(ptr, size, dev_offset_m);
                HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start_time));
            }
        }

        return bytes_read;
    }

    /* Read the data for a given BlkId. With this method signature, virtual dev can read only in block boundary
     * and nothing in-between offsets (say if blk size is 8K it cannot read 4K only, rather as full 8K. It does not
     * have offset as one of the parameter. Reason for that is its actually ok and make the interface and also
     * buf (caller buf) simple and there is no use case. However, we need to keep the blk size to be small as possible
     * to avoid read overhead */
    void read(const BlkId& bid, const homeds::MemPiece& mp, boost::intrusive_ptr< virtualdev_req > req) {
        PhysicalDevChunk* primary_chunk;

        uint64_t primary_dev_offset = to_dev_offset(bid, &primary_chunk);

        do_read_internal(primary_chunk->get_physical_dev_mutable(), primary_chunk, primary_dev_offset, (char*)mp.ptr(),
                         mp.size(), req);
    }

    void readv(const BlkId& bid, const homeds::MemVector& buf, boost::intrusive_ptr< virtualdev_req > req) {
        // Convert the input memory to iovector
        struct iovec iov[BlkId::max_blks_in_op()];
        int iovcnt = 0;
        uint32_t size = buf.size();

        HS_ASSERT_CMP(DEBUG, buf.size(), ==,
                      bid.get_nblks() * get_page_size()); // Expected to be less than allocated blk originally.
        for (auto i : boost::irange< uint32_t >(0, buf.npieces())) {
            homeds::blob b;
            buf.get(&b, i);

            iov[iovcnt].iov_base = b.bytes;
            iov[iovcnt].iov_len = b.size;
            iovcnt++;
        }

        PhysicalDevChunk* primary_chunk;
        uint64_t primary_dev_offset = to_dev_offset(bid, &primary_chunk);

        auto pdev = primary_chunk->get_physical_dev_mutable();

        do_preadv_internal(pdev, primary_chunk, primary_dev_offset, iov, iovcnt, size, req);
    }

    void get_vb_context(uint8_t* ctx_data) const {
        m_mgr->get_vb_context(m_vb->vdev_id, (char*)ctx_data);
    }

    void update_vb_context(uint8_t* blob) { m_mgr->update_vb_context(m_vb->vdev_id, blob); }
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
    uint64_t get_size() { return m_num_chunks * m_chunk_size; }

    /* Adds a primary chunk to the chunk list in pdev */
    void add_primary_chunk(PhysicalDevChunk* chunk) {
        auto pdev_id = chunk->get_physical_dev()->get_dev_id();

        if (m_chunk_size == 0) {
            m_chunk_size = chunk->get_size();
        } else {
            HS_ASSERT_CMP(DEBUG, m_chunk_size, ==, chunk->get_size());
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
        HS_ASSERT_CMP(DEBUG, m_chunk_size, <=, MAX_CHUNK_SIZE);
        std::shared_ptr< BlkAllocator > ba = create_allocator(m_chunk_size, chunk->get_chunk_id(), m_recovery_init);
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
            HS_ASSERT_CMP(DEBUG, m_chunk_size, ==, chunk->get_size());
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
        auto pdev = m_primary_pdev_chunks_list[pdev_ind].pdev;
        PhysicalDevChunk* chunk = m_mgr->alloc_chunk(pdev, m_vb->vdev_id, m_chunk_size, primary_id);
        HS_LOG(DEBUG, device, "Allocating new chunk for vdev_id = {} pdev_id = {} chunk: {}", m_vb->get_vdev_id(),
               pdev->get_dev_id(), chunk->to_string());
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
}; // namespace homestore

} // namespace homestore
