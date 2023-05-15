/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
//
// Created by Kadayam, Hari on 08/11/17.
//
#pragma once

#include <atomic>
#include <functional>
#include <limits>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <sisl/utility/obj_life_counter.hpp>
#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/enum.hpp>

#include "device.h"
#include "device_selector.hpp"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/blkalloc/varsize_blk_allocator.h"
#include "engine/homeds/memory/mempiece.hpp"

namespace iomgr {
class DriveInterface;
}

namespace homestore {

struct pdev_chunk_map {
    PhysicalDev* pdev;
    std::vector< PhysicalDevChunk* > chunks_in_pdev;
};
ENUM(blk_allocator_type_t, uint8_t, none, fixed, varsize);

struct virtualdev_req;

typedef std::function< void(const boost::intrusive_ptr< virtualdev_req >& req) > vdev_comp_cb_t;
typedef std::function< void(bool success) > vdev_format_cb_t;
typedef std::function< void(void) > vdev_high_watermark_cb_t;

struct virtualdev_req : public sisl::ObjLifeCounter< virtualdev_req > {
    uint64_t request_id{0};
    uint64_t version;
    vdev_comp_cb_t cb; // callback into vdev from static completion function. It is set for all the ops
    uint64_t size;
    std::error_condition err{no_error};
    bool is_read{false};
    bool isSyncCall{false};
    bool is_completed{false};
    sisl::atomic_counter< int > refcount;
    PhysicalDevChunk* chunk{nullptr};
    Clock::time_point io_start_time;
    bool part_of_batch{false};
    bool format{false};
    vdev_format_cb_t format_cb; // callback stored for format operation.
    bool fsync{false};
    vdev_comp_cb_t fsync_cb; // callback stored for fsync operation;
    uint8_t* cookie;

#ifndef NDEBUG
    uint64_t dev_offset;
    uint8_t* mem;
#endif

#ifdef _PRERELEASE
    bool delay_induced{false};
#endif
    bool outstanding_cbs{false};
    sisl::atomic_counter< uint8_t > outstanding_cb{0};

    void inc_ref() { intrusive_ptr_add_ref(this); }
    void dec_ref() { intrusive_ptr_release(this); }

    template < typename RequestType,
               typename = std::enable_if_t<
                   std::is_base_of_v< virtualdev_req, std::decay_t< typename RequestType::element_type > > > >
    static auto to_vdev_req(RequestType& req) {
        return boost::static_pointer_cast< virtualdev_req >(req);
    }

    static boost::intrusive_ptr< virtualdev_req > make_request() {
        return boost::intrusive_ptr< virtualdev_req >(sisl::ObjectAllocator< virtualdev_req >::make_object());
    }
    virtual void free_yourself() { sisl::ObjectAllocator< virtualdev_req >::deallocate(this); }
    friend void intrusive_ptr_add_ref(virtualdev_req* const req) { req->refcount.increment(1); }
    friend void intrusive_ptr_release(virtualdev_req* const req) {
        if (req->refcount.decrement_testz()) { req->free_yourself(); }
    }

    virtualdev_req(const virtualdev_req&) = delete;
    virtualdev_req(virtualdev_req&&) noexcept = delete;
    virtualdev_req& operator=(const virtualdev_req&) = delete;
    virtualdev_req& operator=(virtualdev_req&&) noexcept = delete;

    virtual ~virtualdev_req() { version = 0; }

protected:
    friend class sisl::ObjectAllocator< virtualdev_req >;
    virtualdev_req() : request_id{s_req_id.fetch_add(1, std::memory_order_relaxed)}, refcount{0} {}

private:
    static std::atomic< uint64_t > s_req_id;
};

class VirtualDevMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit VirtualDevMetrics(const char* const inst_name) : sisl::MetricsGroupWrapper{"VirtualDev", inst_name} {
        REGISTER_COUNTER(vdev_read_count, "vdev total read cnt");
        REGISTER_COUNTER(vdev_write_count, "vdev total write cnt");
        REGISTER_COUNTER(vdev_truncate_count, "vdev total truncate cnt");
        REGISTER_COUNTER(vdev_high_watermark_count, "vdev total high watermark cnt");
        REGISTER_COUNTER(vdev_num_alloc_failure, "vdev blk alloc failure cnt");
        REGISTER_COUNTER(unalign_writes, "unalign write cnt");
        REGISTER_COUNTER(default_chunk_allocation_cnt, "default chunk allocation count");
        REGISTER_COUNTER(random_chunk_allocation_cnt,
                         "random chunk allocation count"); // ideally it should be zero for hdd
        register_me_to_farm();
    }

    VirtualDevMetrics(const VirtualDevMetrics&) = delete;
    VirtualDevMetrics(VirtualDevMetrics&&) noexcept = delete;
    VirtualDevMetrics& operator=(const VirtualDevMetrics&) = delete;
    VirtualDevMetrics& operator=(VirtualDevMetrics&&) noexcept = delete;

    ~VirtualDevMetrics() { deregister_me_from_farm(); }
};

/*
 * VirtualDev: Virtual device implements a similar functionality of RAID striping, customized however. Virtual devices
 * can be created across multiple physical devices. Unlike RAID, its io is not always in a bigger strip sizes. It
 * support n-mirrored writes.
 *
 */
static constexpr uint32_t VIRDEV_BLKSIZE{512};
static constexpr uint64_t CHUNK_EOF{0xabcdabcd};
static constexpr off_t INVALID_OFFSET{std::numeric_limits< off_t >::max()};

struct blkalloc_cp;
typedef uint32_t vdev_stream_id_t;
struct stream_info_t {
    uint32_t num_streams = 0;
    uint64_t stream_cur = 0;
    std::vector< vdev_stream_id_t > stream_id;
    std::vector< PhysicalDevChunk* > chunk_list;
};

class VirtualDev {
protected:
    vdev_info_block* m_vb;   // This device block info
    DeviceManager* m_mgr;    // Device Manager back pointer
    std::string m_name;      // Name of the vdev
    uint64_t m_chunk_size;   // Chunk size that will be allocated in a physical device
    std::mutex m_mgmt_mutex; // Any mutex taken for management operations (like adding/removing chunks).

    // List of physical devices this virtual device uses and its corresponding chunks for the physdev
    std::vector< pdev_chunk_map > m_primary_pdev_chunks_list;

    // For each of the primary chunk we created, this is the list of mirrored chunks. The physical devices
    // for the mirrored chunk always follows the next device pattern.
    std::map< PhysicalDevChunk*, std::vector< PhysicalDevChunk* > > m_mirror_chunks;

    std::unique_ptr< RoundRobinDeviceSelector > m_selector; // Instance of device selector
    uint32_t m_num_chunks{0};
    vdev_comp_cb_t m_comp_cb;
    uint32_t m_pagesz{0};
    bool m_recovery_init{false};

    blk_allocator_type_t m_allocator_type;
    bool m_auto_recovery{false};
    vdev_high_watermark_cb_t m_hwm_cb{nullptr};
    iomgr::DriveInterface* m_drive_iface{nullptr};
    VirtualDevMetrics m_metrics;
    std::vector< PhysicalDevChunk* > m_free_streams;
    std::mutex m_free_streams_lk;
    PhysicalDevChunk* m_default_chunk{nullptr};
    PhysicalDevGroup m_pdev_group;

private:
    static uint32_t s_num_chunks_created; // vdev will not be created in parallel threads;

public:
    static constexpr size_t context_data_size() { return MAX_CONTEXT_DATA_SZ; }
    static void static_process_completions(const int64_t res, uint8_t* cookie);

    void init(DeviceManager* mgr, vdev_info_block* vb, vdev_comp_cb_t cb, const uint32_t page_size,
              const bool auto_recovery, vdev_high_watermark_cb_t hwm_cb);

    /* Create a new virtual dev for these parameters */
    VirtualDev(DeviceManager* mgr, const char* name, const PhysicalDevGroup pdev_group,
               const blk_allocator_type_t allocator_type, const uint64_t context_size, const uint32_t nmirror,
               const bool is_stripe, const uint32_t page_size, vdev_comp_cb_t cb, char* blob, const uint64_t size_in,
               const bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr);

    /* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
    VirtualDev(DeviceManager* mgr, const char* name, vdev_info_block* vb, const PhysicalDevGroup pdev_group,
               const blk_allocator_type_t allocator_type, vdev_comp_cb_t cb, const bool recovery_init,
               const bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr);

    VirtualDev(const VirtualDev& other) = delete;
    VirtualDev& operator=(const VirtualDev& other) = delete;
    VirtualDev(VirtualDev&&) noexcept = delete;
    VirtualDev& operator=(VirtualDev&&) noexcept = delete;
    virtual ~VirtualDev() = default;

    virtual void reset_failed_state();
    void process_completions(const boost::intrusive_ptr< virtualdev_req >& req);

    /* This method adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
     * takes lock for writing and not reading
     */
    virtual void add_chunk(PhysicalDevChunk* chunk);

    /**
     * @brief : get the next chunk handle based on input dev_id and chunk_id
     *
     * @param dev_id : the current dev_id
     * @param chunk_id : the current chunk_id
     *
     * @return : the hundle to the next chunk, if current chunk is the last chunk, loop back to begining device/chunk;
     *
     * TODO: organize chunks in a vector so that we can get next chunk id easily;
     */
    PhysicalDevChunk* get_next_chunk(uint32_t dev_id, uint32_t chunk_id);

    virtual void format(const vdev_format_cb_t& cb);

    virtual bool is_blk_alloced(const BlkId& blkid) const;
    virtual BlkAllocStatus reserve_blk(const BlkId& blkid);
    virtual BlkAllocStatus alloc_contiguous_blk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                                BlkId* out_blkid);
    virtual BlkAllocStatus alloc_blk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                     std::vector< BlkId >& out_blkid);
    virtual bool free_on_realtime(const BlkId& b);
    virtual void free_blk(const BlkId& b);

    void write(const BlkId& bid, const iovec* iov, const int iovcnt,
               const boost::intrusive_ptr< virtualdev_req >& req = nullptr);
    void write(const BlkId& bid, const homeds::MemVector& buf, const boost::intrusive_ptr< virtualdev_req >& req,
               const uint32_t data_offset_in = 0);

    /* Read the data for a given BlkId. With this method signature, virtual dev can read only in block boundary
     * and nothing in-between offsets (say if blk size is 8K it cannot read 4K only, rather as full 8K. It does not
     * have offset as one of the parameter. Reason for that is its actually ok and make the interface and also
     * buf (caller buf) simple and there is no use case. However, we need to keep the blk size to be small as possible
     * to avoid read overhead */
    void read(const BlkId& bid, const homeds::MemPiece& mp, const boost::intrusive_ptr< virtualdev_req >& req);
    void read(const BlkId& bid, std::vector< iovec >& iovecs, const uint64_t size,
              const boost::intrusive_ptr< virtualdev_req >& req);
    void readv(const BlkId& bid, const homeds::MemVector& buf, const boost::intrusive_ptr< virtualdev_req >& req);

    // Issue fsync to all physical devices and call cb on completion
    void fsync_pdevs(vdev_comp_cb_t cb, uint8_t* const cookie = nullptr);

    void submit_batch();

    void get_vb_context(const sisl::blob& ctx_data) const;
    void update_vb_context(const sisl::blob& ctx_data);
    virtual void recovery_done();

    std::shared_ptr< blkalloc_cp > attach_prepare_cp(const std::shared_ptr< blkalloc_cp >& cur_ba_cp);
    void blkalloc_cp_start(const std::shared_ptr< blkalloc_cp >& ba_cp);

    virtual uint64_t get_available_blks() const;
    virtual uint64_t get_size() const { return (get_num_chunks() * get_chunk_size()); }
    virtual uint64_t get_used_size() const;
    virtual uint64_t get_num_chunks() const { return m_num_chunks; }
    virtual uint64_t get_chunk_size() const { return m_chunk_size; }
    virtual uint32_t get_blks_per_chunk() const { return get_chunk_size() / get_page_size(); }
    virtual uint32_t get_page_size() const { return m_vb->page_size; }
    virtual uint32_t get_nmirrors() const { return m_vb->num_mirrors; }
    virtual std::string to_string() const { return std::string{}; }
    virtual nlohmann::json get_status(const int log_level) const;

    static uint64_t get_len(const iovec* iov, const int iovcnt);

    // Remove this virtualdev altogether
    void rm_device();
    void expand(const uint32_t addln_size);

    /* Create debug bitmap for all chunks */
    virtual BlkAllocStatus create_debug_bm();

    /* Update debug bitmap for a given BlkId */
    virtual BlkAllocStatus update_debug_bm(const BlkId& bid);

    /* Verify debug bitmap for all chunks */
    virtual BlkAllocStatus verify_debug_bm(const bool free_debug_bm = true);
    stream_info_t reserve_stream(const vdev_stream_id_t* id_list, const uint32_t num_streams);
    stream_info_t alloc_stream(uint64_t size);
    void free_stream(const stream_info_t& stream_info);
    uint32_t get_align_size() const;
    uint32_t get_phys_page_size() const;
    uint32_t get_atomic_page_size() const;
    uint32_t get_num_streams() const;
    uint64_t get_stream_size() const;

protected:
    /**
     * @brief : internal implementation of pwritev, so that it can be called by differnet callers;
     *
     * @param pdev : pointer to device
     * @param pchunk : pointer to chunk
     * @param iov : io vector
     * @param iovcnt : the count of vectors in iov
     * @param len : total size of buffer length in iov
     * @param offset_in_dev : physical offset in device
     * @param req : if req is nullptr, it is a sync call, if not, it will be an async call;
     *
     * @return : size that has been written;
     */
    ssize_t do_pwritev_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const iovec* iov, const int iovcnt,
                                const uint64_t len, const uint64_t offset_in_dev,
                                const boost::intrusive_ptr< virtualdev_req >& req = nullptr);

    /**
     * @brief : the internal implementation of pwrite
     *
     * @param pdev : pointer to devic3
     * @param pchunk : pointer to chunk
     * @param buf : buffer to be written
     * @param len : length of buffer
     * @param offset_in_dev : physical offset in device to be written
     * @param req : if req is null, it will be sync call, if not, it will be async call;
     *
     * @return : bytes written;
     */
    ssize_t do_pwrite_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const char* buf, const uint32_t len,
                               const uint64_t offset_in_dev,
                               const boost::intrusive_ptr< virtualdev_req >& req = nullptr);
    ssize_t do_read_internal(PhysicalDev* pdev, PhysicalDevChunk* primary_chunk, const uint64_t primary_dev_offset,
                             char* ptr, const uint64_t size,
                             const boost::intrusive_ptr< virtualdev_req >& req = nullptr);

    /**
     * @brief : internal implementation for preadv, so that it call be reused by different callers;
     *
     * @param pdev : pointer to device
     * @param pchunk : pointer to chunk
     * @param dev_offset : physical offset in device
     * @param iov : io vector
     * @param iovcnt : the count of vectors in iov
     * @param size : size of buffers in iov
     * @param req : async req, if req is nullptr, it is a sync call, if not, it is an async call;
     *
     * @return : size being read.
     */
    ssize_t do_preadv_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const uint64_t dev_offset, iovec* iov,
                               const int iovcnt, const uint64_t size,
                               const boost::intrusive_ptr< virtualdev_req >& req = nullptr);

private:
    void write_nmirror(const char* buf, const uint32_t size, PhysicalDevChunk* chunk, const uint64_t dev_offset_in);
    void writev_nmirror(const iovec* iov, const int iovcnt, const uint32_t size, PhysicalDevChunk* chunk,
                        const uint64_t dev_offset_in);

    void read_nmirror(const BlkId& bid, const std::vector< boost::intrusive_ptr< homeds::MemVector > >& mp,
                      const uint64_t size, const uint32_t nmirror);

    void add_primary_chunk(PhysicalDevChunk* chunk);
    void add_mirror_chunk(PhysicalDevChunk* chunk);
    PhysicalDevChunk* create_dev_chunk(const uint32_t pdev_ind, const std::shared_ptr< BlkAllocator >& ba,
                                       const uint32_t primary_id);
    uint64_t to_dev_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const;
    BlkAllocStatus alloc_blk_from_chunk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid, PhysicalDevChunk* const chunk);
    void reserve_stream(const vdev_stream_id_t id);
};

} // namespace homestore
