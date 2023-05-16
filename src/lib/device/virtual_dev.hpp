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

#include <homestore/homestore_decl.hpp>

#include "device.h"
#include "device_selector.hpp"

namespace iomgr {
class DriveInterface;
}

namespace homestore {
class PhysicalDev;
class PhysicalDevChunk;
class BlkAllocator;

struct pdev_chunk_map {
    PhysicalDev* pdev;
    std::vector< PhysicalDevChunk* > chunks_in_pdev;
};
// ENUM(blk_allocator_type_t, uint8_t, none, fixed, varsize);
ENUM(vdev_op_type_t, uint8_t, read, write, format, fsync);

typedef std::function< void(std::error_condition, void* /* cookie */) > vdev_io_comp_cb_t;
typedef std::function< void(void) > vdev_high_watermark_cb_t;

struct vdev_req_context : public sisl::ObjLifeCounter< vdev_req_context > {
    uint64_t request_id{0};                       // ID of the request
    uint64_t version{0xDEAD};                     // Version for debugging
    vdev_io_comp_cb_t cb;                         // User callback is put here
    void* cookie{nullptr};                        // User defined cookie, will be returned back to caller on completion;
    std::error_condition err{no_error};           // Any error info
    vdev_op_type_t op_type{vdev_op_type_t::read}; // Op Type
    sisl::atomic_counter< int > refcount{1};      // Refcount for intrusive ptr
    bool io_on_multi_pdevs{false};                // Is IO part of multiple pdevs (say format)
    sisl::atomic_counter< uint32_t > outstanding_ios{0}; // Outstanding ios in case of multi pdev io
    PhysicalDevChunk* chunk{nullptr};                    // Chunk where the io is issued if its a single pdev io
    Clock::time_point io_start_time{Clock::now()};

    void inc_ref() { intrusive_ptr_add_ref(this); }
    void dec_ref() { intrusive_ptr_release(this); }

    static boost::intrusive_ptr< vdev_req_context > make_req_context() {
        return boost::intrusive_ptr< vdev_req_context >(sisl::ObjectAllocator< vdev_req_context >::make_object());
    }

    friend void intrusive_ptr_add_ref(vdev_req_context* req) { req->refcount.increment(1); }
    friend void intrusive_ptr_release(vdev_req_context* req) {
        if (req->refcount.decrement_testz()) { sisl::ObjectAllocator< vdev_req_context >::deallocate(req); }
    }

    vdev_req_context(const vdev_req_context&) = delete;
    vdev_req_context(vdev_req_context&&) noexcept = delete;
    vdev_req_context& operator=(const vdev_req_context&) = delete;
    vdev_req_context& operator=(vdev_req_context&&) noexcept = delete;

    virtual ~vdev_req_context() { version = 0; }

private:
    static std::atomic< uint64_t > s_req_id;

protected:
    friend class sisl::ObjectAllocator< vdev_req_context >;
    vdev_req_context() : request_id{s_req_id.fetch_add(1, std::memory_order_relaxed)} {}
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
    uint32_t m_blk_size{4096};
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
    static void static_process_completions(int64_t res, uint8_t* cookie);

    void init(DeviceManager* mgr, vdev_info_block* vb, uint32_t blk_size, bool auto_recovery,
              vdev_high_watermark_cb_t hwm_cb);

    // Create a new virtual dev for these parameters
    VirtualDev(DeviceManager* mgr, const char* name, PhysicalDevGroup pdev_group, blk_allocator_type_t allocator_type,
               uint64_t size_in, uint32_t nmirror, bool is_stripe, uint32_t blk_size, char* context,
               uint64_t context_size, bool auto_recovery = false, vdev_high_watermark_cb_t hwm_cb = nullptr);

    // Load the virtual dev from vdev_info_block and create a Virtual Dev instance
    VirtualDev(DeviceManager* mgr, const char* name, vdev_info_block* vb, PhysicalDevGroup pdev_group,
               blk_allocator_type_t allocator_type, bool recovery_init, bool auto_recovery = false,
               vdev_high_watermark_cb_t hwm_cb = nullptr);

    VirtualDev(const VirtualDev& other) = delete;
    VirtualDev& operator=(const VirtualDev& other) = delete;
    VirtualDev(VirtualDev&&) noexcept = delete;
    VirtualDev& operator=(VirtualDev&&) noexcept = delete;
    virtual ~VirtualDev() = default;

    /// @brief Adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
    /// takes lock for writing and not reading
    ///
    /// @param chunk Chunk to be added
    virtual void add_chunk(PhysicalDevChunk* chunk);

    /// @brief get the next chunk handle based on input dev_id and chunk_id
    /// @param dev_id : the current dev_id
    /// @param chunk_id : the current chunk_id
    /// @return  the hundle to the next chunk, if current chunk is the last chunk, loop back to begining device/chunk;
    ///
    /// TODO: organize chunks in a vector so that we can get next chunk id easily;
    PhysicalDevChunk* get_next_chunk(uint32_t dev_id, uint32_t chunk_id);

    /// @brief Formats the vdev asynchronously by zeroing the entire vdev. It will use underlying physical device
    /// capabilities to zero them if fast zero is possible, otherwise will zero block by block
    /// @param cb Callback after formatting is completed.
    virtual void async_format(vdev_io_comp_cb_t cb);

    /////////////////////// Block Allocation related methods /////////////////////////////
    /// @brief This method allocates contigous blocks in the vdev
    /// @param nblks : Number of blocks to allocate
    /// @param hints : Hints about block allocation, (specific device to allocate, stream etc)
    /// @param out_blkid : Pointer to where allocated BlkId to be placed
    /// @return BlkAllocStatus : Status about the allocation
    virtual BlkAllocStatus alloc_contiguous_blk(blk_count_t nblks, const blk_alloc_hints& hints, BlkId* out_blkid);

    /// @brief This method allocates blocks in the vdev and it could be non-contiguous, hence multiple BlkIds are
    /// returned
    /// @param nblks : Number of blocks to allocate
    /// @param hints : Hints about block allocation, (specific device to allocate, stream etc)
    /// @param out_blkid : Reference to the vector of blkids to be placed. It appends into the vector
    /// @return BlkAllocStatus : Status about the allocation
    virtual BlkAllocStatus alloc_blk(uint32_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid);

    /// @brief Checks if a given block id is allocated in the in-memory version of the blk allocator
    /// @param blkid : BlkId to check for allocation
    /// @return true or false
    virtual bool is_blk_alloced(const BlkId& blkid) const;

    /// @brief Commits the blkid in on-disk version of the blk allocator. The blkid is assumed to be allocated using
    /// alloc_blk or alloc_contiguous_blk method earlier (either after reboot or prior to reboot). It is not required
    /// to call this method if alloc_blk is called and system is not restarted. Typical use case of this method is
    /// during recovery where alloc_blk is called but before it was checkpointed, it crashed and we are trying to
    /// recover Please note that even calling this method is not guaranteed to persisted until checkpoint is taken.
    /// @param blkid BlkId to commit explicitly.
    /// @return Allocation Status
    virtual BlkAllocStatus commit_blk(const BlkId& blkid);

    virtual bool free_on_realtime(const BlkId& b);
    virtual void free_blk(const BlkId& b);

    /////////////////////// Write API related methods /////////////////////////////
    /// @brief Asynchornously write the buffer to the device on a given blkid
    /// @param buf : Buffer to write data from
    /// @param size : Size of the buffer
    /// @param bid : BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @param cb : Callback once write is completed
    /// @param cookie : cookie set by caller and returned on completion; It is defaulted to null as some caller is not
    /// intrested of of this field
    /// @param part_of_batch : Is this write part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this write request will not be queued.
    void async_write(const char* buf, uint32_t size, const BlkId& bid, vdev_io_comp_cb_t cb,
                     const void* cookie = nullptr, bool part_of_batch = false);

    /// @brief Asynchornously write the buffer to the device on a given blkid from vector of buffer
    /// @param iov : Vector of buffer to write data from
    /// @param iovcnt : Count of buffer
    /// @param bid  BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @param cb : Callback once write is completed
    /// @param cookie : cookie set by caller and returned on completion; It is defaulted to null as some caller is not
    /// intrested of of this field
    /// @param part_of_batch : Is this write part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this write request will not be queued.
    void async_writev(const iovec* iov, int iovcnt, const BlkId& bid, vdev_io_comp_cb_t cb,
                      const void* cookie = nullptr, bool part_of_batch = false);

    /// @brief Synchronously write the buffer to the blkid
    /// @param buf : Buffer to write data from
    /// @param size : Size of the buffer
    /// @param bid : BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @return ssize_t: Size of the data actually written.
    ssize_t sync_write(const char* buf, uint32_t size, const BlkId& bid);

    /// @brief Synchronously write the vector of buffers to the blkid
    /// @param iov : Vector of buffer to write data from
    /// @param iovcnt : Count of buffer
    /// @param bid  BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @return ssize_t: Size of the data actually written.
    ssize_t sync_writev(const iovec* iov, int iovcnt, const BlkId& bid);

    /////////////////////// Read API related methods /////////////////////////////

    /// @brief Asynchronously read the data for a given BlkId.
    /// @param buf : Buffer to read data to
    /// @param size : Size of the buffer
    /// @param bid : BlkId from data needs to be read
    /// @param cb : Callback once the read is completed and buffer is filled with data. Note that we don't support
    /// partial data read and hence callback will not be provided with size read or written
    /// @param cookie : cookie set by caller and returned on completion; It is defaulted to null as some caller is not
    /// intrested of of this field
    /// @param part_of_batch : Is this read part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this read request will not be queued.
    void async_read(char* buf, uint64_t size, const BlkId& bid, vdev_io_comp_cb_t cb, const void* cookie = nullptr,
                    bool part_of_batch = false);

    /// @brief Asynchronously read the data for a given BlkId to the vector of buffers
    /// @param iov : Vector of buffer to write read to
    /// @param iovcnt : Count of buffer
    /// @param size : Size of the actual data, it is really to optimize the iovec from iterating again to get size
    /// @param bid : BlkId from data needs to be read
    /// @param cb : Callback once the read is completed and buffer is filled with data. Note that we don't support
    /// partial data read and hence callback will not be provided with size read or written.
    /// @param cookie : cookie set by caller and returned on completion; It is defaulted to null as some caller is not
    /// intrested of of this field
    /// @param part_of_batch : Is this read part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this read request will not be queued.
    void async_readv(iovec* iovs, int iovcnt, uint64_t size, const BlkId& bid, vdev_io_comp_cb_t cb,
                     const void* cookie = nullptr, bool part_of_batch = false);

    /// @brief Synchronously read the data for a given BlkId.
    /// @param buf : Buffer to read data to
    /// @param size : Size of the buffer
    /// @param bid : BlkId from data needs to be read
    /// @return ssize_t: Size of the data actually read.
    ssize_t sync_read(char* buf, uint32_t size, const BlkId& bid);

    /// @brief Synchronously read the data for a given BlkId to vector of buffers
    /// @param iov : Vector of buffer to write read to
    /// @param iovcnt : Count of buffer
    /// @param size : Size of the actual data, it is really to optimize the iovec from iterating again to get size
    /// @return ssize_t: Size of the data actually read.
    ssize_t sync_readv(iovec* iov, int iovcnt, const BlkId& bid);

    /////////////////////// Other API related methods /////////////////////////////

    /// @brief Fsync the underlying physical devices that vdev is sitting on asynchornously
    /// @param cb Callback upon fsync on all devices is completed
    void fsync_pdevs(vdev_io_comp_cb_t cb);

    /// @brief Submit the batch of IOs previously queued as part of async read/write APIs.
    void submit_batch();

    void get_vb_context(const sisl::blob& ctx_data) const;
    void update_vb_context(const sisl::blob& ctx_data);
    virtual void recovery_done();
    void cp_flush();

    ////////////////////////// Standard Getters ///////////////////////////////
    virtual uint64_t available_blks() const;
    virtual uint64_t size() const { return (num_chunks() * chunk_size()); }
    virtual uint64_t used_size() const;
    virtual uint64_t num_chunks() const { return m_num_chunks; }
    virtual uint64_t chunk_size() const { return m_chunk_size; }
    virtual uint32_t blks_per_chunk() const { return chunk_size() / block_size(); }
    virtual uint32_t block_size() const;
    virtual uint32_t num_mirrors() const;
    virtual std::string to_string() const { return std::string{}; }
    virtual nlohmann::json get_status(const int log_level) const;

    static uint64_t get_len(const iovec* iov, const int iovcnt);
    virtual void reset_failed_state();

    // Remove this virtualdev altogether
    void rm_device();
    void expand(const uint32_t addln_size);

    /* Create debug bitmap for all chunks */
    virtual BlkAllocStatus create_debug_bm();

    /* Update debug bitmap for a given BlkId */
    virtual BlkAllocStatus update_debug_bm(const BlkId& bid);

    /* Verify debug bitmap for all chunks */
    virtual BlkAllocStatus verify_debug_bm(const bool free_debug_bm = true);
    stream_info_t reserve_stream(const stream_id_t* id_list, const uint32_t num_streams);
    stream_info_t alloc_stream(uint64_t size);
    void free_stream(const stream_info_t& stream_info);
    uint32_t align_size() const;
    uint32_t phys_page_size() const;
    uint32_t atomic_page_size() const;

protected:
    /// @brief : internal implementation of async_write
    ///
    /// @param buf : buffer to be written
    /// @param size : total size of buffer
    /// @param pdev : pointer to physical device
    /// @param pchunk : pointer to physical chunk in the device
    /// @param dev_offset : offset within the physical device
    /// @param cb : Completion callback to be called after write is completed
    /// @param cookie : cookie set by caller and returned on completion;
    /// @param part_of_batch : Is this write part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this write request will not be queued.
    void async_write_internal(const char* buf, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                              uint64_t dev_offset, vdev_io_comp_cb_t cb, const void* cookie = nullptr,
                              bool part_of_batch = false);

    /// @brief : internal implementation of async_writev
    ///
    /// @param iov : Vector of buffer to write data from
    /// @param iovcnt : Count of buffer
    /// @param pdev : pointer to physical device
    /// @param pchunk : pointer to physical chunk in the device
    /// @param dev_offset : offset within the physical device
    /// @param cb : Completion callback to be called after write is completed
    /// @param cookie : cookie set by caller and returned on completion;
    /// @param part_of_batch : Is this write part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this write request will not be queued.
    void async_writev_internal(const iovec* iov, int iovcnt, uint64_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                               uint64_t dev_offset, vdev_io_comp_cb_t cb, const void* cookie = nullptr,
                               bool part_of_batch = false);

    ssize_t sync_write_internal(const char* buf, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                uint64_t dev_offset);

    ssize_t sync_writev_internal(const iovec* iov, int iovcnt, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                 uint64_t dev_offset);

    /// @brief  Internal implementation of async read
    ///
    /// @param buf : buffer to be read data to
    /// @param size : total size of buffer
    /// @param pdev : pointer to physical device
    /// @param pchunk : pointer to physical chunk in the device
    /// @param dev_offset : offset within the physical device
    /// @param cb : Completion callback to be called after read is completed
    /// @param cookie : cookie set by caller and returned on completion;
    /// @param part_of_batch : Is this read part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this read request will not be queued.
    void async_read_internal(char* buf, uint64_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk, uint64_t dev_offset,
                             vdev_io_comp_cb_t cb, const void* cookie = nullptr, bool part_of_batch = false);

    /// @brief : internal implementation of async_readv
    ///
    /// @param iov : Vector of buffer to read data to
    /// @param iovcnt : Count of buffer
    /// @param pdev : pointer to physical device
    /// @param pchunk : pointer to physical chunk in the device
    /// @param dev_offset : offset within the physical device
    /// @param cb : Completion callback to be called after read is completed
    /// @param cookie : cookie set by caller and returned on completion;
    /// @param part_of_batch : Is this read part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this read request will not be queued.
    void async_readv_internal(iovec* iovs, int iovcnt, uint64_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                              uint64_t dev_offset, vdev_io_comp_cb_t cb, const void* cookie = nullptr,
                              bool part_of_batch = false);

    ssize_t sync_read_internal(char* buf, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                               uint64_t dev_offset);
    ssize_t sync_readv_internal(iovec* iov, int iovcnt, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                uint64_t dev_offset);

private:
    void write_nmirror(const char* buf, const uint32_t size, PhysicalDevChunk* chunk, const uint64_t dev_offset_in);
    void writev_nmirror(const iovec* iov, const int iovcnt, const uint32_t size, PhysicalDevChunk* chunk,
                        const uint64_t dev_offset_in);

    virtual BlkAllocStatus do_alloc_blk(blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid);
    uint32_t num_streams() const;
    uint64_t stream_size() const;

    void add_primary_chunk(PhysicalDevChunk* chunk);
    void add_mirror_chunk(PhysicalDevChunk* chunk);
    PhysicalDevChunk* create_dev_chunk(const uint32_t pdev_ind, const std::shared_ptr< BlkAllocator >& ba,
                                       const uint32_t primary_id);
    uint64_t to_dev_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const;
    BlkAllocStatus alloc_blk_from_chunk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid, PhysicalDevChunk* const chunk);
    void reserve_stream(const stream_id_t id);
};

} // namespace homestore
