/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#include "device/device.h"
#include "device/chunk_selector.hpp"

namespace homestore {
class PhysicalDev;
class Chunk;
class BlkAllocator;

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

class VirtualDev;
ENUM(vdev_event_t, uint8_t, SIZE_THRESHOLD_REACHED, VDEV_ERRORED_OUT);
using vdev_event_cb_t = std::function< void(VirtualDev&, vdev_event_t, const std::string&) >;

class VirtualDev {
protected:
    vdev_info m_vdev_info;      // This device block info
    DeviceManager& m_dmgr;      // Device Manager back pointer
    std::string m_name;         // Name of the vdev
    vdev_event_cb_t m_event_cb; // Callback registered for any events
    VirtualDevMetrics m_metrics;

    std::mutex m_mgmt_mutex;          // Any mutex taken for management operations (like adding/removing chunks).
    std::set< PhysicalDev* > m_pdevs; // PDevs this vdev is working on
    sisl::sparse_vector< shared< Chunk > > m_all_chunks; // All chunks part of this vdev
    std::unique_ptr< ChunkSelector > m_chunk_selector;   // Instance of chunk selector
    blk_allocator_type_t m_allocator_type;
    chunk_selector_type_t m_chunk_selector_type;
    bool m_auto_recovery;

public:
    VirtualDev(DeviceManager& dmgr, const vdev_info& vinfo, blk_allocator_type_t allocator_type,
               chunk_selector_type_t chunk_selector, vdev_event_cb_t event_cb, bool is_auto_recovery);

    VirtualDev(const VirtualDev& other) = delete;
    VirtualDev& operator=(const VirtualDev& other) = delete;
    VirtualDev(VirtualDev&&) noexcept = delete;
    VirtualDev& operator=(VirtualDev&&) noexcept = delete;
    virtual ~VirtualDev() = default;

    /// @brief Adds chunk to the vdev. It is expected that this will happen at startup time and hence it only
    /// takes lock for writing and not reading
    ///
    /// @param chunk Chunk to be added
    virtual void add_chunk(cshared< Chunk >& chunk, bool is_fresh_chunk);

    /// @brief Formats the vdev asynchronously by zeroing the entire vdev. It will use underlying physical device
    /// capabilities to zero them if fast zero is possible, otherwise will zero block by block
    /// @param cb Callback after formatting is completed.
    virtual folly::Future< bool > async_format();

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

    virtual void free_blk(const BlkId& b);

    /////////////////////// Write API related methods /////////////////////////////
    /// @brief Asynchornously write the buffer to the device on a given blkid
    /// @param buf : Buffer to write data from
    /// @param size : Size of the buffer
    /// @param bid : BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @param part_of_batch : Is this write part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this write request will not be queued.
    /// @return future< bool > Future result of success or failure
    folly::Future< bool > async_write(const char* buf, uint32_t size, const BlkId& bid, bool part_of_batch = false);

    folly::Future< bool > async_write(const char* buf, uint32_t size, cshared< Chunk >& chunk,
                                      uint64_t offset_in_chunk);

    /// @brief Asynchornously write the buffer to the device on a given blkid from vector of buffer
    /// @param iov : Vector of buffer to write data from
    /// @param iovcnt : Count of buffer
    /// @param bid  BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @param part_of_batch : Is this write part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this write request will not be queued.
    /// @return future< bool > Future result of success or failure
    folly::Future< bool > async_writev(const iovec* iov, int iovcnt, const BlkId& bid, bool part_of_batch = false);

    // TODO: This needs to be removed once Journal starting to use AppendBlkAllocator
    folly::Future< bool > async_writev(const iovec* iov, const int iovcnt, cshared< Chunk >& chunk,
                                       uint64_t offset_in_chunk);

    /// @brief Synchronously write the buffer to the blkid
    /// @param buf : Buffer to write data from
    /// @param size : Size of the buffer
    /// @param bid : BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @return ssize_t: Size of the data actually written.
    void sync_write(const char* buf, uint32_t size, const BlkId& bid);
    void sync_write(const char* buf, uint32_t size, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    // TODO: This needs to be removed once Journal starting to use AppendBlkAllocator
    void sync_write(const char* buf, uint32_t size, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    /// @brief Synchronously write the vector of buffers to the blkid
    /// @param iov : Vector of buffer to write data from
    /// @param iovcnt : Count of buffer
    /// @param bid  BlkId which was previously allocated. It is expected that entire size was allocated previously.
    /// @return ssize_t: Size of the data actually written.
    void sync_writev(const iovec* iov, int iovcnt, const BlkId& bid);
    void sync_writev(const iovec* iov, int iovcnt, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    // TODO: This needs to be removed once Journal starting to use AppendBlkAllocator
    void sync_writev(const iovec* iov, int iovcnt, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    /////////////////////// Read API related methods /////////////////////////////

    /// @brief Asynchronously read the data for a given BlkId.
    /// @param buf : Buffer to read data to
    /// @param size : Size of the buffer
    /// @param bid : BlkId from data needs to be read
    /// @param part_of_batch : Is this read part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this read request will not be queued.
    /// @return future< bool > Future result of success or failure
    folly::Future< bool > async_read(char* buf, uint64_t size, const BlkId& bid, bool part_of_batch = false);

    /// @brief Asynchronously read the data for a given BlkId to the vector of buffers
    /// @param iov : Vector of buffer to write read to
    /// @param iovcnt : Count of buffer
    /// @param size : Size of the actual data, it is really to optimize the iovec from iterating again to get size
    /// @param bid : BlkId from data needs to be read
    /// @param part_of_batch : Is this read part of batch io. If true, caller is expected to call submit_batch at
    /// the end of the batch, otherwise this read request will not be queued.
    /// @return future< bool > Future result of success or failure
    folly::Future< bool > async_readv(iovec* iovs, int iovcnt, uint64_t size, const BlkId& bid,
                                      bool part_of_batch = false);

    /// @brief Synchronously read the data for a given BlkId.
    /// @param buf : Buffer to read data to
    /// @param size : Size of the buffer
    /// @param bid : BlkId from data needs to be read
    /// @return ssize_t: Size of the data actually read.
    void sync_read(char* buf, uint32_t size, const BlkId& bid);
    void sync_read(char* buf, uint32_t size, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    // TODO: This needs to be removed once Journal starting to use AppendBlkAllocator
    void sync_read(char* buf, uint32_t size, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    /// @brief Synchronously read the data for a given BlkId to vector of buffers
    /// @param iov : Vector of buffer to write read to
    /// @param iovcnt : Count of buffer
    /// @param size : Size of the actual data, it is really to optimize the iovec from iterating again to get size
    /// @return ssize_t: Size of the data actually read.
    void sync_readv(iovec* iov, int iovcnt, const BlkId& bid);
    void sync_readv(iovec* iov, int iovcnt, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    // TODO: This needs to be removed once Journal starting to use AppendBlkAllocator
    void sync_readv(iovec* iov, int iovcnt, cshared< Chunk >& chunk, uint64_t offset_in_chunk);

    /////////////////////// Other API related methods /////////////////////////////

    /// @brief Fsync the underlying physical devices that vdev is sitting on asynchornously
    /// @return future< bool > Future result with bool to indicate when fsync is actually executed
    folly::Future< bool > queue_fsync_pdevs();

    /// @brief Submit the batch of IOs previously queued as part of async read/write APIs.
    void submit_batch();

    virtual void recovery_done();

    ////////////////////// Checkpointing related methods ///////////////////////////
    /// @brief
    ///
    /// @param cp
    void cp_flush(CP* cp);

    std::unique_ptr< CPContext > create_cp_context();

    ////////////////////////// Standard Getters ///////////////////////////////
    virtual uint64_t available_blks() const;
    virtual uint64_t size() const { return m_vdev_info.vdev_size; }
    virtual uint64_t used_size() const;
    virtual uint64_t num_chunks() const { return m_vdev_info.num_primary_chunks; }
    virtual uint32_t block_size() const { return m_vdev_info.blk_size; }
    virtual uint32_t num_mirrors() const { return 0; }
    virtual std::string to_string() const;
    virtual nlohmann::json get_status(int log_level) const;

    uint32_t align_size() const;
    uint32_t optimal_page_size() const;
    uint32_t atomic_page_size() const;

    static uint64_t get_len(const iovec* iov, const int iovcnt);
    const std::set< PhysicalDev* >& get_pdevs() const { return m_pdevs; }
    std::vector< shared< Chunk > > get_chunks() const;
    shared< Chunk > get_next_chunk(cshared< Chunk >& chunk) const;

    ///////////////////////// Meta operations on vdev ////////////////////////
    void update_vdev_private(const sisl::blob& data);

private:
    BlkAllocStatus do_alloc_blk(blk_count_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid);
    uint64_t to_dev_offset(const BlkId& b, Chunk** chunk) const;
    BlkAllocStatus alloc_blk_from_chunk(blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid, Chunk* chunk);
};

class VDevCPContext : public CPContext {
    // place holder for future needs in which components underlying virtualdev needs cp flush context;
};

} // namespace homestore
