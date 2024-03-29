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

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <vector>
#include <condition_variable>

#include "device.h"
#include "physical_dev.hpp"
#include "virtual_dev.hpp"
#include <homestore/logstore/log_store_internal.hpp>

namespace homestore {
typedef std::function< void(const off_t ret_off) > alloc_next_blk_cb_t;
using journal_id_t = uint64_t;

// Chunks used for journal vdev has journal related info stored in chunk private data.
// Each log device has a list of journal chunk data with next_chunk.
// Journal vdev will arrange the chunks in order during recovery.
struct JournalChunkPrivate {
    logdev_id_t logdev_id{0};
    bool is_head{false};       // Is it the head element.
    uint64_t created_at{0};    // Creation timestamp
    uint64_t end_of_chunk{0};  // The offset indicates end of chunk.
    chunk_num_t next_chunk{0}; // Next chunk in the list.
};

static_assert(sizeof(JournalChunkPrivate) <= chunk_info::user_private_size, "Journal private area bigger");

class JournalVirtualDev : public VirtualDev {
public:
    // Client use journal vdev open to create a descriptor to append log entries.
    // Each descriptor is independent list of chunks in order and like sliding window
    // maintains size, offsets like the left side (m_data_start_offset) and
    // right side (m_end_offset). Truncate increases the left m_data_start_offset
    // and pop chunks from the front of the list. alloc_next_append_blk adds more chunk to
    // the back of list if no space and adjusts the right m_end_offset. All offsets
    // only increase and never wraps around. Each chunk in the descriptor has private
    // data about the logdev_id its part of, next chunk to maintain the list.
    struct Descriptor {
    private:
        JournalVirtualDev& m_vdev;
        logdev_id_t m_logdev_id; // Unique id identifying the journal descriptor.
        // off_t is long. make it uint64_t ?
        off_t m_seek_cursor{0}; // the seek cursor

        off_t m_data_start_offset{0};                   // Start offset of where actual data begin for this vdev
        std::atomic< uint64_t > m_write_sz_in_total{0}; //  Size will be decreased by truncate and increased by append;
        bool m_truncate_done{true};
        uint64_t m_reserved_sz{0};                       // write size within chunk, used to check chunk boundary;
        std::vector< shared< Chunk > > m_journal_chunks; // Chunks part of this journal in order.
        uint64_t m_total_size{0};                        // Total size of all chunks.
        off_t m_end_offset{0};        // Offset right to window. Never reduced. Increased in multiple of chunk size.
        bool m_end_offset_set{false}; // Adjust the m_end_offset only once during init.
        std::atomic< bool > m_ready_for_truncate{false}; // reset by truncation thread and set by append thread;
        friend class JournalVirtualDev;

    public:
        // Descriptor is created via JournalVirtualDev::open similar to file descriptor.
        Descriptor(JournalVirtualDev& vdev, logdev_id_t id) : m_vdev(vdev), m_logdev_id(id) {}

        // Create and append the chunk to m_journal_chunks.
        void append_chunk();
#if 0
        bool ready_for_truncate() const { return m_ready_for_truncate.load(std::memory_order_relaxed); }
        void set_ready_for_truncate() { m_ready_for_truncate.store(true, std::memory_order_relaxed); }
        void unset_ready_for_truncate() { m_ready_for_truncate.store(false, std::memory_order_relaxed); }
#endif
        /**
         * @brief : allocate space specified by input size.
         * this API will always be called in single thread;
         *
         * @param size : size to be allocated
         *
         * @return : the start unique offset of the allocated space
         *
         * Possible calling sequence:
         * offset_1 = alloc_next_append_blk(size1);
         * offset_2 = alloc_next_append_blk(size2);
         * write_at_offset(offset_2);
         * write_at_offset(offset_1);
         */
        off_t alloc_next_append_blk(const size_t size);

        /**
         * @brief : writes up to count bytes from the buffer starting at buf. append advances seek cursor;
         *
         * @param buf : buffer to be written
         * @param count : size of buffer in bytes
         * @param req : async req;
         *
         * @return : On success, the number of bytes written is returned.  On error, -1 is returned.
         */
        folly::Future< std::error_code > async_append(const uint8_t* buf, size_t count);

        /**
         * @brief : writes up to count bytes from the buffer starting at buf at offset offset.
         * The cursor is not changed.
         * pwrite always use offset returned from alloc_next_append_blk to do the write;
         * pwrite should not across chunk boundaries because alloc_next_append_blk guarantees offset returned always
         * doesn't across chunk boundary;
         *
         * @param buf : buffer pointing to the data being written
         * @param size : size of buffer to be written
         * @param offset : offset to be written
         * @param req : async req
         *
         * @return : On success, the number of bytes read or written is returned, or -1 on error.
         */
        folly::Future< std::error_code > async_pwrite(const uint8_t* buf, size_t size, off_t offset);

        /**
         * @brief : writes iovcnt buffers of data described by iov to the offset.
         * pwritev doesn't advance curosr;
         *
         * @param iov : the iovec that holds vector of data buffers
         * @param iovcnt : size of iov
         * @param offset : offset to be written
         * @param req : aync req.
         * if req is not nullptr, it will be an async call.
         * if req is nullptr, it will be a sync call.
         *
         * @return : On success, number of bytes written. On error, -1 is returned
         */
        folly::Future< std::error_code > async_pwritev(const iovec* iov, int iovcnt, off_t offset);

        /// @brief writes up to count bytes from the buffer starting at buf at offset offset. The cursor is not
        /// changed. pwrite always use offset returned from alloc_next_append_blk to do the write;pwrite should not
        /// across chunk boundaries because alloc_next_append_blk guarantees offset returned always doesn't across chunk
        /// boundary;
        ///
        /// @param buf : buffer pointing to the data being written
        /// @param size : size of buffer to be written
        /// @param offset : offset to be written
        /// @return : On success, the number of bytes written is returned, or -1 on error.
        void sync_pwrite(const uint8_t* buf, size_t size, off_t offset);

        void sync_pwritev(const iovec* iov, int iovcnt, off_t offset);

        /**
         * @brief : read up to count bytes into the buffer starting at buf.
         * Only read the size before end of chunk and update m_seek_cursor to next chunk;
         *
         * @param buf : the buffer that points to read out data
         * @param count : the size of buffer;
         *
         * @return : On success, the number of bytes read is returned (zero indicates end of file), and the cursor is
         * advanced by this number. it is not an error if this number is smaller than the number requested, because it
         * can be end of chunk, since read won't across chunk.
         */
        size_t sync_next_read(uint8_t* buf, size_t count_in);

        /**
         * @brief : reads up to count bytes at offset into the buffer starting at buf.
         * The curosr is not updated.
         *
         * @param buf : the buffer that points to the read out data.
         * @param count : size of buffer
         * @param offset : the start offset to do read
         *
         * @return : return the error code of the read
         */
        std::error_code sync_pread(uint8_t* buf, size_t count_in, off_t offset);

        /**
         * @brief : read at offset and save output to iov.
         * We don't have a use case for external caller of preadv now, meaning iov will always have only 1 element;
         * if the len is acrossing chunk boundary,
         * we only do read on one chunk and return the num of bytes read on this chunk;
         *
         * @param iov : the iovect to store the read out data
         * @param iovcnt : size of iovev
         * @param offset : the start offset to read
         *
         * @return : return the error code of the read
         */
        std::error_code sync_preadv(iovec* iov, int iovcnt, off_t offset);

        /**
         * @brief : repositions the cusor of the device to the argument offset
         * according to the directive whence as follows:
         * SEEK_SET
         *     The curosr is set to offset bytes.
         * SEEK_CUR
         *     The cursor is set to its current location plus offset bytes.
         * SEEK_END
         *     Not supported yet. No use case for now.
         *
         * @param offset : the logical offset
         * @param whence : see above
         *
         * @return :  Upon successful completion, lseek() returns the resulting offset
         * location as measured in bytes from the beginning of the file.  On
         * error, the value (off_t) -1 is returned
         */
        off_t lseek(off_t offset, int whence = SEEK_SET);

        /**
         * @brief : this API can be replaced by lseek(0, SEEK_CUR);
         *
         * @return : current curosr offset
         */
        off_t seeked_pos() const { return m_seek_cursor; }

        /**
         * @brief :- it returns the vdev offset after nbytes from start offset
         */
        off_t dev_offset(off_t nbytes) const;

        /**
         * @brief : get the start logical offset where data starts;
         *
         * @return : the start logical offset where data starts;
         */
        off_t data_start_offset() const { return m_data_start_offset; }

        off_t end_offset() const { return m_end_offset; }

        /**
         * @brief : persist start logical offset to vdev's super block
         * Supposed to be called when truncate happens;
         *
         * @param offset : the start logical offset to be persisted
         */
        void update_data_start_offset(off_t offset);

        /**
         * @brief : get the logical tail offset;
         *
         * @param reserve_space_include : include reserved space or not;
         *
         * @return : the logical tail offset;
         */
        off_t tail_offset(bool reserve_space_include = true) const;

        /**
         * @brief : update the tail to vdev, this API will be called during reboot and
         * upper layer(logdev) has completed scanning all the valid records in vdev and then
         * update the tail in vdev.
         *
         * @param tail : logical tail offset
         */
        void update_tail_offset(off_t tail);

        /**
         * @brief : truncate vdev to the provided logcial offset
         *
         * @param truncate_offset: logical offset that vdev needs to truncate to.
         *
         * Concurrency:
         * 1. truncate and write can be received concurrently.
         * 2. multiple truncate calls can be received concurently.
         *
         * Following things should happen for truncate:
         * 1. update in-memory counter of total write size.
         * 2. update vdev superblock of the new start logical offset that is being truncate to;
         *
         */
        void truncate(off_t truncate_offset);

        /**
         * @brief : get the total size in journal
         *
         * @return : the total space in journal
         */
        uint64_t size() const { return m_total_size; }

        /**
         * @brief : get the used size in journal
         *
         * @return : the used space in journal
         */
        uint64_t used_size() const { return m_write_sz_in_total.load(std::memory_order_relaxed) + m_reserved_sz; }

        /**
         * @brief : get the free space left in journal
         *
         * @return : free space left in journal
         */
        uint64_t available_size() const { return size() - used_size(); }

        /**
         * @brief : get the free blks available in journal, assuming page_size as a measure of blks
         *
         * @return : free number of pages/blks available.
         */
        uint64_t available_blks() const { return available_size() / m_vdev.block_size(); }

        /**
         * @brief : Check if the offset_bytes lies at the last chunk.
         *
         * @return : check if last chunk or not.
         */
        bool is_offset_at_last_chunk(off_t offset_bytes);

        /**
         * @brief Get the status of the journal vdev and its internal structures
         * @param log_level: Log level to do verbosity.
         * @return Json containing internal details
         */
        nlohmann::json get_status(int log_level) const;

        logdev_id_t logdev_id() const { return m_logdev_id; }

        std::string to_string() const;

    private:
        /**
         * @brief : convert logical offset to physical offset for pwrite/pwritev;
         *
         * @param len : len of data that is going to be written
         * @param offset : logical offset to be written
         * @param dev_id : the return value of device id
         * @param chunk_id : the return value of chunk id
         * @param req : async req
         *
         * @return : the unique offset
         */
        auto process_pwrite_offset(size_t len, off_t offset);

        /**
         * @brief : convert logical offset in chunk to the physical device offset
         *
         * @param dev_id : the device id
         * @param chunk_id : the chunk id;
         * @param offset_in_chunk : the logical offset in chunk;
         *
         * @return : the physical device offset;
         */
        uint64_t get_offset_in_dev(uint32_t dev_id, uint32_t chunk_id, uint64_t offset_in_chunk) const;

        /**
         * @brief : get the physical start offset of the chunk;
         *
         * @param dev_id : the deivce id;
         * @param chunk_id : the chunk id;
         *
         * @return : the physical start offset of the chunk;
         */
        uint64_t get_chunk_start_offset(uint32_t dev_id, uint32_t chunk_id) const;

        /**
         * @brief : Convert from logical offset to device offset.
         * It handles device overloop, e.g. reach to end of the device then start from the beginning device
         *
         * @param log_offset : the logical offset
         * @param dev_id     : the device id after convertion
         * @param chunk_id   : the chunk id after convertion
         * @param offset_in_chunk : the relative offset in chunk
         *
         * @return : the unique offset after converion;
         */
        // uint64_t logical_to_dev_offset(off_t log_offset, uint32_t& dev_id, uint32_t& chunk_id,
        //                                off_t& offset_in_chunk) const;

        // Return the chunk, its index and offset in the chunk list.
        std::tuple< shared< Chunk >, uint32_t, off_t > offset_to_chunk(off_t log_offset, bool check = true) const;

        bool validate_append_size(size_t count) const;

        void high_watermark_check();

        bool is_alloc_accross_chunk(size_t size) const;

        auto get_dev_details(size_t len, off_t offset);
    };

    /* Create a new virtual dev for these parameters */
    JournalVirtualDev(DeviceManager& dmgr, const vdev_info& vinfo, vdev_event_cb_t event_cb);
    JournalVirtualDev(const JournalVirtualDev& other) = delete;
    JournalVirtualDev& operator=(const JournalVirtualDev& other) = delete;
    JournalVirtualDev(JournalVirtualDev&&) noexcept = delete;
    JournalVirtualDev& operator=(JournalVirtualDev&&) noexcept = delete;
    virtual ~JournalVirtualDev();

    // Initialize the journal vdev during reovery. Traverse all chunks
    // and group chunks based on logdev_id and its list.
    virtual void init() override;

    // Create and return a journal descriptor. A journal descriptor has a list of chunks
    // where log entries are stored. It also mantains offsets, size etc.
    shared< Descriptor > open(logdev_id_t id);

    /**
     * @brief Get the status of the journal vdev and its internal structures
     * @param log_level: Log level to do verbosity.
     * @return Json containing internal details
     */
    nlohmann::json get_status(int log_level) const override;

    uint64_t used_size() const override;
    uint64_t available_blks() const override;

    void update_chunk_private(shared< Chunk >& chunk, JournalChunkPrivate* chunk_private);
    uint64_t get_end_of_chunk(shared< Chunk >& chunk) const;

private:
    // Mapping of logdev id to its journal descriptors.
    std::unordered_map< logdev_id_t, shared< Descriptor > > m_journal_descriptors;
    std::mutex m_mutex;

    // Cache the chunks. Getting a chunk from the pool causes a single write of the
    // last chunk in the list to update its end_of_chunk and next_chunk.
    std::unique_ptr< ChunkPool > m_chunk_pool;
    std::shared_ptr< JournalChunkPrivate > m_init_private_data;
};

} // namespace homestore
