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
#include <sys/uio.h>
#include <cstdint>

#include <folly/small_vector.h>
#include <folly/futures/Future.h>
#include <sisl/fds/buffer.hpp>
#include <sisl/utility/atomic_counter.hpp>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>

namespace homestore {
// callback type for caller to provide
typedef std::function< void(std::error_condition) > io_completion_cb_t;

class VirtualDev;
struct vdev_info;
struct stream_info_t;
class BlkReadTracker;
struct blk_alloc_hints;
class ChunkSelector;

class BlkDataService {
public:
    /**
     * @brief Constructs a new BlkDataService object with the given custom chunk selector.
     *
     * @param custom_chunk_selector A shared pointer to a ChunkSelector object that will be used to select chunks for
     * this service.
     */
    BlkDataService(shared< ChunkSelector > custom_chunk_selector);

    /**
     * @brief Destructor for the BlkDataService class.
     *
     * This destructor is responsible for cleaning up any resources
     * allocated by the BlkDataService instance.
     */
    ~BlkDataService();

    /**
     * @brief Creates a new virtual device with the specified size and block size, using the specified
     * block allocator and chunk selector types. The virtual device will be composed of the specified
     * number of chunks.
     *
     * @param size The size of the virtual device, in bytes.
     * @param blk_size The size of each block in the virtual device, in bytes.
     * @param alloc_type The type of block allocator to use for the virtual device.
     * @param chunk_sel_type The type of chunk selector to use for the virtual device.
     * @param num_chunks The number of chunks to use for the virtual device.
     */
    void create_vdev(uint64_t size, uint32_t blk_size, blk_allocator_type_t alloc_type,
                     chunk_selector_type_t chunk_sel_type, uint32_t num_chunks);

    /**
     * @brief Opens a virtual device with the specified virtual device information.
     *
     * @param vinfo The virtual device information.
     * @param load_existing Whether to load an existing virtual device or create a new one.
     * @return A shared pointer to the opened virtual device.
     */
    shared< VirtualDev > open_vdev(vdev_info const& vinfo, bool load_existing);

    /**
     * @brief Asynchronously allocates and writes data to a block device using the provided scatter-gather list.
     *
     * @param sgs The scatter-gather list containing the data to write.
     * @param hints Hints for allocating the block(s) to write to.
     * @param out_blkids The ID(s) of the block(s) that were allocated and written to.
     * @param part_of_batch Whether this operation is part of a batch of operations.
     * @return A Future that will contain an error code indicating the success or failure of the operation.
     */
    folly::Future< std::error_code > async_alloc_write(sisl::sg_list const& sgs, blk_alloc_hints const& hints,
                                                       MultiBlkId& out_blkids, bool part_of_batch = false);

    /**
     * @brief Asynchronously writes the given buffer to the specified block ID.
     *
     * @param buf The buffer to write.
     * @param size The size of the buffer in bytes.
     * @param bid The ID of the block to write to.
     * @param part_of_batch Whether this write is part of a batch operation.
     * @return A Future that will resolve to an error code indicating the result of the write operation.
     */
    folly::Future< std::error_code > async_write(const char* buf, uint32_t size, MultiBlkId const& bid,
                                                 bool part_of_batch);
    /**
     * @brief : asynchronous write with input block ids;
     *
     * @param sgs : the data buffer that needs to be written
     * @param hints : blk alloc hints
     * @param in_blkids : input block ids that this write should be written to;
     * @param cb : callback that will be triggered after write completes
     * @param part_of_batch : is this write part of a batch;
     */
    folly::Future< std::error_code > async_write(sisl::sg_list const& sgs, MultiBlkId const& in_blkids,
                                                 bool part_of_batch = false);

    /**
     * @brief Asynchronously reads data from the specified block ID into the provided buffer.
     *
     * @param bid The ID of the block to read from.
     * @param buf The buffer to read data into.
     * @param size The number of bytes to read.
     * @param part_of_batch Whether this read is part of a batch operation.
     * @return A Future that will resolve to an error code indicating the result of the operation.
     */
    folly::Future< std::error_code > async_read(MultiBlkId const& bid, uint8_t* buf, uint32_t size,
                                                bool part_of_batch = false);

    /**
     * @brief Asynchronously reads data from the specified block ID.
     *
     * @param bid The block ID to read from.
     * @param sgs The scatter-gather list to store the read data.
     * @param size The size of the data to read.
     * @param part_of_batch Whether this read is part of a batch.
     *
     * @return A `folly::Future` that will contain the error code of the read operation.
     */
    folly::Future< std::error_code > async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false);

    /**
     * @brief Commits the block with the given MultiBlkId.
     *
     * @param bid The MultiBlkId of the block to commit.
     */
    void commit_blk(MultiBlkId const& bid);

    /**
     * @brief Allocates a contiguous block of disk space of the given size.
     *
     * @param size The size of the block to allocate, in bytes.
     * @param hints Hints for how to allocate the block.
     * @param out_blkids Output parameter that will be filled with the IDs of the allocated blocks.
     * @return The status of the block allocation attempt.
     */
    BlkAllocStatus alloc_blks(uint32_t size, blk_alloc_hints const& hints, MultiBlkId& out_blkids);

    /**
     * @brief Asynchronously frees the specified block IDs.
     * It is asynchronous because it might need to wait for pending read to complete if same block is being read and not
     * completed yet;
     *
     * @param bid The block IDs to free.
     * @return A Future that will resolve to an error code indicating the result of the operation.
     */
    folly::Future< std::error_code > async_free_blk(MultiBlkId const& bid);

    /**
     * @brief : get the blk size of this data service;
     *
     * @return : blk size
     */
    uint32_t get_blk_size() const { return m_blk_size; }

    /**
     * @brief : get the read block tracker handle;
     *
     * @return : the read block tracker pointer;
     */
    BlkReadTracker* read_blk_tracker() { return m_blk_read_tracker.get(); }

    /**
     * @brief Starts the block data service.
     *
     * This function starts the block data service, which is responsible for managing
     * the storage and retrieval of block data. Once started, the service will listen
     * for incoming requests and respond accordingly.
     */
    void start();

private:
    /**
     * @brief Initializes the block data service.
     *
     * This function initializes the block data service by performing any necessary setup
     * and configuration. It should be called before any other functions in the service are used.
     */
    void init();

    /**
     * @brief Callback function for processing data completion.
     *
     * This function is called when data processing is complete. It takes an error condition and a cookie as arguments.
     *
     * @param ec The error condition.
     * @param cookie A pointer to the cookie associated with the data processing.
     */
    static void process_data_completion(std::error_condition ec, void* cookie);

private:
    std::shared_ptr< VirtualDev > m_vdev;
    std::unique_ptr< BlkReadTracker > m_blk_read_tracker;
    std::shared_ptr< ChunkSelector > m_custom_chunk_selector;
    uint32_t m_blk_size;
};

extern BlkDataService& data_service();
} // namespace homestore
