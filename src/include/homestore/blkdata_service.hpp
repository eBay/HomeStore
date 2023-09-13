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

using blk_t = uint64_t;
using blk_list_t = folly::small_vector< blk_t, 4 >;

class BlkDataService {
public:
    BlkDataService();
    ~BlkDataService();

    /**
     * @brief : called in non-recovery mode to create a new vdev for data service
     *
     * @param size : size of this vdev
     */
    void create_vdev(uint64_t size, homestore::blk_allocator_type_t alloc_type,
                     homestore::chunk_selector_type_t chunk_sel_type);

    /**
     * @brief : called during recovery to open existing vdev for data service
     *
     * @param vb : vdev info blk containing the details of this blkstore
     */
    shared< VirtualDev > open_vdev(vdev_info const& vinfo, bool load_existing);

    /**
     * @brief : asynchronous write without input block ids. Block ids will be allocated by this api and returned;
     *
     * @param sgs : the data buffer that needs to be written
     * @param hints : blk alloc hints
     * @param out_blkids : the output block ids that were allocated and written to
     * @param cb : callback that will be triggered after write completes;
     * @param part_of_batch : is this write part of a batch;
     */
    folly::Future< std::error_code > async_alloc_write(sisl::sg_list const& sgs, blk_alloc_hints const& hints,
                                                       MultiBlkId& out_blkids, bool part_of_batch = false);

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

    folly::Future< std::error_code > async_read(MultiBlkId const& bid, uint8_t* buf, uint32_t size,
                                                bool part_of_batch = false);

    /**
     * @brief : asynchronous read
     *
     * @param bid : block id to read
     * @param sgs : the read buffer stored
     * @param size : size to read
     * @param cb : callback that will be triggered after read completes
     * @param part_of_batch : is this read part of batch;
     */
    folly::Future< std::error_code > async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false);

    /**
     * @brief : commit a block, usually called during recovery
     *
     * @param bid : block id to commit;
     */
    void commit_blk(MultiBlkId const& bid);

    /**
     * @brief : alloc blocks based on input size;
     *
     * @param size : size to allocate blocks with;
     *
     * @return : the block list that have the blocks;
     */
    blk_list_t alloc_blks(uint32_t size);

    /**
     * @brief : asynchronous free block, it is asynchronous because it might need to wait for pending read to complete
     * if same block is being read and not completed yet;
     *
     * @param bid : the block id to free
     * @param cb : the callback that will be triggered after free block completes;
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
     * @brief : start data service;
     */
    void start();

private:
    BlkAllocStatus alloc_blks(uint32_t size, blk_alloc_hints const& hints, MultiBlkId& out_blkids);

    void init();

    static void process_data_completion(std::error_condition ec, void* cookie);

private:
    std::shared_ptr< VirtualDev > m_vdev;
    std::unique_ptr< BlkReadTracker > m_blk_read_tracker;
    uint32_t m_blk_size;
};

extern BlkDataService& data_service();
} // namespace homestore
