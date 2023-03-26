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
struct vdev_info_block;
struct stream_info_t;
class BlkReadTracker;
struct blk_alloc_hints;

struct async_info {
    io_completion_cb_t cb{nullptr};
    bool is_read{false};
    BlkId bid; // only needed when is_read is true, used for blk read tracker;
    sisl::atomic_counter< int > outstanding_io_cnt{0};
    folly::Promise< std::error_condition > promise{folly::Promise< std::error_condition >::makeEmpty()};
};

using blk_t = uint64_t;
using blk_list_t = folly::small_vector< blk_t, 4 >;

class BlkDataService {
public:
    BlkDataService();
    ~BlkDataService();

    /**
     * @brief : called during recovery to open existing vdev for data service
     *
     * @param vb : vdev info blk containing the details of this blkstore
     */
    void open_vdev(vdev_info_block* vb);

    /**
     * @brief : called in non-recovery mode to create a new vdev for data service
     *
     * @param size : size of this vdev
     */
    void create_vdev(uint64_t size);

    /**
     * @brief : asynchronous write without input block ids. Block ids will be allocated by this api and returned;
     *
     * @param sgs : the data buffer that needs to be written
     * @param hints : blk alloc hints
     * @param out_blkids : the output block ids that were allocated and written to
     * @param cb : callback that will be triggered after write completes;
     * @param part_of_batch : is this write part of a batch;
     */
    void async_alloc_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids,
                           const io_completion_cb_t& cb, bool part_of_batch = false);

    folly::Future< std::error_condition > alloc_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                                                      std::vector< BlkId >& out_blkids, bool part_of_batch = false);

    /**
     * @brief : asynchronous write with input block ids;
     *
     * @param sgs : the data buffer that needs to be written
     * @param hints : blk alloc hints
     * @param in_blkids : input block ids that this write should be written to;
     * @param cb : callback that will be triggered after write completes
     * @param part_of_batch : is this write part of a batch;
     */
    void async_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints, const std::vector< BlkId >& in_blkids,
                     const io_completion_cb_t& cb, bool part_of_batch = false);

    folly::Future< bool > async_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                                      const std::vector< BlkId >& in_blkids, bool part_of_batch = false);

    /**
     * @brief : asynchronous read
     *
     * @param bid : block id to read
     * @param sgs : the read buffer stored
     * @param size : size to read
     * @param cb : callback that will be triggered after read completes
     * @param part_of_batch : is this read part of batch;
     */
    void async_read(const BlkId& bid, sisl::sg_list& sgs, uint32_t size, const io_completion_cb_t& cb,
                    bool part_of_batch = false);

    folly::Future< bool > async_read(const BlkId& bid, sisl::sg_list& sgs, uint32_t size, bool part_of_batch = false);

    /**
     * @brief : commit a block, usually called during recovery
     *
     * @param bid : block id to commit;
     */
    void commit_blk(const BlkId& bid);

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
    void async_free_blk(const BlkId bid, const io_completion_cb_t& cb);

    folly::Future< bool > async_free_blk(const BlkId bid);

    /**
     * @brief : get the page size of this data service;
     *
     * @return : page size
     */
    uint32_t get_page_size() const { return m_page_size; }

    /**
     * @brief : get the read block tracker handle;
     *
     * @return : the read block tracker pointer;
     */
    BlkReadTracker* read_blk_tracker() { return m_blk_read_tracker.get(); }

    /************************ hdd stream apis *************************/
    /**
     * @brief : allocate a stream for client in non-recovery mode;
     *
     * @param size : size of stream to allocate
     *
     * @return : stream handle;
     */
    stream_info_t alloc_stream(const uint64_t size);

    /**
     * @brief : reserve a stream for consumer during recovery
     *
     * @param id_list : the id of streams to reserve
     * @param num_streams : number of streams
     *
     * @return : stream handle;
     */
    stream_info_t reserve_stream(const stream_id_t* id_list, const uint32_t num_streams);

    /**
     * @brief : free a stream;
     *
     * @param stream_info : stream handle
     */
    void free_stream(const stream_info_t& stream_info);

private:
    BlkAllocStatus alloc_blks(uint32_t size, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids);

    void queue_write(async_info* as_info, const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                     const std::vector< BlkId >& in_blkids, bool part_of_batch);
    void queue_read(async_info* as_info, const BlkId& bid, sisl::sg_list& sgs, uint32_t size, bool part_of_batch);
    void init();

    static void process_data_completion(std::error_condition ec, void* cookie);

private:
    std::unique_ptr< VirtualDev > m_vdev;
    std::unique_ptr< BlkReadTracker > m_blk_read_tracker;
    uint32_t m_page_size;
};

extern BlkDataService& data_service();
} // namespace homestore
