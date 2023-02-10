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
    io_completion_cb_t cb;
    bool is_read{false};
    BlkId bid; // only needed when is_read is true, used for blk read tracker;
    sisl::atomic_counter< int > outstanding_io_cnt = 0;
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
     * @param vb
     */
    void open_vdev(vdev_info_block* vb);

    /**
     * @brief : called in non-recovery mode to create a new vdev for data service
     *
     * @param size
     */
    void create_vdev(uint64_t size);

    /**
     * @brief
     *
     * @param sgs
     * @param hints
     * @param out_blkids
     * @param cb
     * @param part_of_batch
     */
    void async_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids,
                     const io_completion_cb_t& cb, bool part_of_batch = false);

    /**
     * @brief
     *
     * @param sgs
     * @param hints
     * @param in_blkids
     * @param cb
     * @param part_of_batch
     */
    void async_write_ahead(const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                           const std::vector< BlkId >& in_blkids, const io_completion_cb_t& cb,
                           bool part_of_batch = false);

    /**
     * @brief
     *
     * @param bid
     * @param sgs
     * @param size
     * @param cb
     * @param part_of_batch
     */
    void async_read(const BlkId& bid, sisl::sg_list& sgs, uint32_t size, const io_completion_cb_t& cb,
                    bool part_of_batch = false);

    /**
     * @brief
     *
     * @param bid
     */
    void commit_blk(const BlkId& bid);

    /**
     * @brief
     *
     * @param size
     *
     * @return
     */
    blk_list_t alloc_blks(uint32_t size);

    /**
     * @brief
     *
     * @param bid
     * @param cb
     */
    void async_free_blk(const BlkId bid, const io_completion_cb_t& cb);

    /**
     * @brief
     *
     * @return
     */
    uint32_t get_page_size() const { return m_page_size; }

    BlkReadTracker* read_blk_tracker() { return m_blk_read_tracker.get(); }

    /************************ hdd stream apis *************************/
    /**
     * @brief : allocate a stream for client in non-recovery mode;
     *
     * @param size
     *
     * @return
     */
    stream_info_t alloc_stream(const uint64_t size);

    /**
     * @brief : reserve a stream for consumer during recovery
     *
     * @param id_list
     * @param num_streams
     *
     * @return
     */
    stream_info_t reserve_stream(const stream_id_t* id_list, const uint32_t num_streams);

    /**
     * @brief
     *
     * @param stream_info
     */
    void free_stream(const stream_info_t& stream_info);

private:
    BlkAllocStatus alloc_blks(uint32_t size, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkids);

    /**
     * @brief : common initialize for BlkDataService
     */
    void init();

private:
    static void process_data_completion(std::error_condition ec, void* cookie);

private:
    std::unique_ptr< VirtualDev > m_vdev;
    std::unique_ptr< BlkReadTracker > m_blk_read_tracker;
    uint32_t m_page_size;
};

extern BlkDataService& data_service();
} // namespace homestore
