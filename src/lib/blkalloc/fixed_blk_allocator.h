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

#include "bitmap_blk_allocator.h"

namespace homestore {
/* FixedBlkAllocator is a fast allocator where it allocates only 1 size block and ALL free blocks are cached instead
 * of selectively caching few blks which are free. Thus there is no sweeping of bitmap or other to refill the cache.
 * It does not support temperature of blocks and allocates simply on first come first serve basis
 */
class FixedBlkAllocator : public BitmapBlkAllocator {
public:
    FixedBlkAllocator(BlkAllocConfig const& cfg, bool is_fresh, chunk_num_t chunk_id);
    FixedBlkAllocator(FixedBlkAllocator const&) = delete;
    FixedBlkAllocator(FixedBlkAllocator&&) noexcept = delete;
    FixedBlkAllocator& operator=(FixedBlkAllocator const&) = delete;
    FixedBlkAllocator& operator=(FixedBlkAllocator&&) noexcept = delete;
    virtual ~FixedBlkAllocator() = default;

    void load() override;

    BlkAllocStatus alloc_contiguous(BlkId& bid) override;
    BlkAllocStatus alloc(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) override;
    BlkAllocStatus reserve_on_cache(BlkId const& b) override;
    void free(BlkId const& b) override;

    blk_num_t available_blks() const override;
    blk_num_t get_used_blks() const override;
    blk_num_t get_defrag_nblks() const override;
    bool is_blk_alloced(BlkId const& in_bid, bool use_lock = false) const override;
    std::string to_string() const override;

private:
    blk_num_t init_portion(BlkAllocPortion& portion, blk_num_t start_blk_num);

private:
    enum class state_t : uint8_t { RECOVERING, ACTIVE };

    state_t m_state{state_t::RECOVERING};
    std::unordered_set< blk_num_t > m_marked_blks; // Keep track of all blks which are marked as allocated
    std::mutex m_mark_blk_mtx;                     // Mutex used while removing marked_blks from blk_q
    folly::MPMCQueue< blk_num_t > m_free_blk_q;
};
} // namespace homestore
