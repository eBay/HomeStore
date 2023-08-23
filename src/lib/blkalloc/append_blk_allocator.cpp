/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 * *
 * *********************************************************************************/

#include "append_blk_allocator.h"

ISL_LOGGING_DECL(blkalloc)

namespace homestore {

AppendBlkAllocator::AppendBlkAllocator(const AppendBlkAllocConfig& cfg, bool init, chunk_num_t id) :
        BlkAllocator{cfg, id}, m_metrics{get_name().c_str()} {
    if (init) { BlkAllocator::inited(); }
}

BlkAllocStatus AppendBlkAllocator::alloc(BlkId& bid) {
    BLKALLOC_REL_ASSERT(last_append_offset % get_blk_size() == 0);

    const auto blk_num = last_append_offset / get_blk_size();
    // assumption is caller can use all of the remaining space in this chunk;
    bid.set(blk_num, get_total_blks() - blk_num, m_chunk_id);

    return BlkAllocStatus::SUCCESS;
}

//
// For append blk allocator, the assumption is only one writer will append data on one chunk.
// If we want to change above design, we can open this api for vector allocation;
//
BlkAllocStatus AppendBlkAllocator::alloc(blk_count_t, const blk_alloc_hints&, std::vector< BlkId >&) {
    BLKALLOC_REL_ASSERT(false, "not supported for append_blk_allocator for milestone2.");
    return BlkAllocStatus::SUCCESS;
}

void AppendBlkAllocator::free(BlkId& bid) {
    // free is a no-op;
    return;
}

void AppendBlkAllocator::free(const std::vector< BlkId >& blk_ids) {
    BLKALLOC_REL_ASSERT(false, "not supported for append_blk_allocator for milestone2.");
    return BlkAllocStatus::SUCCESS;
}

blk_cap_t AppendBlkAllocator::available_blks() const { return get_total_blks() - get_used_blks(); }

blk_cap_t AppendBlkAllocator::get_used_blks() const { return last_append_offset / get_blk_size(); }

bool AppendBlkAllocator::is_blk_alloced(const BlkId& in_bid, bool use_lock) const {
    // blk_num starts from 0;
    return in_bid.get_blk_num() < get_used_blks();
}

std::string AppendBlkAllocator::to_string() const {
    return fmt::format("{}, last_append_offset: {}", to_string(), last_append_offset);
}

} // namespace homestore
