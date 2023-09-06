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
#include <homestore/meta_service.hpp>
#include "append_blk_allocator.h"

namespace homestore {

AppendBlkAllocator::AppendBlkAllocator(const BlkAllocConfig& cfg, bool need_format, chunk_num_t id) :
        BlkAllocator{cfg, id}, m_metrics{get_name().c_str()}, m_sb{get_name()} {
    // TODO: try to make all append_blk_allocator instances use same client type to reduce metablk's cache footprint;
    meta_service().register_handler(
        get_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) { on_meta_blk_found(std::move(buf), (void*)mblk); },
        nullptr);

    if (need_format) {
        m_freeable_nblks = available_blks();
        m_last_append_offset = 0;

        m_sb.create(sizeof(append_blkalloc_sb));
        m_sb->allocator_id = id;
        m_sb->last_append_offset = 0;
        m_sb->freeable_nblks = m_freeable_nblks;
    }

    // for recovery boot, fields should be recovered from metablks;
}

void AppendBlkAllocator::on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    // TODO: also needs to initialize base class blkallocator for recovery path;

    m_sb.load(buf, meta_cookie);
    m_last_append_offset = m_sb->last_append_offset;
    m_freeable_nblks = m_sb->freeable_nblks;

    HS_REL_ASSERT_EQ(m_sb->magic, append_blkalloc_sb_magic, "Invalid AppendBlkAlloc metablk, magic mismatch");
    HS_REL_ASSERT_EQ(m_sb->version, append_blkalloc_sb_version, "Invalid version of AppendBlkAllocator metablk");
}

// alloc a single block;
BlkAllocStatus AppendBlkAllocator::alloc(BlkId& bid) {
    if (available_blks() < 1) {
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        LOGERROR("No space left to serve request nblks: 1, available_blks: {}", available_blks());
        return BlkAllocStatus::SPACE_FULL;
    }

    bid.set(m_last_append_offset, 1, m_chunk_id);
    ++m_last_append_offset;
    --m_freeable_nblks;

    set_dirty_offset();

    COUNTER_INCREMENT(m_metrics, num_alloc, 1);
    return BlkAllocStatus::SUCCESS;
}

//
// For append blk allocator, the assumption is only one writer will append data on one chunk.
// If we want to change above design, we can open this api for vector allocation;
//
BlkAllocStatus AppendBlkAllocator::alloc(blk_count_t nblks, const blk_alloc_hints& hint,
                                         std::vector< BlkId >& out_bids) {
    if (available_blks() < nblks) {
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        LOGERROR("No space left to serve request nblks: {}, available_blks: {}", nblks, available_blks());
        return BlkAllocStatus::SPACE_FULL;
    } else if (nblks > BlkId::max_blks_in_op()) {
        // consumer(vdev) already handles this case.
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        LOGERROR("Can't serve request nblks: {} larger than max_blks_in_op: {}", nblks, BlkId::max_blks_in_op());
        return BlkAllocStatus::FAILED;
    }

    // Push 1 blk to the vector which has all the requested nblks;
    out_bids.emplace_back(m_last_append_offset, nblks, m_chunk_id);

    m_last_append_offset += nblks;
    m_freeable_nblks -= nblks;

    set_dirty_offset();

    COUNTER_INCREMENT(m_metrics, num_alloc, 1);

    return BlkAllocStatus::SUCCESS;
}

//
// Alternative design option:
// Option-1. Everytime offset is updated in a single append_blk_allocator instance, update the dirty buffer into
// VDevCPContext, which contains a list of (ThreadVector) dirty buffers from all the append_blk_allocator instances
// (protected by RCU);
//
// And cp_flush flush every dirty buffer in that list to disk;
//
// Option-2. vdev cp_flush will call each individual chunk's blkallocator and each append_blk_allocator instance flush
// its dirty buffer on demond;
//
// We are using option-2.
//

//
// cp_flush is happening in different thread that is running concurrently as AppendBlkAllocator::alloc;
//
// 1. if clear_dirty_offset happens before offset is updated by alloc, but before set_dirty_offset, we are flushing
// offset twice, which is fine.
// 2. If clear_dirty_offset happens after set_dirty_offset, we are flushing offset ahead of log
// store, which is also fine during recovery, it is consistent after log store flush completes;
// 3. Any alloc happened after metablk is persisted will come to next cp;
//
void AppendBlkAllocator::cp_flush() {
    if (m_is_dirty) {
        // clear must happen before write to metablk becuase if metablk is written first, if
        // alloc(in-parallel) happened after written but before clear, then the dirty buffer will be cleared.
        clear_dirty_offset();

        // write to metablk;
        m_sb->last_append_offset = m_last_append_offset;
        m_sb->freeable_nblks = m_freeable_nblks;
        m_sb.write();
    }
}

void AppendBlkAllocator::set_dirty_offset() { m_is_dirty = true; }

void AppendBlkAllocator::clear_dirty_offset() { m_is_dirty = false; }

//
// free operation does:
// 1. book keeping "total freeable" space
// 2. if the blk being freed happens to be last block, move last_append_offset backwards accordingly;
//
void AppendBlkAllocator::free(const BlkId& bid) {
    const auto n = bid.get_nblks();
    m_freeable_nblks += n;
    if (bid.get_blk_num() + n == m_last_append_offset) {
        // we are freeing the the last blk id, let's rewind.
        m_last_append_offset -= n;
    }
    set_dirty_offset();
}

void AppendBlkAllocator::free(const std::vector< BlkId >& blk_ids) {
    for (const auto b : blk_ids) {
        this->free(b);
    }
}

blk_cap_t AppendBlkAllocator::available_blks() const { return get_total_blks() - get_used_blks(); }

blk_cap_t AppendBlkAllocator::get_used_blks() const { return m_last_append_offset; }

bool AppendBlkAllocator::is_blk_alloced(const BlkId& in_bid, bool) const {
    // blk_num starts from 0;
    return in_bid.get_blk_num() < get_used_blks();
}

std::string AppendBlkAllocator::get_name() const { return "AppendBlkAlloc_chunk_" + std::to_string(m_chunk_id); }

std::string AppendBlkAllocator::to_string() const {
    auto str = fmt::format("{}, last_append_offset: {}", get_name(), m_last_append_offset.load());
    return str;
}

blk_cap_t AppendBlkAllocator::get_freeable_nblks() const { return m_freeable_nblks; }

} // namespace homestore
