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
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/meta_service.hpp>

#include "append_blk_allocator.h"
#include "checkpoint/cp.hpp"

namespace homestore {

AppendBlkAllocator::AppendBlkAllocator(const BlkAllocConfig& cfg, bool need_format, chunk_num_t id) :
        BlkAllocator{cfg, id}, m_metrics{get_name().c_str()} {
    // TODO: try to make all append_blk_allocator instances use same client type to reduce metablk's cache footprint;
    meta_service().register_handler(
        get_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) { on_meta_blk_found(std::move(buf), (void*)mblk); },
        nullptr);

    if (need_format) {
        m_freeable_nblks = available_blks();
        m_last_append_offset = 0;

        for (uint8_t i = 0; i < m_sb.size(); ++i) {
            m_sb[i].set_name(get_name());
            m_sb[i].create(sizeof(append_blkalloc_ctx));
            m_sb[i]->is_dirty = false;
            m_sb[i]->allocator_id = id;
            m_sb[i]->last_append_offset = 0;
            m_sb[i]->freeable_nblks = m_freeable_nblks;
        }
    }

    // for recovery boot, fields should be recovered from metablks;
}

void AppendBlkAllocator::on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    // TODO: also needs to initialize base class blkallocator for recovery path;
    // load all dirty buffer from the same starting point;
    m_sb[0].load(buf, meta_cookie);
    for (uint8_t i = 1; i < m_sb.size(); ++i) {
        m_sb[i].load(buf, meta_cookie);
    }

    m_last_append_offset = m_sb[0]->last_append_offset;
    m_freeable_nblks = m_sb[0]->freeable_nblks;

    HS_REL_ASSERT_EQ(m_sb[0]->magic, append_blkalloc_sb_magic, "Invalid AppendBlkAlloc metablk, magic mismatch");
    HS_REL_ASSERT_EQ(m_sb[0]->version, append_blkalloc_sb_version, "Invalid version of AppendBlkAllocator metablk");
}

//
// Every time buffer is being dirtied, it needs to be within CPGuard().
// It garunteens either this dirty buffer is flushed in current cp or next cp as a whole;
//
// alloc a single block;
//
BlkAllocStatus AppendBlkAllocator::alloc_contiguous(BlkId& bid) {
    std::unique_lock lk(m_mtx);
    if (available_blks() < 1) {
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        LOGERROR("No space left to serve request nblks: 1, available_blks: {}", available_blks());
        return BlkAllocStatus::SPACE_FULL;
    }

    bid = BlkId{m_last_append_offset, 1, m_chunk_id};

    auto cur_cp = hs()->cp_mgr().cp_guard();
    ++m_last_append_offset;
    --m_freeable_nblks;
    set_dirty_offset(cur_cp->id() % MAX_CP_COUNT);

    COUNTER_INCREMENT(m_metrics, num_alloc, 1);
    return BlkAllocStatus::SUCCESS;
}

//
// For append blk allocator, the assumption is only one writer will append data on one chunk.
// If we want to change above design, we can open this api for vector allocation;
//
BlkAllocStatus AppendBlkAllocator::alloc(blk_count_t nblks, const blk_alloc_hints& hint, BlkId& out_bid) {
    std::unique_lock lk(m_mtx);
    if (available_blks() < nblks) {
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        LOGERROR("No space left to serve request nblks: {}, available_blks: {}", nblks, available_blks());
        return BlkAllocStatus::SPACE_FULL;
    } else if (nblks > max_blks_per_blkid()) {
        // consumer(vdev) already handles this case.
        COUNTER_INCREMENT(m_metrics, num_alloc_failure, 1);
        LOGERROR("Can't serve request nblks: {} larger than max_blks_in_op: {}", nblks, max_blks_per_blkid());
        return BlkAllocStatus::FAILED;
    }

    // Push 1 blk to the vector which has all the requested nblks;
    out_bid = BlkId{m_last_append_offset, nblks, m_chunk_id};

    auto cur_cp = hs()->cp_mgr().cp_guard();
    m_last_append_offset += nblks;
    m_freeable_nblks -= nblks;

    // it is guaranteed that dirty buffer always contains updates of current_cp or next_cp, it will
    // never get dirty buffer from across updates;
    set_dirty_offset(cur_cp->id() % MAX_CP_COUNT);

    COUNTER_INCREMENT(m_metrics, num_alloc, 1);

    return BlkAllocStatus::SUCCESS;
}

//
// cp_flush doesn't need CPGuard as it is triggered by CPMgr which already handles the reference check;
//
// cp_flush should not block alloc/free;
//
void AppendBlkAllocator::cp_flush(CP* cp) {
    const auto idx = cp->id();
    // check if current cp's context has dirty buffer already
    if (m_sb[idx]->is_dirty) {
        // write to metablk;
        m_sb[cp->id()].write();

        // clear this dirty buff's dirty flag;
        clear_dirty_offset(idx);
    }
}

// updating current cp's dirty buffer context;
void AppendBlkAllocator::set_dirty_offset(const uint8_t idx) {
    m_sb[idx]->is_dirty = true;

    m_sb[idx]->last_append_offset = m_last_append_offset;
    m_sb[idx]->freeable_nblks = m_freeable_nblks;
}

// clearing current cp context's dirty flag;
void AppendBlkAllocator::clear_dirty_offset(const uint8_t idx) { m_sb[idx]->is_dirty = false; }

//
// free operation does:
// 1. book keeping "total freeable" space
// 2. if the blk being freed happens to be last block, move last_append_offset backwards accordingly;
//
void AppendBlkAllocator::free(const BlkId& bid) {
    std::unique_lock lk(m_mtx);
    auto cur_cp = hs()->cp_mgr().cp_guard();
    const auto n = bid.blk_count();
    m_freeable_nblks += n;
    if (bid.blk_num() + n == m_last_append_offset) {
        // we are freeing the the last blk id, let's rewind.
        m_last_append_offset -= n;
    }
    set_dirty_offset(cur_cp->id() % MAX_CP_COUNT);
}

blk_num_t AppendBlkAllocator::available_blks() const { return get_total_blks() - get_used_blks(); }

blk_num_t AppendBlkAllocator::get_used_blks() const { return m_last_append_offset; }

bool AppendBlkAllocator::is_blk_alloced(const BlkId& in_bid, bool) const {
    // blk_num starts from 0;
    return in_bid.blk_num() < get_used_blks();
}

std::string AppendBlkAllocator::get_name() const { return "AppendBlkAlloc_chunk_" + std::to_string(m_chunk_id); }

std::string AppendBlkAllocator::to_string() const {
    return fmt::format("{}, last_append_offset: {}", get_name(), m_last_append_offset);
}

blk_num_t AppendBlkAllocator::get_freeable_nblks() const { return m_freeable_nblks; }

} // namespace homestore
