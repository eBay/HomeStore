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
#include <homestore/checkpoint/cp.hpp>
#include <homestore/meta_service.hpp>

#include "append_blk_allocator.h"

namespace homestore {

AppendBlkAllocator::AppendBlkAllocator(const BlkAllocConfig& cfg, bool need_format, allocator_id_t id) :
        BlkAllocator{cfg, id}, m_metrics{get_name().c_str()} {
    // TODO: try to make all append_blk_allocator instances use same client type to reduce metablk's cache footprint;
    meta_service().register_handler(
        get_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t size) { on_meta_blk_found(std::move(buf), (void*)mblk); },
        nullptr);

    if (need_format) {
        m_freeable_nblks = 0;
        m_last_append_offset = 0;
    }

    // for both fresh start and recovery, firstly init m_sb fields;
    m_sb.create(sizeof(append_blk_sb_t));
    m_sb.set_name(get_name());
    m_sb->allocator_id = id;
    m_sb->last_append_offset = m_last_append_offset;
    m_sb->freeable_nblks = m_freeable_nblks;

    // for recovery boot, fields will also be recovered from metablks;
}

void AppendBlkAllocator::on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie) {
    m_sb.load(buf, meta_cookie);

    HS_REL_ASSERT_EQ(m_sb->magic, append_blkalloc_sb_magic, "Invalid AppendBlkAlloc metablk, magic mismatch");
    HS_REL_ASSERT_EQ(m_sb->version, append_blkalloc_sb_version, "Invalid version of AppendBlkAllocator metablk");

    // recover in-memory counter/offset from metablk;
    m_last_append_offset.store(m_sb->last_append_offset);
    m_freeable_nblks.store(m_sb->freeable_nblks);
}

//
// Every time buffer is being dirtied, it needs to be within CPGuard().
// It garunteens either this dirty buffer is flushed in current cp or next cp as a whole;
//
// alloc a single block;
//
BlkAllocStatus AppendBlkAllocator::alloc_contiguous(BlkId& bid) { return alloc(1, blk_alloc_hints{}, bid); }

//
// For append blk allocator, the assumption is only one writer will append data on one chunk.
// If we want to change above design, we can open this api for vector allocation;
//
BlkAllocStatus AppendBlkAllocator::alloc(blk_count_t nblks, const blk_alloc_hints& hint, BlkId& out_bid) {
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
    out_bid = BlkId{m_last_append_offset.fetch_add(nblks), nblks, m_chunk_id};

    COUNTER_INCREMENT(m_metrics, num_alloc, 1);

    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus AppendBlkAllocator::alloc_on_disk(BlkId const&) {
    m_is_dirty.store(true);
    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus AppendBlkAllocator::alloc_on_cache(BlkId const& blkid) {
    auto new_offset = blkid.blk_num() + blkid.blk_count();
    auto cur_offset = m_last_append_offset.load();
    do {
        if (cur_offset >= new_offset) { break; } // Already allocated
    } while (!m_last_append_offset.compare_exchange_weak(cur_offset, new_offset));
    return BlkAllocStatus::SUCCESS;
}

void AppendBlkAllocator::cp_flush(CP* cp) {
    // check if current cp's context has dirty buffer already
    if (m_is_dirty.exchange(false)) {
        m_sb->last_append_offset = m_last_append_offset.load();
        m_sb->freeable_nblks = m_freeable_nblks.load();

        // write to metablk;
        m_sb.write();
    }
}

//
// free operation does:
// 1. book keeping "total freeable" space
// 2. if the blk being freed happens to be last block, move last_append_offset backwards accordingly;
//
void AppendBlkAllocator::free(const BlkId& bid) {
    auto const nblks = bid.blk_count();
    auto exp_last_offset = bid.blk_num() + nblks;
    auto const new_offset = m_last_append_offset - nblks;
    if (m_last_append_offset.compare_exchange_strong(exp_last_offset, new_offset)) { return; }

    // Freeing something in the middle, increment the count
    m_freeable_nblks.fetch_add(nblks);
}

void AppendBlkAllocator::free_on_disk(BlkId const&) { m_is_dirty.store(true); }

bool AppendBlkAllocator::is_blk_alloced(const BlkId& in_bid, bool) const {
    // blk_num starts from 0;
    return in_bid.blk_num() < m_last_append_offset;
}

bool AppendBlkAllocator::is_blk_alloced_on_disk(BlkId const& bid, bool) const {
    return bid.blk_num() < m_sb->last_append_offset;
}

std::string AppendBlkAllocator::get_name() const { return "AppendBlkAlloc_chunk_" + std::to_string(m_chunk_id); }

std::string AppendBlkAllocator::to_string() const {
    return fmt::format("{}, last_append_offset: {}", get_name(), m_last_append_offset.load(std::memory_order_relaxed));
}

blk_num_t AppendBlkAllocator::available_blks() const { return get_total_blks() - get_used_blks(); }

blk_num_t AppendBlkAllocator::get_used_blks() const { return m_last_append_offset; }

blk_num_t AppendBlkAllocator::get_freeable_nblks() const { return m_freeable_nblks; }

blk_num_t AppendBlkAllocator::get_defrag_nblks() const { return get_freeable_nblks() + available_blks(); }

nlohmann::json AppendBlkAllocator::get_status(int log_level) const {
    nlohmann::json j;
    j["total_blks"] = get_total_blks();
    j["next_append_blk_num"] = m_last_append_offset.load();
    j["freeable_nblks"] = m_freeable_nblks.load();
    return j;
}
} // namespace homestore
