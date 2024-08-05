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
#include <cassert>
#include <iomgr/iomgr_flip.hpp>

#include "common/homestore_assert.hpp"
#include "fixed_blk_allocator.h"

namespace homestore {
FixedBlkAllocator::FixedBlkAllocator(BlkAllocConfig const& cfg, bool is_fresh, chunk_num_t chunk_id) :
        BitmapBlkAllocator(cfg, is_fresh, chunk_id), m_free_blk_q{get_total_blks()} {
    LOGINFO("FixedBlkAllocator total blks: {}", get_total_blks());
    if (is_fresh || !is_persistent()) { load(); }
}

void FixedBlkAllocator::load() {
    blk_num_t blk_num{0};
    while (blk_num < get_total_blks()) {
        blk_num = init_portion(blknum_to_portion(blk_num), blk_num);
    }
}

blk_num_t FixedBlkAllocator::init_portion(BlkAllocPortion& portion, blk_num_t start_blk_num) {
    auto lock{portion.portion_auto_lock()};

    auto blk_num = start_blk_num;
    while (blk_num < get_total_blks()) {
        BlkAllocPortion& cur_portion = blknum_to_portion(blk_num);
        if (portion.get_portion_num() != cur_portion.get_portion_num()) break;

        if (!is_persistent() || get_disk_bitmap()->is_bits_reset(blk_num, 1)) {
            const auto pushed = m_free_blk_q.write(blk_num);
            HS_DBG_ASSERT_EQ(pushed, true, "Expected to be able to push the blk on fixed capacity Q");
        }
        ++blk_num;
    }

    return blk_num;
}

bool FixedBlkAllocator::is_blk_alloced(BlkId const& b, bool use_lock) const { return true; }

BlkAllocStatus FixedBlkAllocator::alloc([[maybe_unused]] blk_count_t nblks, blk_alloc_hints const&, BlkId& out_blkid) {
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("fixed_blkalloc_no_blks")) { return BlkAllocStatus::SPACE_FULL; }
#endif
retry:
    blk_num_t blk_num;
    if (!m_free_blk_q.read(blk_num)) { return BlkAllocStatus::SPACE_FULL; }

    if (m_state != state_t::ACTIVE) {
        // We are not in active state, means we must be recovering. During recovery state, if any of the blks which are
        // committed, we shouldn't be allocating those blocks. So remove from free blk q and retry another blk
        std::lock_guard lg(m_reserve_blk_mtx);
        if ((m_state == state_t::RECOVERING) && (m_reserved_blks.find(blk_num) != m_reserved_blks.end())) {
            m_reserved_blks.erase(blk_num); // This blk can be removed from reserved, because its no longer free (since
                                            // we also removed from free_blk q)
            goto retry;
        }
    }
    out_blkid = BlkId{blk_num, 1, m_chunk_id};
    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus FixedBlkAllocator::alloc_contiguous(BlkId& out_blkid) { return alloc(1, {}, out_blkid); }

BlkAllocStatus FixedBlkAllocator::reserve_on_cache(BlkId const& b) {
    std::lock_guard lg(m_reserve_blk_mtx);
    if (m_state == state_t::RECOVERING) { m_reserved_blks.insert(b.blk_num()); }
    return BlkAllocStatus::SUCCESS;
}

void FixedBlkAllocator::recovery_completed() {
    std::lock_guard lg(m_reserve_blk_mtx);
    if (!m_reserved_blks.empty()) {
        auto const count = available_blks();
        for (uint64_t i{0}; ((i < count) && !m_reserved_blks.empty()); ++i) {
            blk_num_t blk_num;
            if (!m_free_blk_q.read(blk_num)) { break; }

            if (m_reserved_blks.find(blk_num) == m_reserved_blks.end()) {
                m_free_blk_q.write(blk_num); // This blk is not marked, put it back at the end of queue
            }
        }
        // We no longer need any reserved blks, since all of them are now marked as allocated
        m_reserved_blks.clear();
    }
    m_state = state_t::ACTIVE;
}

void FixedBlkAllocator::free(BlkId const& b) {
    HS_DBG_ASSERT_EQ(b.blk_count(), 1, "Multiple blk free for FixedBlkAllocator? allocated by different allocator?");

    const auto pushed = m_free_blk_q.write(b.blk_num());
    HS_DBG_ASSERT_EQ(pushed, true, "Expected to be able to push the blk on fixed capacity Q");

    if (m_state != state_t::ACTIVE) {
        std::lock_guard lg(m_reserve_blk_mtx);
        if (m_state == state_t::RECOVERING) {
            // If we are in recovering state and freeing blk would removed it from being reserved as well.
            m_reserved_blks.erase(b.blk_num());
        }
    }
    if (is_persistent()) { free_on_disk(b); }
}

blk_num_t FixedBlkAllocator::available_blks() const { return m_free_blk_q.sizeGuess(); }

blk_num_t FixedBlkAllocator::get_defrag_nblks() const {
    // TODO: implement this
    HS_DBG_ASSERT_EQ(false, true, "FixedBlkAllocator get_defrag_nblks Not implemented");
    return 0;
}

blk_num_t FixedBlkAllocator::get_used_blks() const { return get_total_blks() - available_blks(); }

std::string FixedBlkAllocator::to_string() const {
    return fmt::format("Total Blks={} Available_Blks={}", get_total_blks(), available_blks());
}
} // namespace homestore
