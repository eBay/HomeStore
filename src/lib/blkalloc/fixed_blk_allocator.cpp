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
#include "blk_allocator.h"

namespace homestore {
FixedBlkAllocator::FixedBlkAllocator(const BlkAllocConfig& cfg, bool init, chunk_num_t chunk_id) :
        BlkAllocator(cfg, chunk_id), m_blk_q{get_total_blks()} {
    LOGINFO("total blks: {}", get_total_blks());
    if (init) { inited(); }
}

void FixedBlkAllocator::inited() {
    blk_num_t blk_num{0};

    while (blk_num < get_total_blks()) {
        blk_num = init_portion(blknum_to_portion(blk_num), blk_num);
    }
    BlkAllocator::inited();
}

blk_num_t FixedBlkAllocator::init_portion(BlkAllocPortion& portion, blk_num_t start_blk_num) {
    auto lock{portion.portion_auto_lock()};

    auto blk_num = start_blk_num;
    while (blk_num < get_total_blks()) {
        BlkAllocPortion& cur_portion = blknum_to_portion(blk_num);
        if (portion.get_portion_num() != cur_portion.get_portion_num()) break;

        if (!get_disk_bm_const()->is_bits_set(blk_num, 1)) {
            const auto pushed = m_blk_q.write(BlkId{blk_num, 1, m_chunk_id});
            HS_DBG_ASSERT_EQ(pushed, true, "Expected to be able to push the blk on fixed capacity Q");
        }
        ++blk_num;
    }

    return blk_num;
}

bool FixedBlkAllocator::is_blk_alloced(const BlkId& b, bool use_lock) const { return true; }

BlkAllocStatus FixedBlkAllocator::alloc(blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid) {
    /* TODO:If it is more then 1 then we need to make sure that we never allocate across the portions. As of now
     * we don't support the vector of blkids in fixed blk allocator */
    HS_DBG_ASSERT_EQ(nblks, 1, "FixedBlkAllocator does not support multiple blk allocation yet");

    BlkId bid;
    const auto status = alloc(bid);
    if (status == BlkAllocStatus::SUCCESS) {
        out_blkid.push_back(bid);
        // no need to update real time bm as it is already updated in alloc of single blkid api;
    }
    return status;
}

BlkAllocStatus FixedBlkAllocator::alloc(BlkId& out_blkid) {
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("fixed_blkalloc_no_blks")) { return BlkAllocStatus::SPACE_FULL; }
#endif
    const auto ret = m_blk_q.read(out_blkid);
    if (ret) {
        // update real time bitmap;
        alloc_on_realtime(out_blkid);
        return BlkAllocStatus::SUCCESS;
    } else {
        return BlkAllocStatus::SPACE_FULL;
    }
}

void FixedBlkAllocator::free(const std::vector< BlkId >& blk_ids) {
    for (const auto& blk_id : blk_ids) {
        free(blk_id);
    }
}

void FixedBlkAllocator::free(const BlkId& b) {
    HS_DBG_ASSERT_EQ(b.get_nblks(), 1, "Multiple blk free for FixedBlkAllocator? allocated by different allocator?");

    // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache bm.
    if (m_inited) {
        const auto pushed = m_blk_q.write(b);
        HS_DBG_ASSERT_EQ(pushed, true, "Expected to be able to push the blk on fixed capacity Q");
    }
}

blk_cap_t FixedBlkAllocator::available_blks() const { return m_blk_q.sizeGuess(); }
blk_cap_t FixedBlkAllocator::get_used_blks() const { return get_total_blks() - available_blks(); }

std::string FixedBlkAllocator::to_string() const {
    return fmt::format("Total Blks={} Available_Blks={}", get_total_blks(), available_blks());
}
} // namespace homestore
