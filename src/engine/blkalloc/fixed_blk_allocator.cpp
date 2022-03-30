/*
 * fixed_blk_allocator.cpp
 *
 *  Created on: Aug 09, 2016
 *      Author: hkadayam
 */
#include <cassert>

#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_flip.hpp"

#include "blk_allocator.h"

namespace homestore {
FixedBlkAllocator::FixedBlkAllocator(const BlkAllocConfig& cfg, const bool init, const chunk_num_t chunk_id) :
        BlkAllocator(cfg, chunk_id),
        m_blk_q{cfg.get_total_blks()} {
    LOGINFO("total blks: {}", cfg.get_total_blks());
    if (init) { inited(); }
}

void FixedBlkAllocator::inited() {
    blk_num_t blk_num{0};

    while (blk_num < m_cfg.get_total_blks()) {
        blk_num = init_portion(blknum_to_portion(blk_num), blk_num);
    }
    BlkAllocator::inited();
}

blk_num_t FixedBlkAllocator::init_portion(BlkAllocPortion* const portion, const blk_num_t start_blk_num) {
    auto lock{portion->portion_auto_lock()};

    auto blk_num{start_blk_num};
    while (blk_num < m_cfg.get_total_blks()) {
        BlkAllocPortion* const cur_portion{blknum_to_portion(blk_num)};
        if (portion != cur_portion) break;

        if (!get_disk_bm()->is_bits_set(blk_num, 1)) {
            const auto pushed = m_blk_q.write(BlkId{blk_num, 1, m_chunk_id});
            HS_DBG_ASSERT_EQ(pushed, true, "Expected to be able to push the blk on fixed capacity Q");
        }
        ++blk_num;
    }

    return blk_num;
}

bool FixedBlkAllocator::is_blk_alloced(const BlkId& b, const bool use_lock) const { return true; }

BlkAllocStatus FixedBlkAllocator::alloc(const blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid) {
    /* TODO:If it is more then 1 then we need to make sure that we never allocate across the portions. As of now
     * we don't support the vector of blkids in fixed blk allocator */
    HS_DBG_ASSERT_EQ(nblks, 1, "FixedBlkAllocator does not support multiple blk allocation yet");

    BlkId bid;
    const auto status{alloc(bid)};
    if (status == BlkAllocStatus::SUCCESS) {
        out_blkid.push_back(bid);
        // no need to update real time bm as it is already updated in alloc of single blkid api;
    }
    return status;
}

BlkAllocStatus FixedBlkAllocator::alloc(BlkId& out_blkid) {
#ifdef _PRERELEASE
    if (homestore_flip->test_flip("fixed_blkalloc_no_blks")) { return BlkAllocStatus::SPACE_FULL; }
#endif
    const auto ret{m_blk_q.read(out_blkid)};
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

blk_cap_t FixedBlkAllocator::get_available_blks() const { return m_blk_q.sizeGuess(); }
blk_cap_t FixedBlkAllocator::get_used_blks() const { return get_config().get_total_blks() - get_available_blks(); }

std::string FixedBlkAllocator::to_string() const {
    return fmt::format("Total Blks={} Available_Blks={}", m_cfg.get_total_blks(), get_available_blks());
}
} // namespace homestore
