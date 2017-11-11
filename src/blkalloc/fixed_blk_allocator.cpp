/*
 * fixed_blk_allocator.cpp
 *
 *  Created on: Aug 09, 2016
 *      Author: hkadayam
 */
#include "blk_allocator.h"
#include <cassert>

using namespace std;

namespace omstore {

FixedBlkAllocator::FixedBlkAllocator(BlkAllocConfig &cfg) :
        BlkAllocator(cfg) {
    m_blk_nodes = new __fixed_blk_node[cfg.get_total_blks()];
    uint32_t last_blk_id = BLKID32_INVALID;

    for (auto i = (uint32_t)cfg.get_total_blks(); i > 0; i--) {
#ifndef NDEBUG
        m_blk_nodes[i-1].this_blk_id = i-1;
#endif
        m_blk_nodes[i - 1].next_blk = last_blk_id;
        last_blk_id = (uint32_t)i - 1;
    }

    __top_blk tp(0, last_blk_id);
    m_top_blk_id.store(tp.to_integer());
#ifndef NDEBUG
    m_nfree_blks.store(cfg.get_total_blks(), std::memory_order_relaxed);
#endif
}

FixedBlkAllocator::~FixedBlkAllocator() {
    delete (m_blk_nodes);
}

BlkAllocStatus FixedBlkAllocator::alloc(uint32_t size, blk_alloc_hints &hints, SingleBlk *out_blk) {
    uint64_t prev_val;
    uint64_t cur_val;
    uint32_t blk_id;

    do {
        prev_val = m_top_blk_id.load();
        __top_blk tp(prev_val);

        // Get the __top_blk blk and replace the __top_blk blk id with next id
        blk_id = tp.get_top_blk_id();
        if (blk_id == BLKID32_INVALID) {
            return BLK_ALLOC_SPACEFULL;
        }

        __fixed_blk_node blknode = m_blk_nodes[blk_id];

        tp.set_top_blk_id(blknode.next_blk);
        tp.set_gen(tp.get_gen() + 1);
        cur_val = tp.to_integer();

    } while (!(m_top_blk_id.compare_exchange_weak(prev_val, cur_val)));

    out_blk->set_id(blk_id);
    out_blk->set_size(m_cfg.get_blk_size());

#ifndef NDEBUG
    m_nfree_blks.fetch_sub(1, std::memory_order_relaxed);
#endif
    return BLK_ALLOC_SUCCESS;
}

void FixedBlkAllocator::free(SingleBlk &b) {
    free_blk((uint32_t)b.get_id());
#ifndef NDEBUG
    m_nfree_blks.fetch_add(1, std::memory_order_relaxed);
#endif
}

void FixedBlkAllocator::free_blk(uint32_t blk_id) {
    uint64_t prev_val;
    uint64_t cur_val;
    __fixed_blk_node *blknode = &m_blk_nodes[blk_id];

    do {
        prev_val = m_top_blk_id.load();
        __top_blk tp(prev_val);

        blknode->next_blk = tp.get_top_blk_id();;

        tp.set_gen(tp.get_gen() + 1);
        tp.set_top_blk_id(blk_id);
        cur_val = tp.to_integer();
    } while (!(m_top_blk_id.compare_exchange_weak(prev_val, cur_val)));
}

std::string FixedBlkAllocator::to_string() const {
    ostringstream oss;
#ifndef NDEBUG
    oss << "Total free blks = " << m_nfree_blks.load(std::memory_order_relaxed) << " ";
#endif
    oss << "m_top_blk_id=" << m_top_blk_id << "\n";
    return oss.str();
}
} // namespace omstore

