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
#include <homestore/homestore.hpp>
#include <homestore/meta_service.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include "bitmap_blk_allocator.h"
#include "meta/meta_sb.hpp"
#include "common/homestore_utils.hpp"

namespace homestore {
BitmapBlkAllocator::BitmapBlkAllocator(BlkAllocConfig const& cfg, bool is_fresh, chunk_num_t id) :
        BlkAllocator(cfg, id), m_blks_per_portion{cfg.m_blks_per_portion} {
    if (is_persistent()) {
        meta_service().register_handler(
            get_name(),
            [this](meta_blk* mblk, sisl::byte_view buf, size_t size) {
                on_meta_blk_found(voidptr_cast(mblk), std::move(buf), size);
            },
            nullptr);
    }

    if (is_fresh) {
        if (is_persistent()) { m_disk_bm = std::make_unique< sisl::Bitset >(m_num_blks, m_chunk_id, m_align_size); }
    }

    // NOTE:  Blocks per portion must be modulo word size so locks do not fall on same word
    m_blks_per_portion = sisl::round_up(m_blks_per_portion, m_disk_bm ? m_disk_bm->word_size() : 64u);

    m_blk_portions = std::make_unique< BlkAllocPortion[] >(get_num_portions());
    for (blk_num_t index{0}; index < get_num_portions(); ++index) {
        m_blk_portions[index].set_portion_num(index);
    }
}

void BitmapBlkAllocator::on_meta_blk_found(void* mblk_cookie, sisl::byte_view const& buf, size_t size) {
    m_meta_blk_cookie = mblk_cookie;

    m_disk_bm = std::unique_ptr< sisl::Bitset >{new sisl::Bitset{
        hs_utils::extract_byte_array(buf, meta_service().is_aligned_buf_needed(size), meta_service().align_size())}};

    m_alloced_blk_count.store(m_disk_bm->get_set_count(), std::memory_order_relaxed);
    load();
}

void BitmapBlkAllocator::cp_flush(CP*) {
    if (!is_persistent()) { return; }

    if (m_is_disk_bm_dirty.load()) {
        sisl::byte_array bitmap_buf = acquire_underlying_buffer();
        if (m_meta_blk_cookie) {
            meta_service().update_sub_sb(bitmap_buf->bytes, bitmap_buf->size, m_meta_blk_cookie);
        } else {
            meta_service().add_sub_sb(get_name(), bitmap_buf->bytes, bitmap_buf->size, m_meta_blk_cookie);
        }
        m_is_disk_bm_dirty.store(false); // No longer dirty now, needs to be set before releasing the buffer
        release_underlying_buffer();
    }
}

bool BitmapBlkAllocator::is_blk_alloced_on_disk(const BlkId& b, bool use_lock) const {
    // for non-persistent bitmap nothing to compare. So always return true
    if (!is_persistent()) { return true; }

    if (use_lock) {
        const BlkAllocPortion& portion = blknum_to_portion_const(b.blk_num());
        auto lock{portion.portion_auto_lock()};
        return m_disk_bm->is_bits_set(b.blk_num(), b.blk_count());
    } else {
        return m_disk_bm->is_bits_set(b.blk_num(), b.blk_count());
    }
}

BlkAllocStatus BitmapBlkAllocator::alloc_on_disk(BlkId const& bid) {
    if (!is_persistent()) { return BlkAllocStatus::FAILED; }

    rcu_read_lock();
    auto list = get_alloc_blk_list();
    if (list) {
        // cp has started, accumulating to the list
        list->push_back(bid);
    } else {
        auto set_on_disk_bm = [this](auto& b) {
            BlkAllocPortion& portion = blknum_to_portion(b.blk_num());
            {
                auto lock{portion.portion_auto_lock()};
                if (!hs()->is_initializing()) {
                    // During recovery we might try to free the entry which is already freed while replaying the
                    // journal, This assert is valid only post recovery.
                    BLKALLOC_REL_ASSERT(m_disk_bm->is_bits_reset(b.blk_num(), b.blk_count()),
                                        "Expected disk blks to reset");
                }
                m_disk_bm->set_bits(b.blk_num(), b.blk_count());
                BLKALLOC_LOG(DEBUG, "blks allocated {} chunk number {}", b.to_string(), m_chunk_id);
            }
        };

        // cp is not started or already done, allocate on disk bm directly;
        if (bid.is_multi()) {
            MultiBlkId const& mbid = r_cast< MultiBlkId const& >(bid);
            auto it = mbid.iterate();
            while (auto b = it.next()) {
                set_on_disk_bm(*b);
            }
        } else {
            set_on_disk_bm(bid);
        }
        m_is_disk_bm_dirty.store(true);
    }
    rcu_read_unlock();

    return BlkAllocStatus::SUCCESS;
}

void BitmapBlkAllocator::free_on_disk(BlkId const& bid) {
    // this api should be called only on persistent blk allocator
    DEBUG_ASSERT_EQ(is_persistent(), true, "free_on_disk called for non-persistent blk allocator");

    auto unset_on_disk_bm = [this](auto& b) {
        BlkAllocPortion& portion = blknum_to_portion(b.blk_num());
        {
            auto lock{portion.portion_auto_lock()};
            if (!hs()->is_initializing()) {
                // During recovery we might try to free the entry which is already freed while replaying the journal,
                // This assert is valid only post recovery.
                if (!m_disk_bm->is_bits_set(b.blk_num(), b.blk_count())) {
                    BLKALLOC_LOG(ERROR, "bit not set {} nblks {} chunk number {}", b.blk_num(), b.blk_count(),
                                 m_chunk_id);
                    for (blk_count_t i{0}; i < b.blk_count(); ++i) {
                        if (!m_disk_bm->is_bits_set(b.blk_num() + i, 1)) {
                            BLKALLOC_LOG(ERROR, "bit not set {}", b.blk_num() + i);
                        }
                    }
                    BLKALLOC_REL_ASSERT(m_disk_bm->is_bits_set(b.blk_num(), b.blk_count()),
                                        "Expected disk bits to set blk num {} num blks {}", b.blk_num(), b.blk_count());
                }
            }
            m_disk_bm->reset_bits(b.blk_num(), b.blk_count());
        }
    };

    if (bid.is_multi()) {
        MultiBlkId const& mbid = r_cast< MultiBlkId const& >(bid);
        auto it = mbid.iterate();
        while (auto const b = it.next()) {
            unset_on_disk_bm(*b);
        }
    } else {
        unset_on_disk_bm(bid);
    }
}

sisl::byte_array BitmapBlkAllocator::acquire_underlying_buffer() {
    // prepare and temporary alloc list, where blkalloc is accumulated till underlying buffer is released.
    // RCU will wait for all I/Os that are still in critical section (allocating on disk bm) to complete and exit;
    auto alloc_list_ptr = new sisl::ThreadVector< BlkId >();
    auto old_alloc_list_ptr = rcu_xchg_pointer(&m_alloc_blkid_list, alloc_list_ptr);
    synchronize_rcu();

    BLKALLOC_REL_ASSERT(old_alloc_list_ptr == nullptr, "Multiple acquires concurrently?");
    return (m_disk_bm->serialize(m_align_size));
}

void BitmapBlkAllocator::release_underlying_buffer() {
    // set to nullptr, so that alloc will go to disk bm directly
    // wait for all I/Os in critical section (still accumulating bids) to complete and exit;
    auto old_alloc_list_ptr = rcu_xchg_pointer(&m_alloc_blkid_list, nullptr);
    synchronize_rcu();

    // at this point, no I/O will be pushing back to the list (old_alloc_list_ptr);
    auto it = old_alloc_list_ptr->begin(true /* latest */);
    const BlkId* bid{nullptr};
    while ((bid = old_alloc_list_ptr->next(it)) != nullptr) {
        alloc_on_disk(*bid);
    }
    old_alloc_list_ptr->clear();
    delete (old_alloc_list_ptr);
}

/* Get status */
nlohmann::json BitmapBlkAllocator::get_status(int) const { return nlohmann::json{}; }

sisl::ThreadVector< BlkId >* BitmapBlkAllocator::get_alloc_blk_list() {
    auto p = rcu_dereference(m_alloc_blkid_list);
    return p;
}

} // namespace homestore
