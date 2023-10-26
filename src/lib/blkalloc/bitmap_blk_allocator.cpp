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
#include "blk_allocator.h"

namespace homestore {
BlkAllocator::BlkAllocator(const BlkAllocConfig& cfg, chunk_num_t id) :
        m_name{cfg.m_unique_name},
        m_blk_size{cfg.m_blk_size},
        m_align_size{cfg.m_align_size},
        m_num_blks{cfg.m_capacity},
        m_auto_recovery{cfg.m_auto_recovery},
        m_realtime_bm_on{cfg.m_realtime_bm_on},
        m_chunk_id{id} {
    m_disk_bm = std::make_unique< sisl::Bitset >(m_num_blks, m_chunk_id, m_align_size);

    // NOTE:  Blocks per portion must be modulo word size so locks do not fall on same word
    m_blks_per_portion = sisl::round_up(cfg.m_blks_per_portion, m_disk_bm->word_size());

    m_blk_portions = std::make_unique< BlkAllocPortion[] >(get_num_portions());
    for (blk_num_t index{0}; index < get_num_portions(); ++index) {
        m_blk_portions[index].set_portion_num(index);
        m_blk_portions[index].set_available_blocks(get_blks_per_portion());
    }

    if (realtime_bm_on()) {
        LOGINFO("realtime bitmap turned ON for chunk_id: {}", m_chunk_id);
        m_realtime_bm = std::make_unique< sisl::Bitset >(m_num_blks, m_chunk_id, m_align_size);
    }
}

void BlkAllocator::cp_flush(CP*) {
    // To be implemented;
    LOGINFO("BitmapBlkAllocator cp_flush in not yet supported. ");
}

void BlkAllocator::set_disk_bm(std::unique_ptr< sisl::Bitset > recovered_bm) {
    BLKALLOC_LOG(INFO, "Persistent bitmap of size={} recovered", recovered_bm->size());
    m_disk_bm = std::move(recovered_bm);
    // mark dirty
    set_disk_bm_dirty();
}

void BlkAllocator::inited() {
    if (!m_inited) {
        m_alloced_blk_count.fetch_add(get_disk_bm_const()->get_set_count(), std::memory_order_relaxed);
        if (!auto_recovery_on()) { m_disk_bm.reset(); }
        m_inited = true;
        if (realtime_bm_on()) { m_realtime_bm->copy(*(get_disk_bm_const())); }
    }
}

bool BlkAllocator::is_blk_alloced_on_disk(const BlkId& b, bool use_lock) const {
    if (!auto_recovery_on()) {
        return true; // nothing to compare. So always return true
    }
    auto bits_set = [this](BlkId const& b) {
        if (!get_disk_bm_const()->is_bits_set(b.blk_num(), b.blk_count())) { return false; }
        return true;
    };

    if (use_lock) {
        const BlkAllocPortion& portion = blknum_to_portion_const(b.blk_num());
        auto lock{portion.portion_auto_lock()};
        return bits_set(b);
    } else {
        return bits_set(b);
    }
}

BlkAllocStatus BlkAllocator::alloc_on_disk(BlkId const& bid) {
    if (!auto_recovery_on() && m_inited) { return BlkAllocStatus::FAILED; }

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
                if (m_inited) {
                    BLKALLOC_REL_ASSERT(get_disk_bm_const()->is_bits_reset(b.blk_num(), b.blk_count()),
                                        "Expected disk blks to reset");
                }
                get_disk_bm_mutable()->set_bits(b.blk_num(), b.blk_count());
                portion.decrease_available_blocks(b.blk_count());
                BLKALLOC_LOG(DEBUG, "blks allocated {} chunk number {}", b.to_string(), m_chunk_id);
            }
        };

        // cp is not started or already done, allocate on disk bm directly;
        /* enable this assert later when reboot is supported */
        // assert(auto_recovery_on() || !m_inited);
        if (bid.is_multi()) {
            MultiBlkId const& mbid = r_cast< MultiBlkId const& >(bid);
            auto it = mbid.iterate();
            while (auto b = it.next()) {
                set_on_disk_bm(*b);
            }
        } else {
            set_on_disk_bm(bid);
        }
    }
    rcu_read_unlock();

    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus BlkAllocator::alloc_on_realtime(BlkId const& bid) {
    if (!realtime_bm_on()) { return BlkAllocStatus::SUCCESS; }

    if (!auto_recovery_on() && m_inited) { return BlkAllocStatus::FAILED; }

    auto set_on_realtime_bm = [this](BlkId const& b) {
        BlkAllocPortion& portion = blknum_to_portion(b.blk_num());
        {
            auto lock{portion.portion_auto_lock()};
            if (m_inited) {
                if (!get_realtime_bm()->is_bits_reset(b.blk_num(), b.blk_count())) {
                    BLKALLOC_LOG(ERROR, "bit not reset {} nblks {} chunk number {}", b.blk_num(), b.blk_count(),
                                 m_chunk_id);
                    for (blk_count_t i{0}; i < b.blk_count(); ++i) {
                        if (!get_disk_bm_const()->is_bits_reset(b.blk_num() + i, 1)) {
                            BLKALLOC_LOG(ERROR, "bit not reset {}", b.blk_num() + i);
                        }
                    }
                    BLKALLOC_REL_ASSERT(get_realtime_bm()->is_bits_reset(b.blk_num(), b.blk_count()),
                                        "Expected disk bits to reset blk num {} num blks {}", b.blk_num(),
                                        b.blk_count());
                }
            }
            get_realtime_bm()->set_bits(b.blk_num(), b.blk_count());
            BLKALLOC_LOG(DEBUG, "realtime blks allocated {} chunk number {}", b.to_string(), m_chunk_id);
        }
    };

    if (bid.is_multi()) {
        MultiBlkId const& mbid = r_cast< MultiBlkId const& >(bid);
        auto it = mbid.iterate();
        while (auto const b = it.next()) {
            set_on_realtime_bm(*b);
        }
    } else {
        set_on_realtime_bm(bid);
    }

    return BlkAllocStatus::SUCCESS;
}

//
// Caller should consume the return value and print context when return false;
//
bool BlkAllocator::free_on_realtime(BlkId const& bid) {
    if (!realtime_bm_on()) { return true; }

    /* this api should be called only when auto recovery is enabled */
    assert(auto_recovery_on());

    auto unset_on_realtime_bm = [this](BlkId const& b) {
        BlkAllocPortion& portion = blknum_to_portion(b.blk_num());
        {
            auto lock{portion.portion_auto_lock()};
            if (m_inited) {
                /* During recovery we might try to free the entry which is already freed while replaying the journal,
                 * This assert is valid only post recovery.
                 */
                if (!get_realtime_bm()->is_bits_set(b.blk_num(), b.blk_count())) {
                    BLKALLOC_LOG(ERROR, "{}, bit not set {} nblks{} chunk number {}", b.to_string(), b.blk_num(),
                                 b.blk_count(), m_chunk_id);
                    for (blk_count_t i{0}; i < b.blk_count(); ++i) {
                        if (!get_realtime_bm()->is_bits_set(b.blk_num() + i, 1)) {
                            BLKALLOC_LOG(ERROR, "bit not set {}", b.blk_num() + i);
                        }
                    }
                    return false;
                }
            }

            BLKALLOC_LOG(DEBUG, "realtime: free bid: {}", b.to_string());
            get_realtime_bm()->reset_bits(b.blk_num(), b.blk_count());
            return true;
        }
    };

    bool ret{true};
    if (bid.is_multi()) {
        MultiBlkId const& mbid = r_cast< MultiBlkId const& >(bid);
        auto it = mbid.iterate();
        while (auto const b = it.next()) {
            if (!unset_on_realtime_bm(*b)) {
                ret = false;
                break;
            }
        }
    } else {
        ret = unset_on_realtime_bm(bid);
    }
    return ret;
}

void BlkAllocator::free_on_disk(BlkId const& bid) {
    /* this api should be called only when auto recovery is enabled */
    assert(auto_recovery_on());
    auto unset_on_disk_bm = [this](auto& b) {
        BlkAllocPortion& portion = blknum_to_portion(b.blk_num());
        {
            auto lock{portion.portion_auto_lock()};
            if (m_inited) {
                /* During recovery we might try to free the entry which is already freed while replaying the journal,
                 * This assert is valid only post recovery.
                 */
                if (!get_disk_bm_const()->is_bits_set(b.blk_num(), b.blk_count())) {
                    BLKALLOC_LOG(ERROR, "bit not set {} nblks {} chunk number {}", b.blk_num(), b.blk_count(),
                                 m_chunk_id);
                    for (blk_count_t i{0}; i < b.blk_count(); ++i) {
                        if (!get_disk_bm_const()->is_bits_set(b.blk_num() + i, 1)) {
                            BLKALLOC_LOG(ERROR, "bit not set {}", b.blk_num() + i);
                        }
                    }
                    BLKALLOC_REL_ASSERT(get_disk_bm_const()->is_bits_set(b.blk_num(), b.blk_count()),
                                        "Expected disk bits to set blk num {} num blks {}", b.blk_num(), b.blk_count());
                }
            }
            get_disk_bm_mutable()->reset_bits(b.blk_num(), b.blk_count());
            portion.increase_available_blocks(b.blk_count());
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

sisl::byte_array BlkAllocator::acquire_underlying_buffer() {
    // prepare and temporary alloc list, where blkalloc is accumulated till underlying buffer is released.
    // RCU will wait for all I/Os that are still in critical section (allocating on disk bm) to complete and exit;
    auto alloc_list_ptr = new sisl::ThreadVector< BlkId >();
    auto old_alloc_list_ptr = rcu_xchg_pointer(&m_alloc_blkid_list, alloc_list_ptr);
    synchronize_rcu();

    BLKALLOC_REL_ASSERT(old_alloc_list_ptr == nullptr, "Multiple acquires concurrently?");
    return (m_disk_bm->serialize(m_align_size));
}

void BlkAllocator::release_underlying_buffer() {
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

void BlkAllocator::create_debug_bm() {
    m_debug_bm = std::make_unique< sisl::Bitset >(m_num_blks, m_chunk_id, m_align_size);
    assert(get_blks_per_portion() % m_debug_bm->word_size() == 0);
}

void BlkAllocator::update_debug_bm(const BlkId& bid) {
    BLKALLOC_REL_ASSERT(get_disk_bm_const()->is_bits_set(bid.blk_num(), bid.blk_count()),
                        "Expected disk bits to set blk num {} num blks {}", bid.blk_num(), bid.blk_count());
    get_debug_bm()->set_bits(bid.blk_num(), bid.blk_count());
}

bool BlkAllocator::verify_debug_bm(bool free_debug_bm) {
    const bool ret = *get_disk_bm_const() == *get_debug_bm();
    if (free_debug_bm) { m_debug_bm.reset(); }
    return ret;
}

/* Get status */
nlohmann::json BlkAllocator::get_status(int log_level) const {
    nlohmann::json j;
    return j;
}

sisl::ThreadVector< BlkId >* BlkAllocator::get_alloc_blk_list() {
    auto p = rcu_dereference(m_alloc_blkid_list);
    return p;
}

} // namespace homestore
