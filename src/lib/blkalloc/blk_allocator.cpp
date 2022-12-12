#include "blk_allocator.h"
//#include "blkalloc_cp.hpp"

namespace homestore {
BlkAllocator::BlkAllocator(const BlkAllocConfig& cfg, chunk_num_t id) : m_cfg{cfg}, m_chunk_id{id} {
    m_blk_portions = std::make_unique< BlkAllocPortion[] >(cfg.get_total_portions());
    for (blk_num_t index{0}; index < cfg.get_total_portions(); ++index) {
        m_blk_portions[index].set_portion_num(index);
        m_blk_portions[index].set_available_blocks(m_cfg.get_blks_per_portion());
    }
    m_auto_recovery = cfg.get_auto_recovery();
    const auto align_size = m_cfg.get_align_size();
    const auto bitmap_id = id;
    m_disk_bm = std::make_unique< sisl::Bitset >(m_cfg.get_total_blks(), bitmap_id, align_size);

    if (realtime_bm_on()) {
        LOGINFO("realtime bitmap turned ON for chunk_id: {}", m_chunk_id);
        m_realtime_bm = std::make_unique< sisl::Bitset >(m_cfg.get_total_blks(), bitmap_id, align_size);
    }

    // NOTE:  Blocks per portion must be modulo word size so locks do not fall on same word
    assert(m_cfg.get_blks_per_portion() % m_disk_bm->word_size() == 0);
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
        if (!m_auto_recovery) { m_disk_bm.reset(); }
        m_inited = true;
        if (realtime_bm_on()) { m_realtime_bm->copy(*(get_disk_bm_const())); }
    }
}

bool BlkAllocator::is_blk_alloced_on_disk(const BlkId& b, bool use_lock) const {
    if (!m_auto_recovery) {
        return true; // nothing to compare. So always return true
    }
    auto bits_set{[this, &b]() {
        if (!get_disk_bm_const()->is_bits_set(b.get_blk_num(), b.get_nblks())) { return false; }
        return true;
    }};
    if (use_lock) {
        const BlkAllocPortion* portion = blknum_to_portion_const(b.get_blk_num());
        auto lock{portion->portion_auto_lock()};
        return bits_set();
    } else {
        return bits_set();
    }
}

BlkAllocStatus BlkAllocator::alloc_on_disk(const BlkId& in_bid) {
    if (!m_auto_recovery && m_inited) { return BlkAllocStatus::FAILED; }

    rcu_read_lock();
    auto list = get_alloc_blk_list();
    if (list) {
        // cp has started, accumulating to the list
        list->push_back(in_bid);
    } else {
        // cp is not started or already done, allocate on disk bm directly;
        /* enable this assert later when reboot is supported */
        // assert(m_auto_recovery || !m_inited);
        BlkAllocPortion* portion = blknum_to_portion(in_bid.get_blk_num());
        {
            auto lock{portion->portion_auto_lock()};
            if (m_inited) {
                BLKALLOC_REL_ASSERT(get_disk_bm_const()->is_bits_reset(in_bid.get_blk_num(), in_bid.get_nblks()),
                                    "Expected disk blks to reset");
            }
            get_disk_bm_mutable()->set_bits(in_bid.get_blk_num(), in_bid.get_nblks());
            portion->decrease_available_blocks(in_bid.get_nblks());
            BLKALLOC_LOG(DEBUG, "blks allocated {} chunk number {}", in_bid.to_string(), m_chunk_id);
        }
    }
    rcu_read_unlock();

    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus BlkAllocator::alloc_on_realtime(const BlkId& b) {
    if (!realtime_bm_on()) { return BlkAllocStatus::SUCCESS; }

    if (!m_auto_recovery && m_inited) { return BlkAllocStatus::FAILED; }
    BlkAllocPortion* portion = blknum_to_portion(b.get_blk_num());
    {
        auto lock{portion->portion_auto_lock()};
        if (m_inited) {
            if (!get_realtime_bm()->is_bits_reset(b.get_blk_num(), b.get_nblks())) {
                BLKALLOC_LOG(ERROR, "bit not reset {} nblks {} chunk number {}", b.get_blk_num(), b.get_nblks(),
                             m_chunk_id);
                for (blk_count_t i{0}; i < b.get_nblks(); ++i) {
                    if (!get_disk_bm_const()->is_bits_reset(b.get_blk_num() + i, 1)) {
                        BLKALLOC_LOG(ERROR, "bit not reset {}", b.get_blk_num() + i);
                    }
                }
                BLKALLOC_REL_ASSERT(get_realtime_bm()->is_bits_reset(b.get_blk_num(), b.get_nblks()),
                                    "Expected disk bits to reset blk num {} num blks {}", b.get_blk_num(),
                                    b.get_nblks());
            }
        }
        get_realtime_bm()->set_bits(b.get_blk_num(), b.get_nblks());
        BLKALLOC_LOG(DEBUG, "realtime blks allocated {} chunk number {}", b.to_string(), m_chunk_id);
    }

    return BlkAllocStatus::SUCCESS;
}

//
// Caller should consume the return value and print context when return false;
//
bool BlkAllocator::free_on_realtime(const BlkId& b) {
    if (!realtime_bm_on()) { return true; }

    /* this api should be called only when auto recovery is enabled */
    assert(m_auto_recovery);
    BlkAllocPortion* portion = blknum_to_portion(b.get_blk_num());
    {
        auto lock{portion->portion_auto_lock()};
        if (m_inited) {
            /* During recovery we might try to free the entry which is already freed while replaying the journal,
             * This assert is valid only post recovery.
             */
            if (!get_realtime_bm()->is_bits_set(b.get_blk_num(), b.get_nblks())) {
                BLKALLOC_LOG(ERROR, "{}, bit not set {} nblks{} chunk number {}", b.to_string(), b.get_blk_num(),
                             b.get_nblks(), m_chunk_id);
                for (blk_count_t i{0}; i < b.get_nblks(); ++i) {
                    if (!get_realtime_bm()->is_bits_set(b.get_blk_num() + i, 1)) {
                        BLKALLOC_LOG(ERROR, "bit not set {}", b.get_blk_num() + i);
                    }
                }
                return false;
            }
        }

        BLKALLOC_LOG(DEBUG, "realtime: free bid: {}", b.to_string());
        get_realtime_bm()->reset_bits(b.get_blk_num(), b.get_nblks());
        return true;
    }
}

void BlkAllocator::free_on_disk(const BlkId& b) {
    /* this api should be called only when auto recovery is enabled */
    assert(m_auto_recovery);
    BlkAllocPortion* portion = blknum_to_portion(b.get_blk_num());
    {
        auto lock{portion->portion_auto_lock()};
        if (m_inited) {
            /* During recovery we might try to free the entry which is already freed while replaying the journal,
             * This assert is valid only post recovery.
             */
            if (!get_disk_bm_const()->is_bits_set(b.get_blk_num(), b.get_nblks())) {
                BLKALLOC_LOG(ERROR, "bit not set {} nblks {} chunk number {}", b.get_blk_num(), b.get_nblks(),
                             m_chunk_id);
                for (blk_count_t i{0}; i < b.get_nblks(); ++i) {
                    if (!get_disk_bm_const()->is_bits_set(b.get_blk_num() + i, 1)) {
                        BLKALLOC_LOG(ERROR, "bit not set {}", b.get_blk_num() + i);
                    }
                }
                BLKALLOC_REL_ASSERT(get_disk_bm_const()->is_bits_set(b.get_blk_num(), b.get_nblks()),
                                    "Expected disk bits to set blk num {} num blks {}", b.get_blk_num(), b.get_nblks());
            }
        }
        get_disk_bm_mutable()->reset_bits(b.get_blk_num(), b.get_nblks());
        portion->increase_available_blocks(b.get_nblks());
    }
}

sisl::byte_array BlkAllocator::acquire_underlying_buffer() {
    // prepare and temporary alloc list, where blkalloc is accumulated till underlying buffer is released.
    // RCU will wait for all I/Os that are still in critical section (allocating on disk bm) to complete and exit;
    auto alloc_list_ptr = new sisl::ThreadVector< BlkId >();
    auto old_alloc_list_ptr = rcu_xchg_pointer(&m_alloc_blkid_list, alloc_list_ptr);
    synchronize_rcu();

    BLKALLOC_REL_ASSERT(old_alloc_list_ptr == nullptr, "Multiple acquires concurrently?");
    return (m_disk_bm->serialize(m_cfg.get_align_size()));
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
    m_debug_bm = std::make_unique< sisl::Bitset >(m_cfg.get_total_blks(), m_chunk_id, m_cfg.get_align_size());
    assert(m_cfg.get_blks_per_portion() % m_debug_bm->word_size() == 0);
}

void BlkAllocator::update_debug_bm(const BlkId& bid) {
    BLKALLOC_REL_ASSERT(get_disk_bm_const()->is_bits_set(bid.get_blk_num(), bid.get_nblks()),
                        "Expected disk bits to set blk num {} num blks {}", bid.get_blk_num(), bid.get_nblks());
    get_debug_bm()->set_bits(bid.get_blk_num(), bid.get_nblks());
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
