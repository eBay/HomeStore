#include "blk_allocator.h"
#include "blkalloc_cp.hpp"

namespace homestore {
BlkAllocator::BlkAllocator(const BlkAllocConfig& cfg, const chunk_num_t id) : m_cfg{cfg}, m_chunk_id{id} {
    m_blk_portions = std::make_unique< BlkAllocPortion[] >(cfg.get_total_portions());
    for (blk_num_t index{0}; index < cfg.get_total_portions(); ++index) {
        m_blk_portions[index].set_portion_num(index);
        m_blk_portions[index].set_available_blocks(m_cfg.get_blks_per_portion());
    }
    m_auto_recovery = cfg.get_auto_recovery();
    const auto align_size{m_cfg.get_pdev_group() == PhysicalDevGroup::DATA
                              ? HS_STATIC_CONFIG(data_drive_attr.align_size)
                              : HS_STATIC_CONFIG(fast_drive_attr.align_size)};
    const auto bitmap_id{encode_pdev_group_and_chunk_id(m_cfg.get_pdev_group(), id)};
    m_disk_bm = std::make_unique< sisl::Bitset >(m_cfg.get_total_blks(), bitmap_id, align_size);

    if (!HS_DYNAMIC_CONFIG(generic.sanity_check_level_non_hotswap)) { m_cfg.m_realtime_bm_on = false; }

    if (realtime_bm_on()) {
        m_realtime_bm = std::make_unique< sisl::Bitset >(m_cfg.get_total_blks(), bitmap_id, align_size);
    }
    // NOTE:  Blocks per portion must be modulo word size so locks do not fall on same word
    assert(m_cfg.get_blks_per_portion() % m_disk_bm->word_size() == 0);
}

void BlkAllocator::set_disk_bm(std::unique_ptr< sisl::Bitset > recovered_bm) {
    BLKALLOC_LOG(INFO, "Persistent bitmap of size={} recovered", recovered_bm->size());
    m_disk_bm = std::move(recovered_bm);
}

void BlkAllocator::inited() {
    if (!m_inited) {
        m_alloced_blk_count.fetch_add(m_disk_bm->get_set_count(), std::memory_order_relaxed);
        if (!m_auto_recovery) { m_disk_bm.reset(); }
        m_inited = true;
        if (realtime_bm_on()) { m_realtime_bm->copy(*(get_disk_bm())); }
    }
}

bool BlkAllocator::is_blk_alloced_on_disk(const BlkId& b, const bool use_lock) const {
    if (!m_auto_recovery) {
        return true; // nothing to compare. So always return true
    }
    auto bits_set{[this, &b]() {
        if (!m_disk_bm->is_bits_set(b.get_blk_num(), b.get_nblks())) { return false; }
        return true;
    }};
    if (use_lock) {
        const BlkAllocPortion* const portion{blknum_to_portion_const(b.get_blk_num())};
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
        BlkAllocPortion* const portion{blknum_to_portion(in_bid.get_blk_num())};
        {
            auto lock{portion->portion_auto_lock()};
            if (m_inited) {
                BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_reset(in_bid.get_blk_num(), in_bid.get_nblks()),
                                "Expected disk blks to reset");
            }
            get_disk_bm()->set_bits(in_bid.get_blk_num(), in_bid.get_nblks());
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
    BlkAllocPortion* const portion{blknum_to_portion(b.get_blk_num())};
    {
        auto lock{portion->portion_auto_lock()};
        if (m_inited) {
            if (!get_realtime_bm()->is_bits_reset(b.get_blk_num(), b.get_nblks())) {
                BLKALLOC_LOG(ERROR, "bit not reset {} nblks {} chunk number {}", b.get_blk_num(), b.get_nblks(),
                             m_chunk_id);
                for (blk_count_t i{0}; i < b.get_nblks(); ++i) {
                    if (!get_disk_bm()->is_bits_reset(b.get_blk_num() + i, 1)) {
                        BLKALLOC_LOG(ERROR, "bit not reset {}", b.get_blk_num() + i);
                    }
                }
                BLKALLOC_ASSERT(RELEASE, get_realtime_bm()->is_bits_reset(b.get_blk_num(), b.get_nblks()),
                                "Expected disk bits to reset blk num {} num blks {}", b.get_blk_num(), b.get_nblks());
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
    BlkAllocPortion* const portion{blknum_to_portion(b.get_blk_num())};
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
    BlkAllocPortion* const portion{blknum_to_portion(b.get_blk_num())};
    {
        auto lock{portion->portion_auto_lock()};
        if (m_inited) {
            /* During recovery we might try to free the entry which is already freed while replaying the journal,
             * This assert is valid only post recovery.
             */
            if (!get_disk_bm()->is_bits_set(b.get_blk_num(), b.get_nblks())) {
                BLKALLOC_LOG(ERROR, "bit not set {} nblks {} chunk number {}", b.get_blk_num(), b.get_nblks(),
                             m_chunk_id);
                for (blk_count_t i{0}; i < b.get_nblks(); ++i) {
                    if (!get_disk_bm()->is_bits_set(b.get_blk_num() + i, 1)) {
                        BLKALLOC_LOG(ERROR, "bit not set {}", b.get_blk_num() + i);
                    }
                }
                BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_set(b.get_blk_num(), b.get_nblks()),
                                "Expected disk bits to set blk num {} num blks {}", b.get_blk_num(), b.get_nblks());
            }
        }
        get_disk_bm()->reset_bits(b.get_blk_num(), b.get_nblks());
        portion->increase_available_blocks(b.get_nblks());
    }
}

/* CP start is called when all its consumers have purged their free lists and now want to persist the
 * disk bitmap.
 */
sisl::byte_array BlkAllocator::cp_start([[maybe_unused]] const std::shared_ptr< blkalloc_cp >& id) {
    // prepare a valid blk alloc list;
    auto alloc_list_ptr{new sisl::ThreadVector< BlkId >()};
    // set to valid pointer, blk alloc will be acummulated;
    auto old_alloc_list_ptr{rcu_xchg_pointer(&m_alloc_blkid_list, alloc_list_ptr)};
    // wait for all I/Os that are still in critical section (allocating on disk bm) to complete and exit;
    synchronize_rcu();

    BLKALLOC_ASSERT(RELEASE, old_alloc_list_ptr == nullptr, "Expecting alloc list to be nullptr");
    return (m_disk_bm->serialize(m_cfg.get_pdev_group() == PhysicalDevGroup::DATA
                                     ? HS_STATIC_CONFIG(data_drive_attr.align_size)
                                     : HS_STATIC_CONFIG(fast_drive_attr.align_size)));
}

void BlkAllocator::cp_done() {
    // set to nullptr, so that alloc will go to disk bm directly
    auto old_alloc_list_ptr{rcu_xchg_pointer(&m_alloc_blkid_list, nullptr)};
    // wait for all I/Os in critical section (still accumulating bids) to complete and exit;
    synchronize_rcu();

    // at this point, no I/O will be pushing back to the list (old_alloc_list_ptr);
    auto it{old_alloc_list_ptr->begin(true /* latest */)};
    const BlkId* bid{nullptr};
    while ((bid = old_alloc_list_ptr->next(it)) != nullptr) {
        alloc_on_disk(*bid);
    }
    old_alloc_list_ptr->clear();

    delete (old_alloc_list_ptr);
    // another cp flush won't start until this flush is completed, so no cp_start won't be called in parallel;
}

void BlkAllocator::create_debug_bm() {
    m_debug_bm = std::make_unique< sisl::Bitset >(m_cfg.get_total_blks(), m_chunk_id,
                                                  (m_cfg.get_pdev_group() == PhysicalDevGroup::DATA
                                                       ? HS_STATIC_CONFIG(data_drive_attr.align_size)
                                                       : HS_STATIC_CONFIG(fast_drive_attr.align_size)));
    assert(m_cfg.get_blks_per_portion() % m_debug_bm->word_size() == 0);
}

void BlkAllocator::update_debug_bm(const BlkId& bid) {
    BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_set(bid.get_blk_num(), bid.get_nblks()),
                    "Expected disk bits to set blk num {} num blks {}", bid.get_blk_num(), bid.get_nblks());
    get_debug_bm()->set_bits(bid.get_blk_num(), bid.get_nblks());
}

bool BlkAllocator::verify_debug_bm(const bool free_debug_bm) {
    const bool ret{*get_disk_bm() == *get_debug_bm()};
    if (free_debug_bm) { m_debug_bm.reset(); }
    return ret;
}

/* Get status */
nlohmann::json BlkAllocator::get_status(const int log_level) const {
    nlohmann::json j;
    return j;
}

uint64_t BlkAllocator::encode_pdev_group_and_chunk_id(const PhysicalDevGroup pdev_group, chunk_num_t chunk_id) {
    return static_cast< uint64_t >(chunk_id & 0xFFFFFFFF) | ((static_cast< uint64_t >(pdev_group) & 0xFFFFFFFF) << 32);
}

std::pair< PhysicalDevGroup, chunk_num_t > BlkAllocator::get_pdev_group_and_chunk_id(const uint64_t id) {
    const chunk_num_t chunk_id{static_cast< chunk_num_t >(id & 0xFFFFFFFF)};
    const auto pdev_id{static_cast< std::underlying_type_t< PhysicalDevGroup > >((id >> 32) & 0xFFFFFFFF)};
    const auto pdev_group{static_cast< PhysicalDevGroup >(pdev_id)};
    return {pdev_group, chunk_id};
}

sisl::ThreadVector< BlkId >* BlkAllocator::get_alloc_blk_list() {
    auto p = rcu_dereference(m_alloc_blkid_list);
    return p;
}

} // namespace homestore
