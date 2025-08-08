#include <homestore/checkpoint/cp_mgr.hpp>
#include "index/cow_btree/cow_btree_cp.h"
#include "index/cow_btree/cow_btree_store.h"
#include "index/index_cp.h"
#include "common/homestore_assert.hpp"

namespace homestore {
COWBtreeCPCallbacks::COWBtreeCPCallbacks(COWBtreeStore* store) : m_bt_store{store} {}

std::unique_ptr< CPContext > COWBtreeCPCallbacks::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    return std::make_unique< COWBtreeCPContext >(new_cp, m_bt_store);
}

folly::Future< bool > COWBtreeCPCallbacks::cp_flush(CP* cp) {
    auto ctx = IndexCPContext::store_context< COWBtreeCPContext >(cp, IndexStore::Type::COPY_ON_WRITE_BTREE);
    return m_bt_store->async_cp_flush(ctx);
}

void COWBtreeCPCallbacks::cp_cleanup(CP* cp) {}

int COWBtreeCPCallbacks::cp_progress_percent() { return 100; }

/////////////////////// COWBtreeCPContext section ///////////////////////////
COWBtreeCPContext::COWBtreeCPContext(CP* cp, COWBtreeStore* bt_store) :
        CPContext(cp),
        m_parallel_flushers_count{bt_store->parallel_map_flushers_count()},
        m_merged_journal_buf{4096u, bt_store->align_size(), sisl::buftag::btree_journal} {
    // NOTE: We calculate this on every CP is because we are making this resource limit of max dirty as hot swappable.
    // However, instead of doing this calculation on every dirty buf increment, it is reasonable to calculate the dirty
    // size per CP
    m_max_dirty_size = uint64_cast(HS_DYNAMIC_CONFIG(resource_limits.index_max_dirty_memory_percent) *
                                   HS_STATIC_CONFIG(input.io_mem_size()) / 100);
    m_max_pending_free_size = uint64_cast(HS_DYNAMIC_CONFIG(resource_limits.index_max_free_space_accumulate_percent) *
                                          bt_store->max_capacity() / 100);
}

bool COWBtreeCPContext::need_full_map_flush() const { return m_is_full_map_flush; }

std::string COWBtreeCPContext::to_string() const {
    // TODO: Fill with approp details
    return std::string();
}

void COWBtreeCPContext::increment_dirty_size(uint32_t size) {
    if (m_dirty_size.increment_test_ge(m_max_dirty_size, size)) {
        hs()->cp_mgr().trigger_cp_flush(false /* force */, CPTriggerReason::IndexBufferFull);
    }
}

void COWBtreeCPContext::increment_pending_free_size(uint32_t size) {
    if (m_pending_free_size.increment_test_ge(m_max_pending_free_size, size)) {
        hs()->cp_mgr().trigger_cp_flush(false /* force */, CPTriggerReason::IndexFreeBlksExceeded);
    }
}

void COWBtreeCPContext::prepare_to_flush(bool full_map_flush) {
    // First we need to decide if this should be full map flush or incremental flush
    CP_PERIODIC_LOG(DEBUG, id(),
                    "CowBtree has dirty node buffer size={}, pending node free size={} across all btrees, flushing "
                    "the nodes and flush {} map",
                    m_dirty_size.get(), m_pending_free_size.get(), full_map_flush ? "FULL" : "only INCREMENTAL");
    m_is_full_map_flush = full_map_flush;

    if (!m_is_full_map_flush) {
        COWBtreeStore::Journal hdr_sb;
        hdr_sb.cp_id = id();
        hdr_sb.index_store_type = IndexStore::Type::COPY_ON_WRITE_BTREE;

        m_merged_journal_buf.append(sisl::blob{uintptr_cast(&hdr_sb), uint32_cast(sizeof(COWBtreeStore::Journal))});
        m_journal_header = r_cast< COWBtreeStore::Journal* >(m_merged_journal_buf.bytes());
    }

    // Get all the current btrees in the system.
    m_all_btrees = std::move(hs()->index_service().get_all_index_tables());
}

void COWBtreeCPContext::flushed_a_btree(COWBtree* cow_btree, COWBtree::Journal const* journal) {
    std::unique_lock lg{m_bt_list_mtx};
    ++m_flushed_btrees_count;

    // This btree was dirtied in this cp, keep track of these btrees to persist their full map (if full
    // map cp) or if superblk is changed.
    // NOTE: We cannot persist superblk before persisting the journal that all btrees have been built.
    // That is why we need to keep track of all btrees whose superblk has been changed and then write
    // later.
    if (m_is_full_map_flush) {
        m_active_btree_list.emplace_back(cow_btree);
    } else {
        append_btree_journal(journal->m_base_buf);
    }
}

folly::Future< folly::Unit > COWBtreeCPContext::add_to_destroyed_list(shared< Index > btree) {
    std::unique_lock lg{m_bt_list_mtx};
    m_destroyed_btrees.emplace_back(std::pair(btree, folly::Promise< folly::Unit >{}));
    return m_destroyed_btrees.back().second.getFuture();
}

void COWBtreeCPContext::actual_destroy_btrees() {
    // If there are any destroyed btrees as part of the CP, do the actual destroy now.
    for (auto& [btree, p] : m_destroyed_btrees) {
        COWBtree::cast_to(btree.get())->destroy();
        p.setValue();
    }

    CP_PERIODIC_LOG(INFO, id(),
                    "CowBtreeStore has {} btrees destroyed in this cp, destroyed all persistent structures for them",
                    m_destroyed_btrees.size());
}

void COWBtreeCPContext::append_btree_journal(sisl::io_blob_safe const& btree_journal_buf) {
    HS_DBG_ASSERT_EQ(m_is_full_map_flush, false, "Btree journal update on full map flush");
    ++m_journal_header->num_btrees;
    m_journal_header->size += btree_journal_buf.size();
    m_merged_journal_buf.append(btree_journal_buf);
}

sisl::byte_view COWBtreeCPContext::store_journal() const { return m_merged_journal_buf.view(); }

} // namespace homestore
