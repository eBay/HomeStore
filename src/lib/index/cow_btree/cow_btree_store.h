#pragma once

#include <vector>
#include <atomic>
#include <unordered_map>

#include <sisl/cache/simple_cache.hpp>
#include <homestore/blk.h>
#include <homestore/btree/btree_store.h>
#include <homestore/btree/detail/btree_internal.hpp>
#include <homestore/superblk_handler.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/index_service.hpp>
#include "common/homestore_utils.hpp"
#include "index/cow_btree/cow_btree.h"

namespace homestore {
class COWBtreeCPContext;
class VirtualDev;

class COWBtreeStore : public BtreeStore {
public:
#pragma pack(1)
    struct Journal : public IndexStoreSuperBlock {
    public:
        cp_id_t cp_id;                   // CP Id for this journal, we have one meta blk which contains journal per CP
        uint32_t size{sizeof(Journal)};  // Total journal size
        uint32_t num_btrees{0};          // Total number of btrees updated in this

        // Followed by multiple cowbtree journals
    };
#pragma pack()

private:
    shared< VirtualDev > m_vdev;

    shared< sisl::SimpleCache< bnodeid_t, BtreeNodePtr > > m_cache;

    // List of fibers to flush (note that this could be on multiple threads)
    std::vector< iomgr::io_fiber_t > m_cp_flush_fibers;

    // All loaded journals arranged by the btree ordinals
    std::unordered_map< uint32_t, std::vector< unique< COWBtree::Journal > > > m_journals_by_btree;

    // All journals maintained (sorted) by its cp_id
    std::vector< superblk< IndexStoreSuperBlock > > m_journals_by_cpid;

    // Total number of incremental cp flushes since last full flushes
    uint32_t m_num_incremental_flushes{0};

    BtreeNode::Allocator::Token m_bufalloc_token;

public:
    COWBtreeStore(shared< VirtualDev > vdev, std::vector< superblk< IndexStoreSuperBlock > > store_sbs);
    virtual ~COWBtreeStore() = default;
    void stop() override;

    //////////////////////// Override of IndexStore Interfaces //////////////////////////
    std::string store_type() const override { return "COW_BTREE"; }
    void on_recovery_completed() override;

    ////////////////// Override Implementation of underlying store requirements //////////////////
    unique< UnderlyingBtree > create_underlying_btree(BtreeBase& btree, bool load_existing) override;
    folly::Future< folly::Unit > destroy_underlying_btree(BtreeBase& bt) override;
    // void on_node_freed(BtreeNode* node) override;
    bool is_fast_destroy_supported() const override { return true; }
    bool is_ephemeral() const { return false; }
    uint32_t max_node_size() const override;
    uint32_t align_size() const;
    uint32_t max_capacity() const;

    // Implemenations for flush
    folly::Future< bool > async_cp_flush(COWBtreeCPContext* cp_ctx);
    uint32_t parallel_map_flushers_count() const;

private:
    void flush_map(COWBtreeCPContext* cp_ctx);
    void load_journal(superblk< IndexStoreSuperBlock >& store_journal);
};
} // namespace homestore
