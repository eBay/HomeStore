#pragma once

#include <vector>
#include <memory>

#include <homestore/btree/btree_store.h>
#include <homestore/btree/btree_base.hpp>

namespace homestore {
class MemBtreeStore : public BtreeStore {
public:
    MemBtreeStore() = default;
    virtual ~MemBtreeStore() = default;

    void stop() override {}
    std::string store_type() const override { return "MEM_BTREE"; }
    void on_recovery_completed() override {}

    unique< UnderlyingBtree > create_underlying_btree(BtreeBase& btree, bool load_existing) override;
    folly::Future< folly::Unit > destroy_underlying_btree(BtreeBase&) override { return folly::makeFuture(); }
    // void on_node_freed(BtreeNode* node) override;
    bool is_fast_destroy_supported() const override { return true; }
    bool is_ephemeral() const override { return true; }
    uint32_t max_node_size() const override { return 4096u; }
};

class MemBtree : public UnderlyingBtree {
public:
    MemBtree(BtreeBase& btree);
    BtreeNodePtr create_node(bool is_leaf, CPContext* context) override;
    btree_status_t write_node(BtreeNodePtr const& node, CPContext* context) override;
    btree_status_t read_node(bnodeid_t id, BtreeNodePtr& node) const override;
    btree_status_t refresh_node(BtreeNodePtr const& node, bool for_read_modify_write, CPContext* context) override;
    void remove_node(BtreeNodePtr const& node, CPContext* context) override;
    btree_status_t transact_nodes(BtreeNodeList const& new_nodes, BtreeNodeList const& freed_nodes,
                                  BtreeNodePtr const& left_child_node, BtreeNodePtr const& parent_node,
                                  CPContext* context) override;
    BtreeLinkInfo load_root_node_id() override;
    btree_status_t on_root_changed(BtreeNodePtr const&, CPContext*) override;
    uint64_t space_occupied() const override { return 0; }

private:
    BtreeBase& m_base_btree;
    // std::vector< std::shared_ptr< uint8_t[] > > node_buf_ptr_vec;
};

} // namespace homestore