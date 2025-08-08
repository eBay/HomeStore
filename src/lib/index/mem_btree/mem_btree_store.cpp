#include "index/mem_btree/mem_btree_store.h"
#include <homestore/btree/detail/btree_node.hpp>
#include <homestore/btree/btree_base.hpp>

namespace homestore {
unique< UnderlyingBtree > MemBtreeStore::create_underlying_btree(BtreeBase& btree, bool load_existing) {
    // We don't need any mem specific btree portion, everything can be accomplished from common store class
    return std::make_unique< MemBtree >(btree);
}

MemBtree::MemBtree(BtreeBase& btree) : m_base_btree{btree} {}

BtreeNodePtr MemBtree::create_node(bool is_leaf, CPContext*) {
    // std::shared_ptr< uint8_t[] > ptr(new uint8_t[m_base_btree.node_size()]);
    // node_buf_ptr_vec.emplace_back(ptr);
    auto node = m_base_btree.new_node(bnodeid_t{0}, is_leaf, BtreeNode::Allocator::default_token);
    node->set_node_id(bnodeid_t{r_cast< std::uintptr_t >(node.get())});
    node->m_refcount.increment();
    return node;
}

btree_status_t MemBtree::write_node(BtreeNodePtr const& node, CPContext*) { return btree_status_t::success; }

btree_status_t MemBtree::read_node(bnodeid_t id, BtreeNodePtr& node) const {
    node.reset(r_cast< BtreeNode* >(id));
    return btree_status_t::success;
}

btree_status_t MemBtree::refresh_node(BtreeNodePtr const& node, bool for_read_modify_write, CPContext*) {
    return btree_status_t::success;
}

void MemBtree::remove_node(BtreeNodePtr const& node, CPContext*) { intrusive_ptr_release(node.get()); }

btree_status_t MemBtree::transact_nodes(BtreeNodeList const& new_nodes, BtreeNodeList const& freed_nodes,
                                        BtreeNodePtr const& left_child_node, BtreeNodePtr const& parent_node,
                                        CPContext* context) {
    for (auto const& node : new_nodes) {
        m_base_btree.write_node(node, context);
    }
    m_base_btree.write_node(left_child_node, context);
    m_base_btree.write_node(parent_node, context);

    for (auto const& node : freed_nodes) {
        m_base_btree.remove_node(node, locktype_t::WRITE, context);
    }
    return btree_status_t::success;
}

BtreeLinkInfo MemBtree::load_root_node_id() { return BtreeLinkInfo{empty_bnodeid, 0}; }

btree_status_t MemBtree::on_root_changed(BtreeNodePtr const&, CPContext*) { return btree_status_t::success; }

} // namespace homestore