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
#pragma once
#ifdef StoreSpecificBtreeNode
#undef StoreSpecificBtreeNode
#endif

#define StoreSpecificBtreeNode BtreeNode

#include "btree.ipp"

namespace homestore {
template < typename K, typename V >
class MemBtree : public Btree< K, V > {
private:
    std::vector< std::shared_ptr< uint8_t[] > > node_buf_ptr_vec;

public:
    MemBtree(const BtreeConfig& cfg) : Btree< K, V >(cfg) {
        BT_LOG(INFO, "New {} being created: Node size {}", btree_store_type(), cfg.node_size());
        auto const status = this->create_root_node(nullptr);
        if (status != btree_status_t::success) { throw std::runtime_error(fmt::format("Unable to create root node")); }
    }

    virtual ~MemBtree() {
        const auto [ret, free_node_cnt] = this->destroy_btree(nullptr);
        BT_LOG_ASSERT_EQ(ret, btree_status_t::success, "btree destroy failed");
    }

    std::string btree_store_type() const override { return "MEM_BTREE"; }

private:
    BtreeNodePtr alloc_node(bool is_leaf) override {
        std::shared_ptr< uint8_t[] > ptr(new uint8_t[this->m_bt_cfg.node_size()]);
        node_buf_ptr_vec.emplace_back(ptr);

        auto new_node = this->init_node(ptr.get(), bnodeid_t{0}, true, is_leaf);
        new_node->set_node_id(bnodeid_t{r_cast< std::uintptr_t >(new_node)});
        new_node->m_refcount.increment();
        return BtreeNodePtr{new_node};
    }

    btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) { return btree_status_t::success; }

    btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr& node) const override {
        node.reset(r_cast< BtreeNode* >(id));
        return btree_status_t::success;
    }

    btree_status_t refresh_node(const BtreeNodePtr& node, bool for_read_modify_write, void* context) const override {
        return btree_status_t::success;
    }

    void free_node_impl(const BtreeNodePtr& node, void* context) override { intrusive_ptr_release(node.get()); }

    btree_status_t transact_nodes(const BtreeNodeList& new_nodes, const BtreeNodeList& freed_nodes,
                                  const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                  void* context) override {
        for (const auto& node : new_nodes) {
            this->write_node(node, context);
        }
        this->write_node(left_child_node, context);
        this->write_node(parent_node, context);

        for (const auto& node : freed_nodes) {
            this->free_node(node, locktype_t::WRITE, context);
        }
        return btree_status_t::success;
    }

    btree_status_t on_root_changed(BtreeNodePtr const&, void*) override { return btree_status_t::success; }
};
} // namespace homestore
