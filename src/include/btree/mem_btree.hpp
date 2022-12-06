/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#include "btree.ipp"

namespace homestore {
#ifdef INCASE_WE_NEED_COMMON
// Common class for all membtree's
template < typename K, typename V >
class MemBtreeCommon : public BtreeCommon< K, V > {
public:
    void deref_node(BtreeNode< K >* node) override {
        if (node->m_refcount.decrement_testz()) {
            delete node->m_node_buf;
            delete node;
        }
    }
};

MemBtree(BtreeConfig& cfg) : Btree(update_node_area_size(cfg)) {
    Btree< K, V >::create_store_common(btree_store_type::MEM, []() { return std::make_shared< MemBtreeCommon >(); });
}
#endif

template < typename K, typename V >
class MemBtree : public Btree< K, V > {
public:
    MemBtree(const BtreeConfig& cfg) : Btree< K, V >(cfg) {
        BT_LOG(INFO, "New {} being created: Node size {}", btree_store_type(), cfg.node_size());
    }

    virtual ~MemBtree() {
        const auto [ret, free_node_cnt] = this->destroy_btree(nullptr);
        BT_LOG_ASSERT_EQ(ret, btree_status_t::success, "btree destroy failed");
    }

    std::string btree_store_type() const override { return "MEM_BTREE"; }

private:
    BtreeNodePtr< K > alloc_node(bool is_leaf) override {
        uint8_t* node_buf = new uint8_t[this->m_bt_cfg.node_size()];
        auto new_node = this->init_node(node_buf, bnodeid_t{0}, true, is_leaf);
        new_node->set_node_id(bnodeid_t{r_cast< std::uintptr_t >(new_node)});
        new_node->m_refcount.increment();
        return BtreeNodePtr< K >{new_node};
    }

    btree_status_t write_node_impl(const BtreeNodePtr< K >& bn, void* context) { return btree_status_t::success; }

    btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr< K >& node) const override {
        node = BtreeNodePtr< K >{r_cast< BtreeNode< K >* >(id)};
        return btree_status_t::success;
    }

    btree_status_t refresh_node(const BtreeNodePtr< K >& bn, bool for_read_modify_write, void* context) const override {
        return btree_status_t::success;
    }

    void free_node_impl(const BtreeNodePtr< K >& node, void* context) override {}

    btree_status_t prepare_node_txn(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node,
                                    void* context) override {
        return btree_status_t::success;
    }

    btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr< K >, 3 >& new_nodes,
                                        const BtreeNodePtr< K >& child_node, const BtreeNodePtr< K >& parent_node,
                                        void* context) override {
        for (const auto& node : new_nodes) {
            this->write_node(node, context);
        }
        this->write_node(child_node, context);
        this->write_node(parent_node, context);
        return btree_status_t::success;
    }

    /*void create_tree_precommit(const BtreeNodePtr< K >& root_node, void* op_context) override {}
    void split_node_precommit(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node1,
                              const BtreeNodePtr< K >& child_node2, bool root_split, bool edge_split,
                              void* context) override {}

    void merge_node_precommit(bool is_root_merge, const BtreeNodePtr< K >& parent_node, uint32_t parent_merge_start_idx,
                              const BtreeNodePtr< K >& child_node1,
                              const std::vector< BtreeNodePtr< K > >* old_child_nodes,
                              const std::vector< BtreeNodePtr< K > >* replace_child_nodes, void* op_context) override {}
  */
#if 0
    static void ref_node(MemBtreeNode* bn) {
        auto mbh = (mem_btree_node_header*)bn;
        LOGMSG_ASSERT_EQ(mbh->magic, 0xDEADBEEF, "Invalid Magic for Membtree node {}, Metrics {}", bn->to_string(),
                         sisl::MetricsFarm::getInstance().get_result_in_json_string());
        mbh->refcount.increment();
    }

    static void deref_node(MemBtreeNode* bn) {
        auto mbh = (mem_btree_node_header*)bn;
        LOGMSG_ASSERT_EQ(mbh->magic, 0xDEADBEEF, "Invalid Magic for Membtree node {}, Metrics {}", bn->to_string(),
                         sisl::MetricsFarm::getInstance().get_result_in_json_string());
        if (mbh->refcount.decrement_testz()) {
            mbh->magic = 0;
            bn->~MemBtreeNode();
            deallocate_mem((uint8_t*)bn);
        }
    }
#endif
};
} // namespace homestore
