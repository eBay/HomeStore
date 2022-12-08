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
    BtreeNodePtr alloc_node(bool is_leaf) override {
        uint8_t* node_buf = new uint8_t[this->m_bt_cfg.node_size()];
        auto new_node = this->init_node(node_buf, bnodeid_t{0}, true, is_leaf);
        new_node->set_node_id(bnodeid_t{r_cast< std::uintptr_t >(new_node)});
        new_node->m_refcount.increment();
        return BtreeNodePtr{new_node};
    }

    btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) { return btree_status_t::success; }

    btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr& node) const override {
        node = BtreeNodePtr{r_cast< BtreeNode* >(id)};
        return btree_status_t::success;
    }

    btree_status_t refresh_node(const BtreeNodePtr& node, bool for_read_modify_write, void* context) const override {
        return btree_status_t::success;
    }

    void free_node_impl(const BtreeNodePtr& node, void* context) override {}

    btree_status_t prepare_node_txn(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                    void* context) override {
        return btree_status_t::success;
    }

    btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr, 3 >& new_nodes,
                                        const BtreeNodePtr& child_node, const BtreeNodePtr& parent_node,
                                        void* context) override {
        for (const auto& node : new_nodes) {
            this->write_node(node, context);
        }
        this->write_node(child_node, context);
        this->write_node(parent_node, context);
        return btree_status_t::success;
    }

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
