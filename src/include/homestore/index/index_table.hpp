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

#include <vector>
#include <atomic>
#include <homestore/btree/btree.ipp>
#include <homestore/index/index_internal.hpp>
#include <homestore/superblk_handler.hpp>
#include <homestore/index_service.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include "checkpoint/cp.hpp"
#include "index/wb_cache.hpp"

namespace homestore {

template < typename K, typename V >
class IndexTable : public IndexTableBase, public Btree< K, V > {
private:
    superblk< index_table_sb > m_sb;

public:
    IndexTable(uuid_t uuid, uuid_t parent_uuid, uint32_t user_sb_size, const BtreeConfig& cfg,
               on_kv_read_t read_cb = nullptr, on_kv_update_t update_cb = nullptr, on_kv_remove_t remove_cb = nullptr) :
            Btree< K, V >{cfg, std::move(read_cb), std::move(update_cb), std::move(remove_cb)}, m_sb{"index"} {
        m_sb.create(sizeof(index_table_sb));
        m_sb->uuid = uuid;
        m_sb->parent_uuid = parent_uuid;
        m_sb->user_sb_size = user_sb_size;

        auto status = init();
        if (status != btree_status_t::success) { throw std::runtime_error(fmt::format("Unable to create root node")); }
    }

    IndexTable(const superblk< index_table_sb >& sb, const BtreeConfig& cfg, on_kv_read_t read_cb = nullptr,
               on_kv_update_t update_cb = nullptr, on_kv_remove_t remove_cb = nullptr) :
            Btree< K, V >{cfg, std::move(read_cb), std::move(update_cb), std::move(remove_cb)} {
        m_sb = sb;
        Btree< K, V >::set_root_node_info(BtreeLinkInfo{m_sb->root_node, m_sb->link_version});
    }

    btree_status_t init() {
        auto cp = hs()->cp_mgr().cp_guard();
        auto ret = Btree< K, V >::init((void*)cp->context(cp_consumer_t::INDEX_SVC));
        m_sb->root_node = Btree< K, V >::root_node_id();
        m_sb->link_version = Btree< K, V >::root_link_version();
        m_sb.write();
        return ret;
    }

    uuid_t uuid() const override { return m_sb->uuid; }
    uint64_t used_size() const override { return m_sb->index_size; }
    superblk< index_table_sb >& mutable_super_blk() { return m_sb; }
    const superblk< index_table_sb >& mutable_super_blk() const { return m_sb; }
    std::string btree_store_type() const override { return "INDEX_BTREE"; }

    template < typename ReqT >
    btree_status_t put(ReqT& put_req) {
        auto cpg = hs()->cp_mgr().cp_guard();
        put_req.m_op_context = (void*)cpg->context(cp_consumer_t::INDEX_SVC);
        return Btree< K, V >::put(put_req);
    }

    template < typename ReqT >
    btree_status_t remove(ReqT& remove_req) {
        auto cpg = hs()->cp_mgr().cp_guard();
        remove_req.m_op_context = (void*)cpg->context(cp_consumer_t::INDEX_SVC);
        return Btree< K, V >::remove(remove_req);
    }

protected:
    ////////////////// Override Implementation of underlying store requirements //////////////////
    BtreeNodePtr alloc_node(bool is_leaf) override {
        return wb_cache().alloc_buf([this, is_leaf](const IndexBufferPtr& idx_buf) -> BtreeNodePtr {
            BtreeNode* n = this->init_node(idx_buf->raw_buffer(), sizeof(IndexBtreeNode), idx_buf->blkid().to_integer(),
                                           true, is_leaf);
            uint8_t* ctx_mem = uintptr_cast(IndexBtreeNode::convert(n));
            new (ctx_mem) IndexBtreeNode(idx_buf); // TODO: Figure out a way to call destructor of IndexBtreeNode
            return BtreeNodePtr{n};
        });
    }

    void realloc_node(const BtreeNodePtr& node) const {
        wb_cache().realloc_buf(IndexBtreeNode::convert(node.get())->m_idx_buf);
    }

    btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) override {
        auto cp_ctx = r_cast< CPContext* >(context);
        auto idx_node = IndexBtreeNode::convert(node.get());

        if (idx_node->m_last_mod_cp_id != cp_ctx->id()) {
            // Need to put it in wb cache
            wb_cache().write_buf(node, idx_node->m_idx_buf, cp_ctx);
            idx_node->m_last_mod_cp_id = cp_ctx->id();
        }
        node->set_checksum(this->m_bt_cfg);
        return btree_status_t::success;
    }

    btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr, 3 >& new_nodes,
                                        const BtreeNodePtr& child_node, const BtreeNodePtr& parent_node,
                                        void* context) override {
        CPContext* cp_ctx = r_cast< CPContext* >(context);
        auto child_idx_node = IndexBtreeNode::convert(child_node.get());
        auto parent_idx_node = IndexBtreeNode::convert(parent_node.get());
        auto& child_buf = child_idx_node->m_idx_buf;
        auto& parent_buf = parent_idx_node->m_idx_buf;

        // TODO
        // BT_DBG_ASSERT_NE((void*)child_buf.m_cur_txn, nullptr,
        //                  "transact_write_nodes called without prepare transaction");

        // Write new nodes in the list as standalone outside transacted pairs.
        for (const auto& node : new_nodes) {
            write_node_impl(node, context);
            auto n = IndexBtreeNode::convert(node.get());
            wb_cache().prepend_to_chain(n->m_idx_buf, child_buf);
        }

        write_node_impl(child_node, context);
        write_node_impl(parent_node, context);

        return btree_status_t::success;
    }

    btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr& node) const override {
        try {
            wb_cache().read_buf(id, node, [this](const IndexBufferPtr& idx_buf) mutable -> BtreeNodePtr {
                bool is_leaf = BtreeNode::identify_leaf_node(idx_buf->raw_buffer());
                BtreeNode* n = this->init_node(idx_buf->raw_buffer(), sizeof(IndexBtreeNode),
                                               idx_buf->blkid().to_integer(), false /* init_buf */, is_leaf);
                uint8_t* ctx_mem = uintptr_cast(IndexBtreeNode::convert(n));
                new (ctx_mem) IndexBtreeNode(idx_buf); // TODO: Figure out a way to call destructor of IndexBtreeNode]2
                return BtreeNodePtr{n};
            });
            return btree_status_t::success;
        } catch (std::exception& e) { return btree_status_t::read_failed; }
    }

    btree_status_t refresh_node(const BtreeNodePtr& node, bool for_read_modify_write, void* context) const override {
        CPContext* cp_ctx = (CPContext*)context;

        auto idx_node = IndexBtreeNode::convert(node.get());
        if (!for_read_modify_write) {
            return btree_status_t::success;
        } else if (idx_node->m_last_mod_cp_id > cp_ctx->id()) {
            return btree_status_t::cp_mismatch;
        } else if (idx_node->m_last_mod_cp_id == cp_ctx->id()) {
            // modifying the buffer multiple times in a same cp
            return btree_status_t::success;
        }

        // TODO
        //        if (cp_ctx->is_recovery_cp()) {
        // If this refresh is part of cp taken during recovery, we need to realloc all nodes that are being
        // modified, which sets the btree blkid
        // realloc_node(node);
        //        }

        // If the backing buffer is already in a clean state, we don't need to make a copy of it
        if (idx_node->m_idx_buf->is_clean()) { return btree_status_t::success; }

        // Make a new btree buffer and copy the contents and swap it to make it the current node's buffer. The
        // buffer prior to this copy, would have been written and already added into the dirty buffer list.
        idx_node->m_idx_buf = wb_cache().copy_buffer(idx_node->m_idx_buf);
        node->m_phys_node_buf = idx_node->m_idx_buf->raw_buffer();

#ifndef NO_CHECKSUM
        if (!node->verify_node(this->m_bt_cfg)) {
            LOGERROR("CRC Mismatch for node: {} after refreshing the cache", node->to_string());
            return btree_status_t::crc_mismatch;
        }
#endif
        return btree_status_t::success;
    }

    btree_status_t prepare_node_txn(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                    void* context) override {
        CPContext* cp_ctx = (CPContext*)context;
        auto child_idx_node = IndexBtreeNode::convert(child_node.get());
        auto parent_idx_node = IndexBtreeNode::convert(parent_node.get());

        // Buffer has been modified by higher cp id than whats requested.
        if ((child_idx_node->m_last_mod_cp_id > cp_ctx->id()) || (parent_idx_node->m_last_mod_cp_id > cp_ctx->id())) {
            // We don't expect this condition because prepare_node_txn should be called only after individual nodes are
            // refreshed and read
            BT_DBG_ASSERT(
                false, "prepare_node_txn facing cp id mismatch, perhaps it was called without refreshing node first?");
            return btree_status_t::cp_mismatch;
        }

        auto& child_buf = child_idx_node->m_idx_buf;
        auto& parent_buf = parent_idx_node->m_idx_buf;
        // BT_DBG_ASSERT(child_buf->is_clean(), "Child buffer is not clean, refresh node was not called before?");
        // BT_DBG_ASSERT(parent_buf->is_clean(), "Parent buffer is not clean, refresh node was not called before?");

        wb_cache().create_chain(child_buf, parent_buf);
        return btree_status_t::success;
    }

    void free_node_impl(const BtreeNodePtr& node, void* context) override {
        auto n = IndexBtreeNode::convert(node.get());
        wb_cache().free_buf(n->m_idx_buf, r_cast< CPContext* >(context));
    }
};

} // namespace homestore
