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
#include <homestore/index/wb_cache_base.hpp>

SISL_LOGGING_DECL(wbcache)

namespace homestore {

template < typename K, typename V >
class IndexTable : public IndexTableBase, public Btree< K, V > {
private:
    superblk< index_table_sb > m_sb;

public:
    IndexTable(uuid_t uuid, uuid_t parent_uuid, uint32_t user_sb_size, const BtreeConfig& cfg) :
            Btree< K, V >{cfg}, m_sb{"index"} {
        m_sb.create(sizeof(index_table_sb));
        m_sb->uuid = uuid;
        m_sb->parent_uuid = parent_uuid;
        m_sb->user_sb_size = user_sb_size;

        auto status = init();
        if (status != btree_status_t::success) { throw std::runtime_error(fmt::format("Unable to create root node")); }
    }

    IndexTable(const superblk< index_table_sb >& sb, const BtreeConfig& cfg) : Btree< K, V >{cfg} {
        m_sb = sb;
        Btree< K, V >::set_root_node_info(BtreeLinkInfo{m_sb->root_node, m_sb->link_version});
    }

    void destroy() override {
        auto cpg = hs()->cp_mgr().cp_guard();
        auto op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
        Btree< K, V >::destroy_btree(op_context);
    }

    btree_status_t init() {
        auto cp = hs()->cp_mgr().cp_guard();
        auto ret = Btree< K, V >::init((void*)cp.context(cp_consumer_t::INDEX_SVC));
        update_new_root_info(Btree< K, V >::root_node_id(), Btree< K, V >::root_link_version());
        return ret;
    }

    uuid_t uuid() const override { return m_sb->uuid; }
    uint64_t used_size() const override { return m_sb->index_size; }
    superblk< index_table_sb >& mutable_super_blk() { return m_sb; }
    const superblk< index_table_sb >& mutable_super_blk() const { return m_sb; }
    std::string btree_store_type() const override { return "INDEX_BTREE"; }

    void update_new_root_info(bnodeid_t root_node, uint64_t version) override {
        m_sb->root_node = root_node;
        m_sb->link_version = version;
        m_sb.write();
        BT_LOG(DEBUG, "Updated index superblk root bnode_id {} version {}", root_node, version);
    }

    template < typename ReqT >
    btree_status_t put(ReqT& put_req) {
        auto cpg = hs()->cp_mgr().cp_guard();
        put_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
        return Btree< K, V >::put(put_req);
    }

    template < typename ReqT >
    btree_status_t remove(ReqT& remove_req) {
        auto cpg = hs()->cp_mgr().cp_guard();
        remove_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
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
            LOGTRACEMOD(wbcache, "{}", idx_node->m_idx_buf->to_string());
        }
        node->set_checksum(this->m_bt_cfg);
        return btree_status_t::success;
    }

    btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr, 3 >& new_nodes,
                                        const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                        void* context) override {
        CPContext* cp_ctx = r_cast< CPContext* >(context);
        auto left_child_idx_node = IndexBtreeNode::convert(left_child_node.get());
        auto parent_idx_node = IndexBtreeNode::convert(parent_node.get());
        auto& left_child_buf = left_child_idx_node->m_idx_buf;
        auto& parent_buf = parent_idx_node->m_idx_buf;

        LOGTRACEMOD(wbcache, "left {} parent {} ", left_child_buf->to_string(), parent_buf->to_string());

        // Write new nodes in the list as standalone outside transacted pairs.
        // Write the new right child nodes, left node and parent in order.
        for (const auto& right_child_node : new_nodes) {
            auto right_child = IndexBtreeNode::convert(right_child_node.get());
            write_node_impl(right_child_node, context);
            wb_cache().prepend_to_chain(right_child->m_idx_buf, left_child_buf);
            LOGTRACEMOD(wbcache, "right {} left {} ", right_child->m_idx_buf->to_string(), left_child_buf->to_string());
        }

        write_node_impl(left_child_node, context);
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
        } catch (std::exception& e) { return btree_status_t::node_read_failed; }
    }

    btree_status_t refresh_node(const BtreeNodePtr& node, bool for_read_modify_write, void* context) const override {
        CPContext* cp_ctx = (CPContext*)context;
        if (cp_ctx == nullptr) { return btree_status_t::success; }

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
        // if (cp_ctx->is_recovery_cp()) {
        //     // If this refresh is part of cp taken during recovery, we need to realloc all nodes that are being
        //     // modified, which sets the btree blkid
        //     realloc_node(node);
        // }

        // If the backing buffer is already in a clean state, we don't need to make a copy of it
        if (idx_node->m_idx_buf->is_clean()) { return btree_status_t::success; }

        // Make a new btree buffer and copy the contents and swap it to make it the current node's buffer. The
        // buffer prior to this copy, would have been written and already added into the dirty buffer list.
        idx_node->m_idx_buf = wb_cache().copy_buffer(idx_node->m_idx_buf);
        idx_node->m_last_mod_cp_id = -1;

        node->m_phys_node_buf = idx_node->m_idx_buf->raw_buffer();
        node->set_checksum(this->m_bt_cfg);

        LOGTRACEMOD(wbcache, "buf {} ", idx_node->m_idx_buf->to_string());

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

        auto [child_copied, parent_copied] = wb_cache().create_chain(child_buf, parent_buf, cp_ctx);
        if (child_copied) {
            child_node->m_phys_node_buf = child_buf->raw_buffer();
            child_idx_node->m_last_mod_cp_id = -1;
        }
        if (parent_copied) {
            parent_node->m_phys_node_buf = parent_buf->raw_buffer();
            parent_idx_node->m_last_mod_cp_id = -1;
        }

        LOGTRACEMOD(wbcache, "child {} parent {} ", child_buf->to_string(), parent_buf->to_string());
        return btree_status_t::success;
    }

    void free_node_impl(const BtreeNodePtr& node, void* context) override {
        auto n = IndexBtreeNode::convert(node.get());
        wb_cache().free_buf(n->m_idx_buf, r_cast< CPContext* >(context));
        n->~IndexBtreeNode();
    }
};

} // namespace homestore
