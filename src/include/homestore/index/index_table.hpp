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
#include <iomgr/iomgr_flip.hpp>

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
        if (status != btree_status_t::success) {
            throw std::runtime_error(fmt::format("Unable to create root/super node"));
        }
    }

    IndexTable(superblk< index_table_sb >&& sb, const BtreeConfig& cfg) : Btree< K, V >{cfg}, m_sb{std::move(sb)} {
        this->set_super_node_info(BtreeLinkInfo{m_sb->super_node, m_sb->super_link_version});
    }

    void destroy() override { Btree< K, V >::destroy_btree(nullptr); }

    btree_status_t init() {
        auto cp = hs()->cp_mgr().cp_guard();
        auto cp_context = (void*)cp->context(cp_consumer_t::INDEX_SVC);
        BtreeNodePtr root = Btree< K, V >::alloc_leaf_node();
        if (root == nullptr) { return btree_status_t::space_not_avail; }
        BtreeNodePtr super_node = Btree< K, V >::alloc_leaf_node();
        if (super_node == nullptr) {
            Btree< K, V >::free_node(root, locktype_t::NONE, cp_context);
            return btree_status_t::space_not_avail;
        }
        root->set_level(0u);

        auto ret = transact_write_nodes({}, root, super_node, cp_context);
        Btree< K, V >::set_root_node_info(BtreeLinkInfo{root->node_id(), root->link_version()});
        Btree< K, V >::set_super_node_info(BtreeLinkInfo{super_node->node_id(), super_node->link_version()});
        super_node->set_edge_value(root->link_info());
        LOGINFO("IndexTable::init root {} super {}", root->node_id(), super_node->node_id());
        update_super_info(super_node->node_id(), super_node->link_version());
        return ret;
    }

    uuid_t uuid() const override { return m_sb->uuid; }
    uint64_t used_size() const override { return m_sb->index_size; }
    superblk< index_table_sb >& mutable_super_blk() { return m_sb; }
    const superblk< index_table_sb >& mutable_super_blk() const { return m_sb; }
    std::string btree_store_type() const override { return "INDEX_BTREE"; }

    void retrieve_root_node() {
        auto super_node_id = this->super_node_id();
        //        this->m_btree_lock.lock_shared();
        //        btree_status_t ret;
        //        BtreeNodePtr root;
        //        BtreeNodePtr super_node;

        //        {
        //            auto cp = hs()->cp_mgr().cp_guard();
        //            auto cp_context = (void*)cp->context(cp_consumer_t::INDEX_SVC);
        LOGINFO("reading root node {}", super_node_id);
        //            ret = this->read_and_lock_node(super_node_id, super_node, locktype_t::READ, locktype_t::READ,
        //            cp_context);
        auto root_info = wb_cache().get_root(super_node_id);
        //        }
        //        if (ret == btree_status_t::success) {
        //            auto root_link_info = super_node->get_edge_value();
        //            this->set_root_node_info(root_link_info);
        //            this->unlock_node(super_node, locktype_t::READ);
        //        }
        //        this->m_btree_lock.unlock_shared();
        //        LOGINFO("retrieve::init root {} super {}", root->node_id(), super_node->node_id());
        this->set_root_node_info(BtreeLinkInfo::bnode_link_info{root_info.first, root_info.second});
        LOGINFO("retrieve::init root {}", root_info.first);
    }
    void update_super_info(bnodeid_t super_node, uint64_t version) override {
        m_sb->super_node = super_node;
        m_sb->super_link_version = version;
        m_sb.write();
        BT_LOG(DEBUG, "Updated index superblk super bnode_id {} version {}", super_node, version);
    }

    template < typename ReqT >
    btree_status_t put(ReqT& put_req) {
        auto ret = btree_status_t::success;
        do {
            auto cpg = hs()->cp_mgr().cp_guard();
            put_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
            ret = Btree< K, V >::put(put_req);
            if (ret == btree_status_t::cp_mismatch) { LOGTRACEMOD(wbcache, "CP Mismatch, retrying put"); }
        } while (ret == btree_status_t::cp_mismatch);
        return ret;
    }

    template < typename ReqT >
    btree_status_t remove(ReqT& remove_req) {
        auto ret = btree_status_t::success;
        do {
            auto cpg = hs()->cp_mgr().cp_guard();
            remove_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
            ret = Btree< K, V >::remove(remove_req);
            if (ret == btree_status_t::cp_mismatch) { LOGTRACEMOD(wbcache, "CP Mismatch, retrying remove"); }
        } while (ret == btree_status_t::cp_mismatch);
        return ret;
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

    btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) override {
        auto cp_ctx = r_cast< CPContext* >(context);
        auto idx_node = IndexBtreeNode::convert(node.get());

        auto prev_state = idx_node->m_idx_buf->m_state.exchange(index_buf_state_t::DIRTY);
        if (prev_state == index_buf_state_t::CLEAN) {
            // It was clean before, dirtying it first time, add it to the wb_cache list to flush
            HS_DBG_ASSERT_EQ(idx_node->m_idx_buf->m_dirtied_cp_id, cp_ctx->id(),
                             "Writing a node which was not acquired by this cp");
            wb_cache().write_buf(node, idx_node->m_idx_buf, cp_ctx);
            LOGTRACEMOD(wbcache, "add to dirty list cp {} {}", cp_ctx->id(), idx_node->m_idx_buf->to_string());
        } else {
            HS_DBG_ASSERT_NE(
                (int)prev_state, (int)index_buf_state_t::FLUSHING,
                "Writing on a node buffer which was currently in flushing state on cur_cp={} buffer_cp_id={}",
                cp_ctx->id(), idx_node->m_idx_buf->m_dirtied_cp_id)
        }
        node->set_checksum(this->m_bt_cfg);
        node->set_modified_cp_id(cp_ctx->id());
        return btree_status_t::success;
    }

    btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr, 3 >& new_nodes,
                                        const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                        void* context) override {
        CPContext* cp_ctx = r_cast< CPContext* >(context);
        auto& left_child_buf = IndexBtreeNode::convert(left_child_node.get())->m_idx_buf;
        auto& parent_buf = IndexBtreeNode::convert(parent_node.get())->m_idx_buf;

        for (const auto& right_child_node : new_nodes) {
            write_node_impl(right_child_node, context);
            wb_cache().link_buf(left_child_buf, IndexBtreeNode::convert(right_child_node.get())->m_idx_buf, cp_ctx);
        }
        wb_cache().link_buf(parent_buf, left_child_buf, cp_ctx);

        write_node_impl(left_child_node, context);
        write_node_impl(parent_node, context);

#ifdef _PRERELEASE
        if (iomgr_flip::instance()->test_flip("index_parent_non_root")) {
            if (parent_node->node_id() != this->root_node_id()) {
                index_service().wb_cache().add_to_crashing_buffers(parent_idx_node->m_idx_buf, "index_parent_non_root");
            }
        }
        if (iomgr_flip::instance()->test_flip("index_parent_root")) {
            if (parent_node->node_id() == this->root_node_id()) {
                LOGINFO("Adding parent to crashing buffers {} ", parent_node->node_id());
                index_service().wb_cache().add_to_crashing_buffers(left_child_idx_node->m_idx_buf, "index_parent_root");
            }
        }
#endif

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
        if (context == nullptr || !for_read_modify_write) { return btree_status_t::success; }
        return wb_cache().get_writable_buf(node, r_cast< CPContext* >(context)) ? btree_status_t::success
                                                                                : btree_status_t::cp_mismatch;
    }

    void free_node_impl(const BtreeNodePtr& node, void* context) override {
        auto n = IndexBtreeNode::convert(node.get());
        wb_cache().free_buf(n->m_idx_buf, r_cast< CPContext* >(context));
        n->~IndexBtreeNode();
    }
};

} // namespace homestore
