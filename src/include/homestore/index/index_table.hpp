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
#include <homestore/index/index_internal.hpp>
#include <homestore/btree/btree.ipp>
#include <homestore/superblk_handler.hpp>
#include <homestore/index_service.hpp>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/index/wb_cache_base.hpp>
#include <homestore/btree/detail/btree_internal.hpp>
#include <iomgr/iomgr_flip.hpp>

SISL_LOGGING_DECL(wbcache)

namespace homestore {

template < typename K, typename V >
class IndexTable : public IndexTableBase, public Btree< K, V > {
private:
    superblk< index_table_sb > m_sb;
    shared< MetaIndexBuffer > m_sb_buffer;

    // graceful shutdown
private:
    std::atomic_bool m_stopping{false};
    mutable std::atomic_uint64_t pending_request_num{0};

    bool is_stopping() const { return m_stopping.load(); }
    void start_stopping() { m_stopping = true; }

    uint64_t get_pending_request_num() const { return pending_request_num.load(); }

    void incr_pending_request_num() const { pending_request_num++; }
    void decr_pending_request_num() const { pending_request_num--; }

public:
    void stop() {
        start_stopping();
        while (true) {
            if (!get_pending_request_num()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }

    IndexTable(uuid_t uuid, uuid_t parent_uuid, uint32_t user_sb_size, const BtreeConfig& cfg) :
            Btree< K, V >{cfg}, m_sb{"index"} {
        // Create a superblk for the index table and create MetaIndexBuffer corresponding to that
        m_sb.create(sizeof(index_table_sb));
        m_sb->uuid = uuid;
        m_sb->ordinal = hs()->index_service().reserve_ordinal();
        m_sb->parent_uuid = parent_uuid;
        m_sb->user_sb_size = user_sb_size;
        m_sb.write();

        m_sb_buffer = std::make_shared< MetaIndexBuffer >(m_sb);

        // Create a root node which is a leaf node.
        auto cp = hs()->cp_mgr().cp_guard();
        auto const status = this->create_root_node((void*)cp.context(cp_consumer_t::INDEX_SVC));
        if (status != btree_status_t::success) { throw std::runtime_error(fmt::format("Unable to create root node")); }
    }

    IndexTable(superblk< index_table_sb >&& sb, const BtreeConfig& cfg) : Btree< K, V >{cfg}, m_sb{std::move(sb)} {
        m_sb_buffer = std::make_shared< MetaIndexBuffer >(m_sb);

        // After recovery, we see that root node is empty, which means that after btree is created, we crashed.
        // So create new root node, which is essential for btree to function.
        if (m_sb->root_node != empty_bnodeid) {
            this->set_root_node_info(BtreeLinkInfo{m_sb->root_node, m_sb->root_link_version});
        }
    }

    void recovery_completed() override {
        if (m_sb->root_node == empty_bnodeid) {
            // After recovery, we see that root node is empty, which means that after btree is created, we crashed.
            // So create new root node, which is essential for btree to function.
            auto cp = hs()->cp_mgr().cp_guard();
            auto const status = this->create_root_node((void*)cp.context(cp_consumer_t::INDEX_SVC));
            if (status != btree_status_t::success) {
                throw std::runtime_error(fmt::format("Unable to create root node"));
            }
        }
    }

    void audit_tree() override {
        cp_mgr().cp_guard();
        Btree< K, V >::sanity_sub_tree();
    }

    btree_status_t destroy() override {
        if (is_stopping()) return btree_status_t::stopping;
        incr_pending_request_num();
        auto cpg = cp_mgr().cp_guard();
        Btree< K, V >::destroy_btree(cpg.context(cp_consumer_t::INDEX_SVC));
        m_sb.destroy();
        m_sb_buffer->m_valid = false;
        decr_pending_request_num();
        return btree_status_t::success;
    }

    uuid_t uuid() const override { return m_sb->uuid; }
    uint32_t ordinal() const override { return m_sb->ordinal; }
    uint64_t used_size() const override { return m_sb->index_size; }
    superblk< index_table_sb >& mutable_super_blk() { return m_sb; }
    const superblk< index_table_sb >& mutable_super_blk() const { return m_sb; }
    std::string btree_store_type() const override { return "INDEX_BTREE"; }

    template < typename ReqT >
    btree_status_t put(ReqT& put_req) {
        if (is_stopping()) return btree_status_t::stopping;
        incr_pending_request_num();
        auto ret = btree_status_t::success;
        do {
            auto cpg = cp_mgr().cp_guard();
            put_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
            ret = Btree< K, V >::put(put_req);
            if (ret == btree_status_t::cp_mismatch) { LOGTRACEMOD(wbcache, "CP Mismatch, retrying put"); }
        } while (ret == btree_status_t::cp_mismatch);
        decr_pending_request_num();
        return ret;
    }

    template < typename ReqT >
    btree_status_t remove(ReqT& remove_req) {
        if (is_stopping()) return btree_status_t::stopping;
        incr_pending_request_num();
        auto ret = btree_status_t::success;
        do {
            auto cpg = cp_mgr().cp_guard();
            remove_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
            ret = Btree< K, V >::remove(remove_req);
            if (ret == btree_status_t::cp_mismatch) { LOGTRACEMOD(wbcache, "CP Mismatch, retrying remove"); }
        } while (ret == btree_status_t::cp_mismatch);
        decr_pending_request_num();
        return ret;
    }

    template < typename ReqT >
    btree_status_t get(ReqT& greq) const {
        if (is_stopping()) return btree_status_t::stopping;
        incr_pending_request_num();
        auto ret = Btree< K, V >::get(greq);
        decr_pending_request_num();
        return ret;
    }

    void repair_root_node(IndexBufferPtr const& idx_buf) override {
        LOGTRACEMOD(wbcache, "check if this was the previous root node {} for buf {} ", m_sb->root_node,
                    idx_buf->to_string());
        if (m_sb->root_node == idx_buf->blkid().to_integer()) {
            // This is the root node, we need to update the root node in superblk
            LOGTRACEMOD(wbcache, "{} is old root so we need to update the meta node ", idx_buf->to_string());
            BtreeNode* n = this->init_node(idx_buf->raw_buffer(), idx_buf->blkid().to_integer(), false /* init_buf */,
                                           BtreeNode::identify_leaf_node(idx_buf->raw_buffer()));
            static_cast< IndexBtreeNode* >(n)->attach_buf(idx_buf);
            auto edge_id = n->next_bnode();

            BT_DBG_ASSERT(!n->has_valid_edge(),
                          "root {} already has a valid edge {}, so we should have found the new root node",
                          n->to_string(), n->get_edge_value().bnode_id());
            n->set_next_bnode(empty_bnodeid);
            n->set_edge_value(BtreeLinkInfo{edge_id, 0});
            LOGTRACEMOD(wbcache, "change root node {}: edge updated to {} and invalidate the next node! ", n->node_id(),
                        edge_id);
            auto cpg = cp_mgr().cp_guard();
            write_node_impl(n, (void*)cpg.context(cp_consumer_t::INDEX_SVC));

        } else {
            LOGTRACEMOD(wbcache, "This is not the root node, so we can ignore this repair call for buf {}",
                        idx_buf->to_string());
        }
    }

    void delete_stale_children(IndexBufferPtr const& idx_buf) override {
        if (!idx_buf->is_meta_buf() && idx_buf->m_created_cp_id == -1) {
            BtreeNode* n = this->init_node(idx_buf->raw_buffer(), idx_buf->blkid().to_integer(), false /* init_buf */,
                                           BtreeNode::identify_leaf_node(idx_buf->raw_buffer()));
            static_cast< IndexBtreeNode* >(n)->attach_buf(idx_buf);
            auto cpg = cp_mgr().cp_guard();
            idx_buf->m_dirtied_cp_id = cpg->id();
            BtreeNodePtr bn = BtreeNodePtr{n};

            if (!bn->is_leaf()) {
                LOGTRACEMOD(wbcache, "delete_stale_links cp={} buf={}", cpg->id(), idx_buf->to_string());
                delete_stale_links(bn, (void*)cpg.context(cp_consumer_t::INDEX_SVC));
            }
        }
    }

    void repair_node(IndexBufferPtr const& idx_buf) override {
        if (idx_buf->is_meta_buf()) {
            // We cannot repair the meta buf on its own, we need to repair the root node which modifies the
            // meta_buf. It is ok to ignore this call, because repair will be done from root before meta_buf is
            // attempted to repair, which would have updated the meta_buf already.
            LOGTRACEMOD(wbcache, "Ignoring repair on meta buf {} root id {} ", idx_buf->to_string(),
                        this->root_node_id());
            return;
        }
        BtreeNode* n = this->init_node(idx_buf->raw_buffer(), idx_buf->blkid().to_integer(), false /* init_buf */,
                                       BtreeNode::identify_leaf_node(idx_buf->raw_buffer()));
        static_cast< IndexBtreeNode* >(n)->attach_buf(idx_buf);
        auto cpg = cp_mgr().cp_guard();

        // Set the cp_id to current cp buf, since repair doesn't call get_writable_buf (unlike regular IO path), so
        // we need to set it here, so that other code path assumes correct cp
        idx_buf->m_dirtied_cp_id = cpg->id();
        BtreeNodePtr bn = BtreeNodePtr{n};

        // Only for interior nodes we need to repair its links
        if (!bn->is_leaf()) {
            LOGTRACEMOD(wbcache, "repair_node cp={} buf={}", cpg->id(), idx_buf->to_string());
            repair_links(bn, (void*)cpg.context(cp_consumer_t::INDEX_SVC));
        }

        /*
        if (idx_buf->m_up_buffer && idx_buf->m_up_buffer->is_meta_buf()) {
            // Our up buffer is a meta buffer, which means that we are the new root node, we need to update the
            // meta_buf with new root as well
            LOGTRACEMOD(wbcache, "root change for after repairing {}\n\n", idx_buf->to_string());
            on_root_changed(bn, (void*)cpg.context(cp_consumer_t::INDEX_SVC));
        }
        */
    }

protected:
    ////////////////// Override Implementation of underlying store requirements //////////////////
    BtreeNodePtr alloc_node(bool is_leaf) override {
        return wb_cache().alloc_buf([this, is_leaf](const IndexBufferPtr& idx_buf) -> BtreeNodePtr {
            BtreeNode* n = this->init_node(idx_buf->raw_buffer(), idx_buf->blkid().to_integer(), true, is_leaf);
            static_cast< IndexBtreeNode* >(n)->attach_buf(idx_buf);
            return BtreeNodePtr{n};
        });
    }

    btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) override {
        auto cp_ctx = r_cast< CPContext* >(context);
        auto idx_node = static_cast< IndexBtreeNode* >(node.get());

        node->set_checksum();
        auto prev_state = idx_node->m_idx_buf->m_state.exchange(index_buf_state_t::DIRTY);
        idx_node->m_idx_buf->m_node_level = node->level();
        if (prev_state == index_buf_state_t::CLEAN) {
            // It was clean before, dirtying it first time, add it to the wb_cache list to flush
            if (idx_node->m_idx_buf->m_dirtied_cp_id != -1) {
                BT_DBG_ASSERT_EQ(idx_node->m_idx_buf->m_dirtied_cp_id, cp_ctx->id(),
                                 "Writing a node which was not acquired by this cp");
            }
            node->set_modified_cp_id(cp_ctx->id());
            wb_cache().write_buf(node, idx_node->m_idx_buf, cp_ctx);
        } else {
            BT_DBG_ASSERT_NE(
                (int)prev_state, (int)index_buf_state_t::FLUSHING,
                "Writing on a node buffer which was currently in flushing state on cur_cp={} buffer_cp_id={}",
                cp_ctx->id(), idx_node->m_idx_buf->m_dirtied_cp_id);
            BT_DBG_ASSERT_EQ(idx_node->m_idx_buf->m_dirtied_cp_id, cp_ctx->id(),
                             "Writing a node which was not acquired by this cp");
        }
        return btree_status_t::success;
    }

    btree_status_t transact_nodes(const BtreeNodeList& new_nodes, const BtreeNodeList& freed_nodes,
                                  const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                  void* context) override {
        CPContext* cp_ctx = r_cast< CPContext* >(context);

        IndexBufferPtrList new_node_bufs;
        for (const auto& right_child_node : new_nodes) {
            write_node_impl(right_child_node, context);
            new_node_bufs.push_back(s_cast< IndexBtreeNode* >(right_child_node.get())->m_idx_buf);
        }
        write_node_impl(left_child_node, context);
        // during recovery it is possible that there is no parent_node
        if (parent_node.get() != nullptr) { write_node_impl(parent_node, context); }

        IndexBufferPtrList freed_node_bufs;
        for (const auto& freed_node : freed_nodes) {
            freed_node_bufs.push_back(s_cast< IndexBtreeNode* >(freed_node.get())->m_idx_buf);
            this->free_node(freed_node, locktype_t::WRITE, context);
        }

        wb_cache().transact_bufs(
            ordinal(), parent_node.get() ? s_cast< IndexBtreeNode* >(parent_node.get())->m_idx_buf : nullptr,
            s_cast< IndexBtreeNode* >(left_child_node.get())->m_idx_buf, new_node_bufs, freed_node_bufs, cp_ctx);
        return btree_status_t::success;
    }

    btree_status_t read_node_impl(bnodeid_t id, BtreeNodePtr& node) const override {
        try {
            wb_cache().read_buf(id, node, [this](const IndexBufferPtr& idx_buf) mutable -> BtreeNodePtr {
                bool is_leaf = BtreeNode::identify_leaf_node(idx_buf->raw_buffer());
                BtreeNode* n = this->init_node(idx_buf->raw_buffer(), idx_buf->blkid().to_integer(),
                                               false /* init_buf */, is_leaf);
                static_cast< IndexBtreeNode* >(n)->attach_buf(idx_buf);
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
        auto n = static_cast< IndexBtreeNode* >(node.get());
        n->m_idx_buf->m_node_level = node->level();
        wb_cache().free_buf(n->m_idx_buf, r_cast< CPContext* >(context));
    }

    btree_status_t on_root_changed(BtreeNodePtr const& new_root, void* context) override {
        // todo: if(m_sb->root_node == new_root->node_id() && m_sb->root_link_version == new_root->link_version()){
        // return btree_status_t::success;}
        LOGTRACEMOD(wbcache, "root changed for index old_root={} new_root={}", m_sb->root_node, new_root->node_id());
        m_sb->root_node = new_root->node_id();
        m_sb->root_link_version = new_root->link_version();

        if (!wb_cache().refresh_meta_buf(m_sb_buffer, r_cast< CPContext* >(context))) {
            LOGTRACEMOD(wbcache, "CP mismatch error - discard transact for meta node");
            return btree_status_t::cp_mismatch;
        }

        auto& root_buf = static_cast< IndexBtreeNode* >(new_root.get())->m_idx_buf;
        wb_cache().transact_bufs(ordinal(), m_sb_buffer, root_buf, {}, {}, r_cast< CPContext* >(context));
        return btree_status_t::success;
    }

    btree_status_t delete_stale_links(BtreeNodePtr const& parent_node, void* cp_ctx) {
        LOGTRACEMOD(wbcache, "deleting stale links for parent node [{}]", parent_node->to_string());
        BtreeNodeList free_nodes;
        auto nentries = parent_node->total_entries();
        uint32_t deleted = 0;
        for (uint32_t i = nentries; i-- > 0;) {
            BtreeLinkInfo cur_child_info;
            BtreeNodePtr child_node;
            parent_node->get_nth_value(i, &cur_child_info, false /* copy */);
            if (auto ret = read_node_impl(cur_child_info.bnode_id(), child_node); ret == btree_status_t::success) {
                if (child_node->is_node_deleted()) {
                    LOGTRACEMOD(wbcache, "Deleting stale child node [{}] for parent node [{}]", child_node->to_string(),
                                parent_node->to_string());
                    child_node->set_node_deleted();
                    free_node_impl(child_node, cp_ctx);

                    if (i > 0) {
                        BtreeLinkInfo pre_child_info;
                        parent_node->get_nth_value(i - 1, &pre_child_info, false /* copy */);
                        //                        auto ckey = parent_node->get_nth_key< K >(i-1, true);
                        //                        parent_node->set_nth_key(i-1, ckey);
                        parent_node->update(i, pre_child_info);
                        parent_node->remove(i - 1);
                    } else {
                        parent_node->remove(i);
                    }

                    LOGTRACEMOD(wbcache, "so far parent node [{}]", parent_node->to_string());
                    // free_nodes.push_back(child_node);
                    deleted++;
                }
            } else {
                LOGTRACEMOD(wbcache, "Failed to read child node {} for parent node [{}] reason {}",
                            cur_child_info.bnode_id(), parent_node->to_string(), ret);
            }
        }
        if (parent_node->has_valid_edge()) {
            auto edge_info = parent_node->get_edge_value();
            BtreeNodePtr edge_node;
            if (auto ret = read_node_impl(edge_info.bnode_id(), edge_node); ret == btree_status_t::success) {
                if (edge_node->is_node_deleted()) {
                    LOGTRACEMOD(wbcache, "Deleting stale edge node [{}] for parent node [{}]", edge_node->to_string(),
                                parent_node->to_string());
                    edge_node->set_node_deleted();
                    free_node_impl(edge_node, cp_ctx);
                    if (parent_node->total_entries() == 0) {
                        parent_node->invalidate_edge();
                    } else {
                        BtreeLinkInfo last_child_info;
                        parent_node->get_nth_value(parent_node->total_entries() - 1, &last_child_info,
                                                   false /* copy */);
                        parent_node->set_edge_value(last_child_info);
                        parent_node->remove(parent_node->total_entries() - 1);
                        LOGTRACEMOD(wbcache, "Replacing edge with previous child node [{}] for parent node [{}]",
                                    last_child_info.bnode_id(), parent_node->to_string());
                    }

                    deleted++;
                }
            } else {
                LOGTRACEMOD(wbcache, "Failed to read edge node {} for parent node [{}] reason {}",
                            edge_node->to_string(), parent_node->to_string(), ret);
            }
        }
        if (deleted /*free_nodes.size()*/) {
            btree_status_t ret = btree_status_t::success;

            if ((parent_node->total_entries() == 0) && !parent_node->has_valid_edge()) {
                parent_node->set_node_deleted();
                LOGTRACEMOD(wbcache,
                            "Freeing parent node=[{}] because it is empty and not an edge node but had stale children",
                            parent_node->to_string());
                ret = write_node_impl(parent_node, cp_ctx);
                free_node_impl(parent_node, cp_ctx);
                LOGTRACEMOD(wbcache,
                            "Accomplishing deleting stale links. After removing {} stale links, parent node is [{}]",
                            deleted, parent_node->to_string());
            } else {
                ret = write_node_impl(parent_node, cp_ctx);
                if (ret != btree_status_t::success) {
                    LOGTRACEMOD(wbcache, "Failed to write parent node [{}] after deleting stale links",
                                parent_node->to_string());
                } else {
                    LOGTRACEMOD(
                        wbcache,
                        "Accomplishing deleting stale links. After removing {} stale links, parent node is [{}]",
                        deleted, parent_node->to_string());
                }
            }
            //            auto ret = transact_nodes({}, free_nodes, parent_node, nullptr, cp_ctx);
            return ret;
        } else {
            LOGTRACEMOD(wbcache, "Accomplishing deleting stale links. No stale links found for parent node [{}]",
                        parent_node->to_string());
        }
        return btree_status_t::success;
    }

    bnodeid_t true_sibling_first_child(BtreeNodePtr const& parent_node) {
        bnodeid_t sibling_first_child_id = empty_bnodeid;
        if (!parent_node->is_leaf() && !parent_node->has_valid_edge()) {
            BtreeNodePtr parent_right_sibling;
            if (auto parent_right_sibling_id = find_true_sibling(parent_node); parent_right_sibling_id != empty_bnodeid) {
                if (auto ret = read_node_impl(parent_right_sibling_id, parent_right_sibling); ret == btree_status_t::success) {
                    if (parent_right_sibling->total_entries() > 0) {
                        BtreeLinkInfo sibling_first_child_info;
                        parent_right_sibling->get_nth_value(0, &sibling_first_child_info, false);
                        sibling_first_child_id = sibling_first_child_info.bnode_id();
                    } else if (parent_right_sibling->has_valid_edge()) {
                        // If the right sibling has an edge, we can use that as the first child
                        sibling_first_child_id = parent_right_sibling->get_edge_value().bnode_id();
                    }
                }
            }
        }
        return sibling_first_child_id;
    }

    void update_root(BtreeNodePtr const& left_child,  BtreeNodeList& new_nodes, void* cp_ctx) {
        auto new_root = this->alloc_interior_node();
        if (new_root == nullptr) {
            return;
        }
        new_root->set_level(left_child->level() + 1);
        auto cur_child = left_child;
        uint32_t i = 0;
        LOGTRACEMOD(wbcache, "Updating new root node={}", new_root->to_string());
        do {
            LOGTRACEMOD(wbcache, "Processiog child {}", cur_child->to_string());
            if (cur_child->has_valid_edge()) {
                new_root->set_edge_value(BtreeLinkInfo{cur_child->node_id(), cur_child->link_version()});
            } else {
                auto child_last_key = cur_child->get_last_key< K >();
                new_root->insert(new_root->total_entries(), child_last_key,
                                   BtreeLinkInfo{cur_child->node_id(), cur_child->link_version()});
            }
            if (i == new_nodes.size()) { break; }
            auto next_child_id = cur_child->next_bnode();
            cur_child = new_nodes[i++];
            DEBUG_ASSERT_EQ(next_child_id, cur_child->node_id(),
                            "Next node id {} does not match current child node id {}", 
                            next_child_id, cur_child->node_id());
        } while (true);
       
        new_nodes.push_back(new_root);
        LOGTRACEMOD(wbcache, "New root node created {}", new_root->to_string());
        on_root_changed(new_root, cp_ctx);
        this->set_root_node_info(BtreeLinkInfo{new_root->node_id(), new_root->link_version()});
    }

    //
    btree_status_t repair_links(BtreeNodePtr const& parent_node, void* cp_ctx) {
        LOGTRACEMOD(wbcache, "Repairing links for parent node [{}]", parent_node->to_string());
        // TODO: is it possible that repairing many nodes causes an increase to level of btree? If so, then this
        // needs to be handled. Get the last key in the node

        auto last_parent_key = parent_node->get_last_key< K >();
        auto sibling_node_id = find_true_sibling(parent_node);
        auto const is_parent_edge_node = (sibling_node_id == empty_bnodeid);
        if ((parent_node->total_entries() == 0) && !is_parent_edge_node) {
            BT_LOG_ASSERT(false, "Parent node={} is empty and not an edge node but was asked to repair",
                          parent_node->node_id());
            return btree_status_t::not_found;
        }

        // Get all original child ids as a support to check if we are beyond the last child node
        std::unordered_map< bnodeid_t, K > orig_child_infos;
        for (uint32_t i = 0; i < parent_node->total_entries(); ++i) {
            BtreeLinkInfo link_info;
            parent_node->get_nth_value(i, &link_info, true);
            orig_child_infos[link_info.bnode_id()] = parent_node->get_nth_key< K >(i, false /* copy */);
            LOGTRACEMOD(wbcache, "Child node [{}] with key [{}] at index [{}]", link_info.bnode_id(),
                        orig_child_infos[link_info.bnode_id()].to_string(), i);
        }
        LOGTRACEMOD(wbcache, "Repairing node=[{}] with last_parent_key={}", parent_node->to_string(),
                    last_parent_key.to_string());

        // Get the first child node and its link info
        BtreeLinkInfo child_info;
        BtreeNodePtr child_node;
        BtreeNodePtr pre_child_node;
        auto ret = this->get_child_and_lock_node(parent_node, 0, child_info, child_node, locktype_t::READ,
                                                 locktype_t::READ, cp_ctx);
        if (ret != btree_status_t::success) {
            BT_LOG_ASSERT(false, "Parent node={} repair failed, because first child_node get has failed with ret={}",
                          parent_node->node_id(), enum_name(ret));
            return ret;
        }

        // update the last key of parent for issue
        // 1- last key is X for parent (P)
        // 2- check the non deleted last child (A) last key  (here is Y)
        // start from first child and store the last key of the child node, then traverse to next sibling
        //        2-1- if this is greater than parent last key, traverse for sibling of parent until reaches to
        // siblings which has keys more than Y or end of list (name this parent sibling node F),
        //        2-2- Put last key of F to last key of P
        //        2-3 - set F as Next of A
        BtreeNodePtr next_cur_child;
        BT_DBG_ASSERT(parent_node->has_valid_edge() || parent_node->total_entries(),
                      "parent node {} doesn't have valid edge and no entries ", parent_node->to_string());
        if (parent_node->total_entries() > 0) {
            K last_child_last_key;
            K last_child_neighbor_key;
            BtreeNodePtr cur_child = child_node;

            // We find the last child node by starting from the leftmost child and traversing through the
            // next_bnode links until we reach the end or find a sibling first child.
            bool found_child = false;
            auto sibling_first_child = true_sibling_first_child(parent_node);
            LOGTRACEMOD(wbcache, "Sibling first child id is {}", sibling_first_child);
            while (cur_child != nullptr) {
                LOGTRACEMOD(wbcache, "Processing child node [{}]", cur_child->to_string());
                if (!cur_child->is_node_deleted() && cur_child->total_entries() > 0) {
                    last_child_last_key = cur_child->get_last_key< K >();
                    found_child = true;
                }
                
                next_cur_child = nullptr;
                if(cur_child->next_bnode() == empty_bnodeid || 
                   read_node_impl(cur_child->next_bnode(), next_cur_child) != btree_status_t::success) {
                    break; // No next child, so we can stop here
                }
                
                if (sibling_first_child != empty_bnodeid && sibling_first_child == cur_child->next_bnode()) {
                    LOGTRACEMOD(
                        wbcache,
                        "Last child last key {} for child_node [{}] parent node [{}],  next neigbor is [{}]",
                        last_child_last_key.to_string(), cur_child->to_string(), parent_node->to_string(),
                        next_cur_child->to_string());
                    break;
                }
                cur_child = next_cur_child;
            }

            // If we found a valid last child node, we adjust the parent_last_key by comparing it with the last
            // child last key.
            if (found_child) {
                LOGTRACEMOD(wbcache, "Last child last key {} for parent node {}, child_node {}",
                            last_child_last_key.to_string(), parent_node->to_string(), cur_child->to_string());
                if (last_child_last_key.compare(last_parent_key) > 0) {
                    if (next_cur_child) {
                        last_child_neighbor_key = next_cur_child->get_last_key< K >();
                        LOGTRACEMOD(wbcache,
                                    "Voila !! last child_key of child [{}] is greater than its parents [{}] and its "
                                    "next neighbor key is {}",
                                    cur_child->to_string(), parent_node->to_string(),
                                    last_child_neighbor_key.to_string());
                    } else {
                        LOGTRACEMOD(
                            wbcache,
                            "Last child_key of child [{}] is greater than its parents [{}] and it has no next neighbor",
                            cur_child->to_string(), parent_node->to_string());
                    }

                    // 2-1 traverse for sibling of parent until reaches to siblings which has keys more than 7563
                    //                        or end
                    // of list (put all siblings in a list, here is F) ,
                    BtreeNodePtr true_sibling;
                    if (sibling_node_id != empty_bnodeid &&
                        read_node_impl(sibling_node_id, true_sibling) == btree_status_t::success) {
                        last_parent_key = last_child_last_key;
                        parent_node->set_next_bnode(true_sibling->node_id());
                        LOGTRACEMOD(wbcache, "True sibling [{}] for parent_node {}", true_sibling->to_string(),
                                parent_node->to_string());
                    }
                    if (!true_sibling) {
                        LOGTRACEMOD(wbcache, "No true sibling found for parent_node [{}]", parent_node->to_string());
                    }
                } else {
                    LOGTRACEMOD(wbcache,
                                "No undeleted child found for parent_node [{}], keep normal repair (regular recovery)",
                                parent_node->to_string());
                    next_cur_child = nullptr;
                }
            }
        }
        
        // Keep a copy of the node buffer, in case we need to revert back
        uint8_t* tmp_buffer = new uint8_t[this->m_node_size];
        std::memcpy(tmp_buffer, parent_node->m_phys_node_buf, this->m_node_size);

        // Remove all the entries in parent_node and let walk across child_nodes rebuild this node
        parent_node->remove_all(this->m_bt_cfg);

        // Walk across all child nodes until it gets the last_parent_key and keep fixing them.
        auto cur_parent = parent_node;
        BtreeNodeList new_parent_nodes;
        do {
            if (child_node->has_valid_edge() || (child_node->is_leaf() && child_node->next_bnode() == empty_bnodeid)) {
                LOGTRACEMOD(wbcache, "Child node [{}] is an edge node or a leaf with no next, so we can stop here",
                            child_node->to_string());
                if (child_node->is_node_deleted()) {
                    // Edge node is merged, we need to set the current last entry as edge
                    if (cur_parent->total_entries() > 0) {
                        auto prev_val = V{};
                        cur_parent->get_nth_value(cur_parent->total_entries() - 1, &prev_val, true);
                        cur_parent->remove(cur_parent->total_entries() - 1);
                        cur_parent->set_edge_value(prev_val);
                        LOGTRACEMOD(wbcache,
                                    "Reparing node={}, child_node=[{}] is deleted, set previous as edge_value={}",
                                    cur_parent->node_id(), child_node->to_string(), prev_val.to_string());
                    } else {
                        LOGTRACEMOD(wbcache, "Found an empty interior node {} with maybe all childs deleted",
                                    cur_parent->node_id());
                    }
                } else {
                    // Update edge and finish
                    if (is_parent_edge_node) {
                        cur_parent->set_next_bnode(empty_bnodeid);
                        cur_parent->set_edge_value(BtreeLinkInfo{child_node->node_id(), child_node->link_version()});
                    } else {
                        if (sibling_node_id != empty_bnodeid) {
                            cur_parent->set_next_bnode(sibling_node_id);
                            LOGTRACEMOD(wbcache,
                                        "True sibling [{}] for parent_node [{}], So don't add child [{}] here ",
                                        sibling_node_id, cur_parent->to_string(), child_node->to_string());
                        } else {
                            cur_parent->set_next_bnode(empty_bnodeid);
                            // if this child node previously belonged to this parent node, we need to add it but as edge
                            // o.w, not this node
                            if (orig_child_infos.contains(child_node->node_id())) {
                                cur_parent->set_edge_value(
                                    BtreeLinkInfo{child_node->node_id(), child_node->link_version()});
                                LOGTRACEMOD(wbcache,
                                            "Child node [{}] is an edge node and previously belong to this parent, so "
                                            "we need to add it as edge",
                                            child_node->to_string());
                            } else {
                                LOGTRACEMOD(wbcache, "No true sibling found for parent_node [{}]",
                                            cur_parent->to_string());
                            }
                            BT_REL_ASSERT(cur_parent->total_entries() != 0 || cur_parent->has_valid_edge(),
                                          "Parent node [{}] cannot be empty", cur_parent->to_string());
                        }
                    }

                    //
                    //                        }
                    break;
                }
                break;
            }

            auto child_last_key = child_node->get_last_key< K >();
            LOGTRACEMOD(wbcache, "Repairing node={}, child_node=[{}] child_last_key={}", cur_parent->node_id(),
                        child_node->to_string(), child_last_key.to_string());

            // Check if we are beyond the last child node.
            //
            // There can be cases where the child level merge is successfully persisted but the parent level is
            // not. In this case, you may have your rightmost child node with last key greater than the
            // last_parent_key. That's why here we have to check if the child node is one of the original child
            // nodes first.
            if (!is_parent_edge_node && !orig_child_infos.contains(child_node->node_id())) {
                LOGTRACEMOD(
                    wbcache,
                    "Child node [{}] is not one of the original child nodes, so we need to check if it is beyond the "
                    "last parent key {}",
                    child_node->to_string(), last_parent_key.to_string());
                if (child_last_key.compare(last_parent_key) > 0) {
                    // We have reached a child beyond this parent, we can stop now
                    // TODO this case if child last key is less than last parent key to update the parent node.
                    // this case can potentially break the btree for put and remove op.
                    break;
                }
                if (child_node->total_entries() == 0) {
                    // this child has no entries, but maybe in the middle of the parent node, we need to update the key
                    // of parent as previous one and go on
                    LOGTRACEMOD(wbcache,
                                "Reach to an empty child node {}, and this child doesn't belong to this parent; Hence "
                                "loop ends",
                                child_node->to_string());
                    // now update  the next of parent node by skipping all deleted siblings of this parent node
                    auto valid_sibling = cur_parent->next_bnode();
                    while (valid_sibling != empty_bnodeid) {
                        BtreeNodePtr sibling;
                        if (read_node_impl(valid_sibling, sibling) == btree_status_t::success) {
                            if (sibling->is_node_deleted()) {
                                valid_sibling = sibling->next_bnode();
                                continue;
                            }
                            // cur_parent->set_next_bnode(sibling->node_id());
                            break;
                        }
                        LOGTRACEMOD(wbcache, "Failed to read child node {} for parent node [{}] reason {}",
                                    valid_sibling, cur_parent->to_string(), ret);
                    }
                    if (valid_sibling != empty_bnodeid) {
                        cur_parent->set_next_bnode(valid_sibling);
                        LOGTRACEMOD(wbcache, "Repairing node={}, child_node=[{}] is an edge node, end loop",
                                    cur_parent->node_id(), child_node->to_string());

                    } else {
                        cur_parent->set_next_bnode(empty_bnodeid);
                        LOGTRACEMOD(wbcache, "Repairing node={}, child_node=[{}] is an edge node, end loop",
                                    cur_parent->node_id(), child_node->to_string());
                    }

                    break;
                }
            }

            if (!cur_parent->has_room_for_put(btree_put_type::INSERT, K::get_max_size(),
                                              BtreeLinkInfo::get_fixed_size())) {
                // No room in the parent_node, let us split the parent_node and continue
                LOGTRACEMOD(wbcache,
                            "Repairing node={}, child_node=[{}] has no room for put, so we need to split the parent "
                            "node", cur_parent->node_id(), child_node->to_string());
                auto new_parent = this->alloc_interior_node();
                if (new_parent == nullptr) {
                    ret = btree_status_t::space_not_avail;
                    break;
                }

                new_parent->set_next_bnode(cur_parent->next_bnode());
                cur_parent->set_next_bnode(new_parent->node_id());
                new_parent->set_level(cur_parent->level());
                cur_parent->inc_link_version();
                new_parent_nodes.push_back(new_parent);
                cur_parent = std::move(new_parent);
            }

            // Insert the last key of the child node into parent node
            if (!child_node->is_node_deleted()) {
                if (child_node->total_entries() == 0) {
                    if (orig_child_infos.contains(child_node->node_id())) {
                        child_last_key = orig_child_infos[child_node->node_id()];
                        LOGTRACEMOD(wbcache,
                                    "Reach to an empty child node [{}], but not the end of the parent node, so we need "
                                    "to update the key of parent node as original one {}",
                                    child_node->to_string(), child_last_key.to_string());
                    } else {
                        LOGTRACEMOD(wbcache,
                                    "Reach to an empty child node [{}] but not belonging to this parent (probably next "
                                    "parent sibling); Hence end loop",
                                    child_node->to_string());
                        break;
                    }
                }
                cur_parent->insert(cur_parent->total_entries(), child_last_key,
                                   BtreeLinkInfo{child_node->node_id(), child_node->link_version()});
            } else {
                // Node deleted indicates it's freed & no longer used during recovery
                LOGTRACEMOD(wbcache, "Repairing node={}, child node=[{}] is deleted, skipping the insert",
                            cur_parent->node_id(), child_node->to_string());
                if (pre_child_node) {
                    // We need to update the next of the previous child node to this child node

                    LOGTRACEMOD(wbcache,
                                "Repairing node={}, child_node=[{}] is deleted, set next of previous child node [{}] "
                                "to this child node [{}]",
                                cur_parent->node_id(), child_node->to_string(), pre_child_node->to_string(),
                                child_node->next_bnode());
                    pre_child_node->set_next_bnode(child_node->next_bnode());
                    // repairing the next of previous child node
                    // We need to set the state of the previous child node to clean, so that it can be flushed
                    IndexBtreeNode* idx_node = static_cast< IndexBtreeNode* >(pre_child_node.get());
                    idx_node->m_idx_buf->set_state(index_buf_state_t::CLEAN);
                    write_node_impl(pre_child_node, cp_ctx);
                    // update the key of last entry of the parent with the last key of deleted child
                    child_last_key = orig_child_infos[child_node->node_id()];
                    LOGTRACEMOD(wbcache, "updating parent [{}] current last key with {}", cur_parent->to_string(),
                                child_last_key.to_string());
                    // update it here to go to the next child node and unlock this node
                    LOGTRACEMOD(wbcache, "update the child node next to the next of previous child node");
                    child_node->set_next_bnode(child_node->next_bnode());
                }
            }

            LOGTRACEMOD(wbcache, "Repairing node={}, repaired so_far=[{}]", cur_parent->node_id(),
                        cur_parent->to_string());

            // Move to the next child node
            auto const next_node_id = child_node->next_bnode();
            this->unlock_node(child_node, locktype_t::READ);
            if (!child_node->is_node_deleted()) {
                // We need to free the child node
                pre_child_node = child_node;
            }
            if (next_node_id == empty_bnodeid) {
                // This can be a deleted edge node - only check if it is still valid
                if (!child_node->is_node_deleted()) {
                    BT_LOG_ASSERT(false,
                                  "Child node={} next_node_id is empty, while its not a edge node, parent_node={} "
                                  "repair is partial",
                                  child_node->node_id(), parent_node->node_id());
                    ret = btree_status_t::not_found;
                }
                child_node = nullptr;
                break;
            }
            if (next_cur_child && next_node_id == next_cur_child->node_id()) {
                // We are at the last child node, we can stop now
                LOGTRACEMOD(
                    wbcache,
                    "REACH Repairing node={}, child_node=[{}] is the true child of sibling parent; Hence, end loop",
                    child_node->node_id(), next_cur_child->to_string());
                child_node = nullptr;
                break;
            }
            ret = this->read_and_lock_node(next_node_id, child_node, locktype_t::READ, locktype_t::READ, cp_ctx);
            if (ret != btree_status_t::success) {
                BT_LOG_ASSERT(false, "Parent node={} repair is partial, because child_node get has failed with ret={}",
                              parent_node->node_id(), enum_name(ret));
                child_node = nullptr;
                break;
            }

        } while (true);

        if (child_node) { this->unlock_node(child_node, locktype_t::READ); }
        // if last parent has the key less than the last child key, then we need to update the parent node with
        // the last child key if it doesn't have edge.
        auto last_parent = parent_node;
        if (new_parent_nodes.size() > 0) { 
            last_parent = new_parent_nodes.back();
            // handle the case where we are splitting the root node
            if (m_sb->root_node == parent_node->node_id()) {
                update_root(parent_node, new_parent_nodes, cp_ctx);
            }
        }
        if (last_parent->total_entries() && !last_parent->has_valid_edge()) {
            if (last_parent->compare_nth_key(last_parent_key, last_parent->total_entries() - 1) < 0) {
                BtreeLinkInfo child_info;
                last_parent->get_nth_value(last_parent->total_entries() - 1, &child_info, false /* copy */);
                last_parent->update(last_parent->total_entries() - 1, last_parent_key, child_info);
                LOGTRACEMOD(wbcache, "Repairing parent node={} with last_parent_key={} and child_info={}",
                            last_parent->node_id(), last_parent_key.to_string(), child_info.to_string());
            }
            // if last key of children is less than the last key of parent, then we need to update the last key of non
            // interior child
            if (last_parent->level() > 1 && !last_parent->has_valid_edge()) {
                // read last child
                BtreeNodePtr last_child;
                BtreeLinkInfo child_info;
                auto total_entries = last_parent->total_entries();
                last_parent->get_nth_value(total_entries - 1, &child_info, false /* copy */);
                if (ret = read_node_impl(child_info.bnode_id(), last_child); ret == btree_status_t::success) {
                    // get last key of cur child
                    auto last_child_key = last_child->get_last_key< K >();
                    BtreeLinkInfo last_child_info;
                    last_child->get_nth_value(last_child->total_entries() - 1, &last_child_info, false /* copy*/);
                    if (last_parent->compare_nth_key(last_child_key, total_entries - 1) > 0) {
                        auto cur_child_st = last_child->to_string();
                        last_child->update(last_child->total_entries() - 1, last_parent_key, last_child_info);
                        LOGTRACEMOD(wbcache,
                                    "Updating interior child node={} with last_parent_key={} and child_info={}",
                                    cur_child_st, last_parent_key.to_string(), last_child_info.to_string());
                        write_node_impl(last_child, cp_ctx);
                    }
                }
            }
        }

        if (ret == btree_status_t::success) {
            // Make write_buf happy for the parent node in case of multiple write (stale repair and link repair)
            IndexBtreeNode* p_node = static_cast< IndexBtreeNode* >(parent_node.get());
            p_node->m_idx_buf->set_state(index_buf_state_t::CLEAN);
            ret = transact_nodes(new_parent_nodes, {}, parent_node, nullptr, cp_ctx);
        }

        if (ret != btree_status_t::success) {
            BT_LOG(ERROR, "An error occurred status={} during repair of parent_node={}, aborting the repair",
                   enum_name(ret), parent_node->node_id());
            std::memcpy(parent_node->m_phys_node_buf, tmp_buffer, this->m_bt_cfg.node_size());
        }

        delete[] tmp_buffer;
        return ret;
    }

    bnodeid_t find_true_sibling(BtreeNodePtr const& node) {
        if (node == nullptr) return empty_bnodeid;
        bnodeid_t sibling_id = node->next_bnode();
        if (sibling_id == empty_bnodeid) {
            return empty_bnodeid;
        } else {
            BtreeNodePtr sibling_node;
            if (read_node_impl(sibling_id, sibling_node) != btree_status_t::success) { 
                LOGTRACEMOD(wbcache, "Failed to read sibling node with id {}", sibling_id);
                return empty_bnodeid; 
            }

            if (sibling_node->is_node_deleted()) {
                LOGTRACEMOD(wbcache, "Sibling node [{}] is not the sibling for parent_node {}",
                            sibling_node->to_string(), node->to_string());
                return find_true_sibling(sibling_node);
            } else {
                return sibling_id;
            }
        }
        return sibling_id;
    }

    K get_last_true_child_key(BtreeNodePtr const& parent_node) {
        uint32_t nentries = parent_node->total_entries() + parent_node->has_valid_edge() ? 1 : 0;
        BtreeLinkInfo cur_child_info;
        BtreeNodePtr cur_child;
        for (uint32_t i = nentries; i-- > 0;) {
            parent_node->get_nth_value(i, &cur_child_info, false /* copy */);
            if (auto ret = read_node_impl(cur_child_info.bnode_id(), cur_child); ret == btree_status_t::success) {
                if (!cur_child->is_node_deleted()) {
                    if (cur_child->total_entries()) {
                        return cur_child->get_last_key< K >();
                    } else {
                        LOGTRACEMOD(wbcache, "Last valid child {} has no entries", cur_child->to_string());
                    }
                }
            }
        }
    }
};

} // namespace homestore
