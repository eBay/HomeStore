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

public:
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
        this->set_root_node_info(BtreeLinkInfo{m_sb->root_node, m_sb->root_link_version});
    }

    void destroy() override {
        Btree< K, V >::destroy_btree(nullptr);
        m_sb.destroy();
    }

    uuid_t uuid() const override { return m_sb->uuid; }
    uint32_t ordinal() const override { return m_sb->ordinal; }
    uint64_t used_size() const override { return m_sb->index_size; }
    superblk< index_table_sb >& mutable_super_blk() { return m_sb; }
    const superblk< index_table_sb >& mutable_super_blk() const { return m_sb; }
    std::string btree_store_type() const override { return "INDEX_BTREE"; }

    template < typename ReqT >
    btree_status_t put(ReqT& put_req) {
        auto ret = btree_status_t::success;
        do {
            auto cpg = cp_mgr().cp_guard();
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
            auto cpg = cp_mgr().cp_guard();
            remove_req.m_op_context = (void*)cpg.context(cp_consumer_t::INDEX_SVC);
            ret = Btree< K, V >::remove(remove_req);
            if (ret == btree_status_t::cp_mismatch) { LOGTRACEMOD(wbcache, "CP Mismatch, retrying remove"); }
        } while (ret == btree_status_t::cp_mismatch);
        return ret;
    }

    void repair_node(IndexBufferPtr const& idx_buf) override {
        BtreeNode* n = this->init_node(idx_buf->raw_buffer(), idx_buf->blkid().to_integer(), true,
                                       BtreeNode::identify_leaf_node(idx_buf->raw_buffer()));
        static_cast< IndexBtreeNode* >(n)->attach_buf(idx_buf);
        auto cpg = cp_mgr().cp_guard();
        repair_links(BtreeNodePtr{n}, (void*)cpg.context(cp_consumer_t::INDEX_SVC));
    }

    void repair_root(IndexBufferPtr const& root_buf) override {
        BtreeNode* n = this->init_node(root_buf->raw_buffer(), root_buf->blkid().to_integer(), true,
                                       BtreeNode::identify_leaf_node(root_buf->raw_buffer()));
        static_cast< IndexBtreeNode* >(n)->attach_buf(root_buf);
        auto cpg = cp_mgr().cp_guard();
        on_root_changed(n, (void*)cpg.context(cp_consumer_t::INDEX_SVC));
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

        auto prev_state = idx_node->m_idx_buf->m_state.exchange(index_buf_state_t::DIRTY);
        if (prev_state == index_buf_state_t::CLEAN) {
            // It was clean before, dirtying it first time, add it to the wb_cache list to flush
            BT_DBG_ASSERT_EQ(idx_node->m_idx_buf->m_dirtied_cp_id, cp_ctx->id(),
                             "Writing a node which was not acquired by this cp");
            wb_cache().write_buf(node, idx_node->m_idx_buf, cp_ctx);
            LOGTRACEMOD(wbcache, "add to dirty list cp {} {}", cp_ctx->id(), idx_node->m_idx_buf->to_string());
        } else {
            BT_DBG_ASSERT_NE(
                (int)prev_state, (int)index_buf_state_t::FLUSHING,
                "Writing on a node buffer which was currently in flushing state on cur_cp={} buffer_cp_id={}",
                cp_ctx->id(), idx_node->m_idx_buf->m_dirtied_cp_id)
        }
        node->set_checksum();
        node->set_modified_cp_id(cp_ctx->id());
        return btree_status_t::success;
    }

    btree_status_t transact_nodes(const BtreeNodeList& new_nodes, const BtreeNodeList& freed_nodes,
                                  const BtreeNodePtr& left_child_node, const BtreeNodePtr& parent_node,
                                  void* context) override {
        CPContext* cp_ctx = r_cast< CPContext* >(context);
        auto& left_child_buf = static_cast< IndexBtreeNode* >(left_child_node.get())->m_idx_buf;
        auto& parent_buf = static_cast< IndexBtreeNode* >(parent_node.get())->m_idx_buf;

        IndexBufferPtrList new_node_bufs;
        for (const auto& right_child_node : new_nodes) {
            write_node_impl(right_child_node, context);
            new_node_bufs.push_back(static_cast< IndexBtreeNode* >(right_child_node.get())->m_idx_buf);
        }
        write_node_impl(left_child_node, context);
        write_node_impl(parent_node, context);

        IndexBufferPtrList freed_node_bufs;
        for (const auto& freed_node : freed_nodes) {
            freed_node_bufs.push_back(static_cast< IndexBtreeNode* >(freed_node.get())->m_idx_buf);
            this->free_node(freed_node, locktype_t::WRITE, context);
        }

        wb_cache().transact_bufs(ordinal(), parent_buf, left_child_buf, new_node_bufs, freed_node_bufs, cp_ctx);
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
        wb_cache().free_buf(n->m_idx_buf, r_cast< CPContext* >(context));
    }

    btree_status_t on_root_changed(BtreeNodePtr const& new_root, void* context) override {
        m_sb->root_node = new_root->node_id();
        m_sb->root_link_version = new_root->link_version();

        if (!wb_cache().refresh_meta_buf(m_sb_buffer, r_cast< CPContext* >(context))) {
            return btree_status_t::cp_mismatch;
        }

        auto& root_buf = static_cast< IndexBtreeNode* >(new_root.get())->m_idx_buf;
        wb_cache().transact_bufs(ordinal(), m_sb_buffer, root_buf, {}, {}, r_cast< CPContext* >(context));
        return btree_status_t::success;
    }

    btree_status_t repair_links(BtreeNodePtr const& parent_node, void* cp_ctx) {
        BT_LOG(DEBUG, "Repairing links for parent node {}", parent_node->node_id());

        // Get the last key in the node
        auto const last_parent_key = parent_node->get_last_key< K >();
        auto const is_parent_edge_node = parent_node->has_valid_edge();
        if ((parent_node->total_entries() == 0) && !is_parent_edge_node) {
            BT_LOG_ASSERT(false, "Parent node={} is empty and not an edge node but was asked to repair",
                          parent_node->node_id());
            return btree_status_t::not_found;
        }

        // Get the first child node and its link info
        BtreeLinkInfo child_info;
        BtreeNodePtr child_node;
        auto ret = this->get_child_and_lock_node(parent_node, 0, child_info, child_node, locktype_t::READ,
                                                 locktype_t::READ, cp_ctx);
        if (ret != btree_status_t::success) {
            BT_LOG_ASSERT(false, "Parent node={} repair failed, because first child_node get has failed with ret={}",
                          parent_node->node_id(), enum_name(ret));
            return ret;
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
            if (child_node->has_valid_edge()) {
                BT_DBG_ASSERT(!is_parent_edge_node,
                              "Child node={} is an edge node but parent_node={} is not an edge node",
                              child_node->node_id(), parent_node->node_id());
                cur_parent->set_edge_value(BtreeLinkInfo{child_node->node_id(), child_node->link_version()});
                break;
            }

            auto const child_last_key = child_node->get_last_key< K >();
            if (child_last_key.compare(last_parent_key) > 0) {
                // We have reached the last key, we can stop now
                break;
            }

            if (!cur_parent->has_room_for_put(btree_put_type::INSERT, K::get_max_size(),
                                              BtreeLinkInfo::get_fixed_size())) {
                // No room in the parent_node, let us split the parent_node and continue
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
            cur_parent->insert(cur_parent->total_entries(), child_last_key,
                               BtreeLinkInfo{child_node->node_id(), child_node->link_version()});

            // Move to the next child node
            auto const next_node_id = child_node->next_bnode();
            if (next_node_id == empty_bnodeid) {
                BT_LOG_ASSERT(
                    false,
                    "Child node={} next_node_id is empty, while its not a edge node, parent_node={} repair is partial",
                    child_node->node_id(), parent_node->node_id());
                ret = btree_status_t::not_found;
                break;
            }

            ret = this->read_and_lock_node(next_node_id, child_node, locktype_t::READ, locktype_t::READ, cp_ctx);
            if (ret != btree_status_t::success) {
                BT_LOG_ASSERT(false, "Parent node={} repair is partial, because child_node get has failed with ret={}",
                              parent_node->node_id(), enum_name(ret));
                break;
            }
        } while (true);

        if (ret == btree_status_t::success) {
            ret = transact_nodes(new_parent_nodes, {}, parent_node, nullptr, cp_ctx);
        }

        if (ret != btree_status_t::success) {
            BT_LOG(DEBUG, "An error occurred status={} during repair of parent_node={}, aborting the repair",
                   enum_name(ret), parent_node->node_id());
            std::memcpy(parent_node->m_phys_node_buf, tmp_buffer, this->m_bt_cfg.node_size());
        }

        delete tmp_buffer;
        return ret;
    }
};

} // namespace homestore
