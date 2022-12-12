/*
 * homestore_btree.hpp
 *
 *  Created on: 04-11-2022
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <vector>
#include <atomic>
#include <homestore/btree/btree.ipp>
#include <homestore/index/index_internal.hpp>
#include <homestore/superblk_handler.hpp>
#include <homestore/index_service.hpp>
#include <homestore/index/wb_cache_base.hpp>

namespace homestore {

IndexBtreeNode* IndexBtreeNode::convert(const BtreeNodePtr& bt_node) {
    return (IndexBtreeNode*)((uint8_t*)bt_node.get() + sizeof(BtreeNode));
}

template < typename K, typename V >
class IndexTable : public IndexTableBase, Btree< K, V > {
private:
    superblk< index_table_sb > m_sb;
    std::function< void(BtreeRequest*, btee_status_t) > m_btree_op_comp_cb;

public:
    IndexTable(uuid_t uuid, const BtreeConfig& cfg, btree_op_comp_cb_t op_comp_cb, on_kv_read_t read_cb = nullptr,
               on_kv_update_t update_cb = nullptr, on_kv_remove_t remove_cb = nullptr) :
            Btree< K, V >{cfg, std::move(read_cb), std::move(update_cb), std::move(remove_cb)},
            m_btree_op_comp_cb{std::move(op_comp_cb)} {
        auto const [status, root_id] = create_root_node(nullptr);
        if (status != btree_status_t::success) {
            throw std::runtime_error(fmt::format("Unable to create root node", key_url));
        }
        m_sb.create(sizeof(index_table_sb));
        m_sb->uuid = uuid;
        m_sb->root_node = root_id;
    }

    IndexTable(const superblk< index_table_sb >& sb, const BtreeConfig& cfg, btree_op_comp_cb_t op_comp_cb,
               on_kv_read_t read_cb = nullptr, on_kv_update_t update_cb = nullptr, on_kv_remove_t remove_cb = nullptr) :
            Btree< K, V >{cfg, std::move(read_cb), std::move(update_cb), std::move(remove_cb)},
            m_btree_op_comp_cb{std::move(op_comp_cb)} {
        m_sb = sb;
    }

    uuid_t uuid() const override { return m_sb->uuid; }

    template < typename ReqT >
    void async_put(ReqT* put_req) override {
        iomanager.run_on(index_svc()->get_next_btree_write_thread(), [this, put_req](const io_thread_addr_t addr) {
            auto* cp = cp_manager()->cp_io_enter();
            put_req->op_context = (void*)cp_manager()->get_context(cp, cp_consumer_t::INDEX_SVC);
            auto ret = sisl::Btree< K, V >::put(*put_req);
            cp_manager()->cp_io_exit(cp);

            BT_DBG_ASSERT_NE(ret, btree_status_t::fast_path_not_possible, "Btree write thread is not fast path thread");
            m_btree_op_comp_cb(put_req, ret);
        });
    }

    template < typename ReqT >
    void async_remove(ReqT* remove_req) override {
        iomanager.run_on(index_svc()->get_next_btree_write_thread(), [this, remove_req](const io_thread_addr_t addr) {
            auto* cp = cp_manager()->cp_io_enter();
            remove_req->op_context = (void*)cp_manager()->get_context(cp, cp_consumer_t::INDEX_SVC);
            auto ret = sisl::Btree< K, V >::remove(*remove_req);
            cp_manager()->cp_io_exit(cp);

            BT_DBG_ASSERT_NE(ret, btree_status_t::fast_path_not_possible, "Btree write thread is not fast path thread");
            m_btree_op_comp_cb(remove_req, ret);
        });
    }

    template < typename ReqT >
    void async_get(ReqT* get_req) override {
        auto ret = sisl::Btree< K, V >::get(*get_req);
        if (ret == btree_status_t::fast_path_not_possible) {
            iomanager.run_on(index_svc()->get_next_btree_write_thread(), [this, get_req](const io_thread_addr_t addr) {
                auto ret = sisl::Btree< K, V >::get(*get_req);
                BT_DBG_ASSERT_NE(ret, btree_status_t::fast_path_not_possible,
                                 "Btree write thread is not fast path thread");
                m_btree_op_comp_cb(get_req, ret);
            });
        } else {
            m_btree_op_comp_cb(get_req, ret);
        }
    }

    template < typename ReqT >
    void async_query(ReqT* query_req) override {
        auto ret = sisl::Btree< K, V >::query(*query_req);
        if (ret == btree_status_t::fast_path_not_possible) {
            iomanager.run_on(index_svc()->get_next_btree_write_thread(), [this, get_req](const io_thread_addr_t addr) {
                auto ret = sisl::Btree< K, V >::query(*query_req);
                BT_DBG_ASSERT_NE(ret, btree_status_t::fast_path_not_possible,
                                 "Btree write thread is not fast path thread");
                m_btree_op_comp_cb(query_req, ret);
            });
        } else {
            m_btree_op_comp_cb(query_req, ret);
        }
    }

protected:
    ////////////////// Override Implementation of underlying store requirements //////////////////
    BtreeNodePtr alloc_node(bool is_leaf) override {
        return wb_cache()->alloc_buf([this](const IndexBufferPtr& idx_buf) -> BtreeNode {
            return this->init_node(idx_buf->raw_buffer(), sizeof(IndexBtreeNode), idx_buf->blkid().to_integer(), true,
                                   is_leaf);
        });
    }

    void realloc_node(const BtreeNodePtr& node) { wb_cache()->realloc_buf(IndexBtreeNode::convert(node)->m_idx_buf); }

    btree_status_t write_node_impl(const BtreeNodePtr& node, void* context) override {
        auto cp_ctx = r_cast< CPContext* >(context);
        auto idx_node = IndexBtreeNode::convert(node);

        if (idx_node->m_last_mod_cp_id != cp_ctx->cp_id()) {
            // Need to put it in wb cache
            wb_cache()->write_buf(idx_node->m_idx_buf, cp_ctx);
        }
        node->set_checksum(m_bt_cfg);
        return btree_status_t::success;
    }

    btree_status_t transact_write_nodes(const folly::small_vector< BtreeNodePtr&, 2 >& new_nodes,
                                        const BtreeNodePtr& child_node, const BtreeNodePtr& parent_node,
                                        void* context) override {
        CPContext* cp_ctx = r_cast< CPContext* >(context);
        auto child_idx_node = IndexBtreeNode::convert(child_node);
        auto parent_idx_node = IndexBtreeNode::convert(parent_node);
        auto& child_buf = child_idx_node->buffer();
        auto& parent_buf = parent_idx_node->buffer();

        BT_DBG_ASSERT_NE((void*)child_buf.m_cur_txn, nullptr,
                         "transact_write_nodes called without prepare transaction");

        // Write new nodes in the list as standalone outside transacted pairs.
        for (auto& node : new_nodes) {
            write_node_impl(node, context);
            wb_cache()->prepend_to_chain(node->buffer(), child_buf);
        }

        write_node_impl(child_node, context);
        write_node_impl(parent_node, context);

        return btree_status_t::success;
    }

    btree_status_t read_node_impl(bnodeid_t id, sisl::BtreeNodePtr& node) override {
        auto const ret = wb_cache()->read_buf(id, node, iomanager.am_i_tight_loop_reactor(),
                                              [this](const IndexBufferPtr& idx_buf) -> BtreeNode {
                                                  return this->init_node(idx_buf->raw_buffer(), sizeof(IndexBtreeNode),
                                                                         idx_buf->blkid().to_integer(), true, is_leaf);
                                              });
        if (ret == no_error) {
            return btree_status_t::success;
        } else if (ret == std::errc::operation_would_block) {
            // We cannot do sync read from any tight loop reactor, let caller relocate the thread and call back
            return btree_status_t::fast_path_not_possible;
        } else {
            return btee_status_t::read_failed;
        }
    }

    btree_status_t refresh_node(const BtreeNodePtr& node, bool for_read_modify_write, void* context) override {
        CPContext* cp_ctx = (CPContext*)context;

        auto idx_node = IndexBtreeNode::convert(node);
        if (idx_node->m_last_mod_cp_id > cp_ctx->cp_id()) {
            return btree_status_t::cp_mismatch;
        } else if (!for_read_modify_write) {
            return btree_status_t::success;
        } else if (idx_node->m_last_mod_cp_id == cp_ctx->cp_id()) {
            // modifying the buffer multiple times in a same cp
            return btree_status_t::success;
        }

        if (cp_ctx->is_recovery_cp()) {
            // If this refresh is part of cp taken during recovery, we need to realloc all nodes that are being
            // modified, which sets the btree blkid
            realloc_node(node);
        }

        // If the backing buffer is already in a clean state, we don't need to make a copy of it
        if (idx_node->m_idx_buf->is_clean()) { return btree_status_t::success; }

        // Make a new btree buffer and copy the contents and swap it to make it the current node's buffer. The
        // buffer prior to this copy, would have been written and already added into the dirty buffer list.
        idx_node->m_idx_buf = wb_cache()->copy_buffer(idx_node->m_idx_buf);

#ifndef NO_CHECKSUM
        if (!node->verify_node(m_bt_cfg)) {
            LOGERROR("CRC Mismatch for node: {} after refreshing the cache", node->to_string());
            return btree_status_t::crc_mismatch;
        }
#endif
        return btree_status_t::success;
    }

    btree_status_t prepare_node_txn(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                    void* context) override {
        CPContext* cp_ctx = (CPContext*)context;
        auto child_idx_node = IndexBtreeNode::convert(child_node);
        auto parent_idx_node = IndexBtreeNode::convert(parent_node);

        // Buffer has been modified by higher cp id than whats requested.
        if ((child_idx_node->m_last_mod_cp_id > cp_ctx->cp_id()) ||
            (parent_idx_node->m_last_mod_cp_id > cp_ctx->cp_id())) {
            // We don't expect this condition because prepare_node_txn should be called only after individual nodes are
            // refreshed and read
            BT_DBG_ASSERT(
                false, "prepare_node_txn facing cp id mismatch, perhaps it was called without refreshing node first?");
            return btree_status_t::cp_mismatch;
        }

        auto& child_buf = child_idx_node->buffer();
        auto& parent_buf = parent_idx_node->buffer();
        BT_DBG_ASSERT(child_buf->is_clean(), "Child buffer is not clean, refresh node was not called before?");
        BT_DBG_ASSERT(parent_buf->is_clean(), "Parent buffer is not clean, refresh node was not called before?");

        wb_cache()->create_chain(child_buf, parent_buf);
        return btree_status_t::success;
    }

    void free_node_impl(const BtreeNodePtr& node, void* context) override {
        wb_cache()->free_buf(node->m_idx_buf, r_cast< CPContext* >(context));
    }
};

} // namespace homestore
