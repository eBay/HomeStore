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

#include <homestore/btree/btree.hpp>
#include <homestore/btree/detail/simple_node.hpp>
#include <homestore/btree/detail/varlen_node.hpp>
#include <homestore/btree/detail/prefix_node.hpp>
#include <sisl/fds/utils.hpp>
// #include <iomgr/iomgr_flip.hpp>

#include <chrono>

namespace homestore {

#define lock_node(a, b, c) _lock_node(a, b, c, __FILE__, __LINE__)

template < typename K, typename V >
btree_status_t Btree< K, V >::create_root_node(void* op_context) {
    // Assign one node as root node and also create a child leaf node and set it as edge
    BtreeNodePtr root = alloc_leaf_node();
    if (root == nullptr) { return btree_status_t::space_not_avail; }

    root->set_level(0u);
    auto ret = write_node(root, op_context);
    if (ret != btree_status_t::success) {
        free_node(root, locktype_t::NONE, op_context);
        return btree_status_t::space_not_avail;
    }

    m_root_node_info = BtreeLinkInfo{root->node_id(), root->link_version()};
    return ret;
}

/*
 * It reads the node and take a lock of the node.
 */
template < typename K, typename V >
btree_status_t Btree< K, V >::read_and_lock_node(bnodeid_t id, BtreeNodePtr& node_ptr, locktype_t int_lock_type,
                                                 locktype_t leaf_lock_type, void* context) const {
    auto ret = read_node_impl(id, node_ptr);
    if (node_ptr == nullptr) {
        BT_LOG(ERROR, "read failed, reason: {}", ret);
        return ret;
    }

    auto acq_lock = (node_ptr->is_leaf()) ? leaf_lock_type : int_lock_type;
    ret = lock_node(node_ptr, acq_lock, context);
    if (ret != btree_status_t::success) { BT_LOG(ERROR, "Node lock and refresh failed"); }

    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::get_child_and_lock_node(const BtreeNodePtr& node, uint32_t index,
                                                      BtreeLinkInfo& child_info, BtreeNodePtr& child_node,
                                                      locktype_t int_lock_type, locktype_t leaf_lock_type,
                                                      void* context) const {
    if (index == node->total_entries()) {
        if (!node->has_valid_edge()) {
            BT_NODE_LOG_ASSERT(false, node, "Child index {} does not have valid bnode_id", index);
            return btree_status_t::not_found;
        }
        child_info = node->get_edge_value();
    } else {
        BT_NODE_LOG_ASSERT_LT(index, node->total_entries(), node);
        node->get_nth_value(index, &child_info, false /* copy */);
    }

    return (read_and_lock_node(child_info.bnode_id(), child_node, int_lock_type, leaf_lock_type, context));
}

template < typename K, typename V >
btree_status_t Btree< K, V >::write_node(const BtreeNodePtr& node, void* context) {
    COUNTER_INCREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_writes, btree_int_node_writes, 1);
    HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_occupancy, btree_int_node_occupancy,
                              ((m_node_size - node->available_size()) * 100) / m_node_size);

    return (write_node_impl(node, context));
}

/* Caller of this api doesn't expect read to fail in any circumstance */
template < typename K, typename V >
void Btree< K, V >::read_node_or_fail(bnodeid_t id, BtreeNodePtr& node) const {
    BT_NODE_REL_ASSERT_EQ(read_node_impl(id, node), btree_status_t::success, node);
}

/*
 * This function upgrades the parent node and child node locks from read lock to write lock and take required steps if
 * things have changed during the upgrade.
 *
 * Inputs:
 * parent_node - Parent Node to upgrade
 * child_node - Child Node to upgrade
 * child_cur_lock - Current child node which is held
 * context - Context to pass down
 *
 * Returns - If successfully able to upgrade both the nodes, return success, else return status of upgrade_node.
 * In case of not success, all nodes locks are released.
 *
 * NOTE: This function expects both the parent_node and child_node to be already locked. Parent node is
 * expected to be read locked and child node could be either read or write locked.
 */
template < typename K, typename V >
btree_status_t Btree< K, V >::upgrade_node_locks(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                                 locktype_t parent_cur_lock, locktype_t child_cur_lock, void* context) {
    btree_status_t ret = btree_status_t::success;

    auto const parent_prev_gen = parent_node->node_gen();
    auto const child_prev_gen = child_node->node_gen();

    unlock_node(child_node, child_cur_lock);
    unlock_node(parent_node, parent_cur_lock);

    ret = lock_node(parent_node, locktype_t::WRITE, context);
    if (ret != btree_status_t::success) { return ret; }

    ret = lock_node(child_node, locktype_t::WRITE, context);
    if (ret != btree_status_t::success) {
        unlock_node(parent_node, locktype_t::WRITE);
        return ret;
    }

    // If the node things have been changed between unlock and lock example, it has been made invalid (probably by merge
    // nodes) ask caller to start over again.
    if (!parent_node->is_valid_node() || (parent_prev_gen != parent_node->node_gen()) || !child_node->is_valid_node() ||
        (child_prev_gen != child_node->node_gen())) {
        unlock_node(child_node, locktype_t::WRITE);
        unlock_node(parent_node, locktype_t::WRITE);
        return btree_status_t::retry;
    }

    ret = prepare_node_txn(parent_node, child_node, context);
    if (ret != btree_status_t::success) {
        unlock_node(child_node, locktype_t::WRITE);
        unlock_node(parent_node, locktype_t::WRITE);
        return ret;
    }

#if 0
#ifdef _PRERELEASE
    {
        auto time = iomgr_flip::instance()->get_test_flip< uint64_t >("btree_upgrade_delay");
        if (time) { std::this_thread::sleep_for(std::chrono::microseconds{time.get()}); }
    }
#endif
#endif

#if 0
#ifdef _PRERELEASE
    {
        int is_leaf = 0;

        if (child_node && child_node->is_leaf()) { is_leaf = 1; }
        if (iomgr_flip::instance()->test_flip("btree_upgrade_node_fail", is_leaf)) {
            unlock_node(my_node, cur_lock);
            cur_lock = locktype_t::NONE;
            if (child_node) {
                unlock_node(child_node, child_cur_lock);
                child_cur_lock = locktype_t::NONE;
            }
            ret = btree_status_t::retry;
        }
    }
#endif
#endif

    return ret;
}

#if 0
template < typename K, typename V >
btree_status_t Btree< K, V >::upgrade_node(const BtreeNodePtr& node, locktype_t prev_lock, void* context,
                                           uint64_t prev_gen) {
    if (prev_lock == locktype_t::READ) { unlock_node(node, locktype_t::READ); }
    if (prev_lock != locktype_t::WRITE) {
        auto const ret = lock_node(node, locktype_t::WRITE, context);
        if (ret != btree_status_t::success) { return ret; }
    }

    // If the node has been made invalid (probably by merge nodes) ask caller to start over again, but before
    // that cleanup or free this node if there is no one waiting.
    if (!node->is_valid_node()) {
        unlock_node(node, locktype_t::WRITE);
        return btree_status_t::retry;
    }

    // If node has been updated, while we have upgraded, ask caller to start all over again.
    if (prev_gen != node->node_gen()) {
        unlock_node(node, locktype_t::WRITE);
        return btree_status_t::retry;
    }
    return btree_status_t::success;
}
#endif

template < typename K, typename V >
btree_status_t Btree< K, V >::_lock_node(const BtreeNodePtr& node, locktype_t type, void* context, const char* fname,
                                         int line) const {
    _start_of_lock(node, type, fname, line);
    node->lock(type);

    auto ret = refresh_node(node, (type == locktype_t::WRITE), context);
    if (ret != btree_status_t::success) {
        node->unlock(type);
        end_of_lock(node, type);
        return ret;
    }

    return btree_status_t::success;
}

template < typename K, typename V >
void Btree< K, V >::unlock_node(const BtreeNodePtr& node, locktype_t type) const {
    node->unlock(type);
    auto time_spent = end_of_lock(node, type);
    observe_lock_time(node, type, time_spent);
}

template < typename K, typename V >
BtreeNodePtr Btree< K, V >::alloc_leaf_node() {
    BtreeNodePtr n = alloc_node(true /* is_leaf */);
    if (n) {
        COUNTER_INCREMENT(m_metrics, btree_leaf_node_count, 1);
        ++m_total_nodes;
    }
    return n;
}

template < typename K, typename V >
BtreeNodePtr Btree< K, V >::alloc_interior_node() {
    BtreeNodePtr n = alloc_node(false /* is_leaf */);
    if (n) {
        COUNTER_INCREMENT(m_metrics, btree_int_node_count, 1);
        ++m_total_nodes;
    }
    return n;
}

template < typename T, typename... Args >
static BtreeNode* create_node(uint32_t node_ctx_size, Args&&... args) {
    uint8_t* raw_mem = new uint8_t[sizeof(T) + node_ctx_size];
    return dynamic_cast< BtreeNode* >(new (raw_mem) T(std::forward< Args >(args)...));
}

template < typename K, typename V >
BtreeNode* Btree< K, V >::init_node(uint8_t* node_buf, uint32_t node_ctx_size, bnodeid_t id, bool init_buf,
                                    bool is_leaf) const {
    BtreeNode* n{nullptr};
    btree_node_type node_type = is_leaf ? m_bt_cfg.leaf_node_type() : m_bt_cfg.interior_node_type();

    switch (node_type) {
    case btree_node_type::VAR_OBJECT:
        n = is_leaf ? create_node< VarObjSizeNode< K, V > >(node_ctx_size, node_buf, id, init_buf, true, this->m_bt_cfg)
                    : create_node< VarObjSizeNode< K, BtreeLinkInfo > >(node_ctx_size, node_buf, id, init_buf, false,
                                                                        this->m_bt_cfg);
        break;

    case btree_node_type::FIXED:
        n = is_leaf ? create_node< SimpleNode< K, V > >(node_ctx_size, node_buf, id, init_buf, true, this->m_bt_cfg)
                    : create_node< SimpleNode< K, BtreeLinkInfo > >(node_ctx_size, node_buf, id, init_buf, false,
                                                                    this->m_bt_cfg);
        break;

    case btree_node_type::VAR_VALUE:
        n = is_leaf
            ? create_node< VarValueSizeNode< K, V > >(node_ctx_size, node_buf, id, init_buf, true, this->m_bt_cfg)
            : create_node< VarValueSizeNode< K, BtreeLinkInfo > >(node_ctx_size, node_buf, id, init_buf, false,
                                                                  this->m_bt_cfg);
        break;

    case btree_node_type::VAR_KEY:
        n = is_leaf ? create_node< VarKeySizeNode< K, V > >(node_ctx_size, node_buf, id, init_buf, true, this->m_bt_cfg)
                    : create_node< VarKeySizeNode< K, BtreeLinkInfo > >(node_ctx_size, node_buf, id, init_buf, false,
                                                                        this->m_bt_cfg);
        break;

    case btree_node_type::PREFIX:
        n = is_leaf
            ? create_node< FixedPrefixNode< K, V > >(node_ctx_size, node_buf, id, init_buf, true, this->m_bt_cfg)
            : create_node< FixedPrefixNode< K, BtreeLinkInfo > >(node_ctx_size, node_buf, id, init_buf, false,
                                                                 this->m_bt_cfg);
        break;

    default:
        BT_REL_ASSERT(false, "Unsupported node type {}", node_type);
        break;
    }
    return n;
}

/* Note:- This function assumes that access of this node is thread safe. */
template < typename K, typename V >
void Btree< K, V >::free_node(const BtreeNodePtr& node, locktype_t cur_lock, void* context) {
    BT_NODE_LOG(DEBUG, node, "Freeing node");

    COUNTER_DECREMENT_IF_ELSE(m_metrics, node->is_leaf(), btree_leaf_node_count, btree_int_node_count, 1);
    if (cur_lock != locktype_t::NONE) {
        BT_NODE_DBG_ASSERT_NE(cur_lock, locktype_t::READ, node, "We can't free a node with read lock type right?");
        node->set_valid_node(false);
        unlock_node(node, cur_lock);
    }
    --m_total_nodes;

    free_node_impl(node, context);
    // intrusive_ptr_release(node.get());
}

template < typename K, typename V >
void Btree< K, V >::observe_lock_time(const BtreeNodePtr& node, locktype_t type, uint64_t time_spent) const {
    if (time_spent == 0) { return; }

    if (type == locktype_t::READ) {
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_inclusive_time_in_leaf_node,
                                  btree_inclusive_time_in_int_node, time_spent);
    } else {
        HISTOGRAM_OBSERVE_IF_ELSE(m_metrics, node->is_leaf(), btree_exclusive_time_in_leaf_node,
                                  btree_exclusive_time_in_int_node, time_spent);
    }
}

template < typename K, typename V >
void Btree< K, V >::_start_of_lock(const BtreeNodePtr& node, locktype_t ltype, const char* fname, int line) {
    btree_locked_node_info info;

#ifndef NDEBUG
    info.fname = fname;
    info.line = line;
#endif

    info.start_time = Clock::now();
    info.node = node.get();
    if (ltype == locktype_t::WRITE) {
        bt_thread_vars()->wr_locked_nodes.push_back(info);
        LOGTRACEMOD(btree, "ADDING node {} to write locked nodes list, its size={}", (void*)info.node,
                    bt_thread_vars()->wr_locked_nodes.size());
    } else if (ltype == locktype_t::READ) {
        bt_thread_vars()->rd_locked_nodes.push_back(info);
        LOGTRACEMOD(btree, "ADDING node {} to read locked nodes list, its size={}", (void*)info.node,
                    bt_thread_vars()->rd_locked_nodes.size());
    } else {
        DEBUG_ASSERT(false, "Invalid locktype_t {}", ltype);
    }
}

template < typename K, typename V >
bool Btree< K, V >::remove_locked_node(const BtreeNodePtr& node, locktype_t ltype, btree_locked_node_info* out_info) {
    auto pnode_infos =
        (ltype == locktype_t::WRITE) ? &bt_thread_vars()->wr_locked_nodes : &bt_thread_vars()->rd_locked_nodes;

    if (!pnode_infos->empty()) {
        auto info = pnode_infos->back();
        if (info.node == node.get()) {
            *out_info = info;
            pnode_infos->pop_back();
            LOGTRACEMOD(btree, "REMOVING node {} from {} locked nodes list, its size = {}", (void*)info.node,
                        (ltype == locktype_t::WRITE) ? "write" : "read", pnode_infos->size());
            return true;
        } else if (pnode_infos->size() > 1) {
            info = pnode_infos->at(pnode_infos->size() - 2);
            if (info.node == node.get()) {
                *out_info = info;
                pnode_infos->at(pnode_infos->size() - 2) = pnode_infos->back();
                pnode_infos->pop_back();
                LOGTRACEMOD(btree, "REMOVING node {} from {} locked nodes list, its size = {}", (void*)info.node,
                            (ltype == locktype_t::WRITE) ? "write" : "read", pnode_infos->size());
                return true;
            }
        }
    }

#ifndef NDEBUG
    if (pnode_infos->empty()) {
        LOGERRORMOD(btree, "locked_node_list: node = {} not found, locked node list empty", (void*)node.get());
    } else if (pnode_infos->size() == 1) {
        LOGERRORMOD(btree, "locked_node_list: node = {} not found, total list count = 1, Expecting node = {}",
                    (void*)node.get(), (void*)pnode_infos->back().node);
    } else {
        LOGERRORMOD(btree, "locked_node_list: node = {} not found, total list count = {}, Expecting nodes = {} or {}",
                    (void*)node.get(), pnode_infos->size(), (void*)pnode_infos->back().node,
                    (void*)pnode_infos->at(pnode_infos->size() - 2).node);
    }
#endif
    return false;
}

template < typename K, typename V >
uint64_t Btree< K, V >::end_of_lock(const BtreeNodePtr& node, locktype_t ltype) {
    btree_locked_node_info info;
    if (!remove_locked_node(node, ltype, &info)) {
        DEBUG_ASSERT(false, "Expected node = {} is not there in locked_node_list", (void*)node.get());
        return 0;
    }
    // DEBUG_ASSERT_EQ(node.get(), info.node);
    return get_elapsed_time_ns(info.start_time);
}

#ifndef NDEBUG
template < typename K, typename V >
void Btree< K, V >::check_lock_debug() {
    // both wr_locked_nodes and rd_locked_nodes are thread_local;
    // nothing will be dumpped if there is no assert failure;
    for (const auto& x : bt_thread_vars()->wr_locked_nodes) {
        x.dump();
    }
    for (const auto& x : bt_thread_vars()->rd_locked_nodes) {
        x.dump();
    }
    DEBUG_ASSERT_EQ(bt_thread_vars()->wr_locked_nodes.size(), 0);
    DEBUG_ASSERT_EQ(bt_thread_vars()->rd_locked_nodes.size(), 0);
}
#endif

} // namespace homestore
