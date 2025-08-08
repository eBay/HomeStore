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
#include <homestore/btree/btree_store.h>

namespace homestore {

#define to_variant_node(n) boost::static_pointer_cast< VariantNode< K, V > >(n)

template < typename K, typename V >
btree_status_t Btree< K, V >::post_order_traversal(locktype_t ltype, const auto& cb) {
    BtreeNodePtr root;

    if (ltype == locktype_t::READ) {
        m_btree_lock.lock_shared();
    } else if (ltype == locktype_t::WRITE) {
        m_btree_lock.lock();
    }

    btree_status_t ret{btree_status_t::success};
    if (m_root_node_info.bnode_id() != empty_bnodeid) {
        read_and_lock_node(m_root_node_info.bnode_id(), root, ltype, ltype, nullptr);
        if (ret != btree_status_t::success) { goto done; }

        ret = post_order_traversal(root, ltype, cb);
        if (ret != btree_status_t::node_freed) { unlock_node(root, ltype); }
    }
done:
    if (ltype == locktype_t::READ) {
        m_btree_lock.unlock_shared();
    } else if (ltype == locktype_t::WRITE) {
        m_btree_lock.unlock();
    }
    if (ret == btree_status_t::node_freed) { ret = btree_status_t::success; }
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::post_order_traversal(const BtreeNodePtr& node, locktype_t ltype, const auto& cb) {
    uint32_t i{0};
    btree_status_t ret = btree_status_t::success;

    if (!node->is_leaf()) {
        BtreeLinkInfo child_info;
        while (i <= node->total_entries()) {
            if (i == node->total_entries()) {
                if (!node->has_valid_edge()) { break; }
                child_info.set_bnode_id(node->edge_id());
            } else {
                node->get_nth_value(i, &child_info, false /* copy */);
            }

            BtreeNodePtr child;
            ret = read_and_lock_node(child_info.bnode_id(), child, ltype, ltype, nullptr);
            if (ret != btree_status_t::success) { return ret; }

            ret = post_order_traversal(child, ltype, cb);
            if (ret != btree_status_t::node_freed) { unlock_node(child, ltype); }
            ++i;
        }
        return cb(node, false /* is_leaf */);
    } else {
        return cb(node, true /* is_leaf */);
    }
}

template < typename K, typename V >
void Btree< K, V >::get_all_kvs(std::vector< std::pair< K, V > >& kvs) const {
    post_order_traversal(locktype_t::READ, [this, &kvs](const auto& node, bool is_leaf) -> btree_status_t {
        if (!is_leaf) { node->get_all_kvs(kvs); }
        return btree_status_t::success;
    });
}

template < typename K, typename V >
folly::Future< folly::Unit > Btree< K, V >::destroy() {
    bool expected = false;
    if (!m_destroyed.compare_exchange_strong(expected, true)) {
        BT_LOG(DEBUG, "Btree is already being destroyed, ignoring this request");
        return folly::makeFuture< folly::Unit >(folly::Unit{});
    }

    if (m_store->is_ephemeral()) {
        post_order_traversal(locktype_t::WRITE, [this](const auto& node, bool is_leaf) -> btree_status_t {
            // On ephemeral btree, we can directly remove the node, however on non-ephemeral btree, we need to do so
            // only at checkpoint time, which should be handled by the store themselves.
            remove_node(node, locktype_t::WRITE, nullptr);
            return btree_status_t::node_freed;
        });
    } else if (!m_store->is_fast_destroy_supported()) {
        // TODO: Need to be implemented. We need to create a BtreeRangeRemoveRequest and put the entire range in the
        // request, which should naturally collapse the tree and remove all the nodes. To generate the entire range we
        // have 2 choices:
        // a) Do a traversal to the left most and right most and implement a btree node method to get first and last key
        // from leaf node and put that in range and traverse again.
        // b) Generate a magical BtreeKey called "min" and "max" and put that in the range. However the user of the
        // Btree should understand this and should handle in their compare function.
    } else {
        // Let the store handle the fast delete of btree as part of the destroy_underlying_btree() call.
    }

    BT_LOG(DEBUG, "btree(root: {}) destroyed successfully", m_root_node_info.bnode_id());
    return m_store->destroy_underlying_btree(*this);
}

#if 0
template < typename K, typename V >
btree_status_t Btree< K, V >::do_destroy(std::function< void(BtreeKey const&, BtreeValue const&) > cb) {
    if (m_store->is_fast_destroy_supported()) {
        return post_order_traversal(locktype_t::WRITE, [this, &cb](const auto& node, bool is_leaf) -> btree_status_t {
            // If callback is defined, then call it for each key-value pair before deleting. It is typically used in
            // case the index stores some indirect data and that needs to be freed.
            if (cb != nullptr) {
                std::vector< std::pair< K, V > > kvs;
                node->get_all_kvs([this, &cb](const auto& kvs) {
                    for (const auto& kv : kvs) {
                        cb(kv.first, kv.second);
                    }
                });
            }

            // On ephemeral btree, we can directly remove the node, however on non-ephemeral btree, we need to do so
            // only at checkpoint time, which should be handled by the store themselves.
            if (m_store->is_ephemeral()) { remove_node(node, locktype_t::WRITE, context); }
            return btree_status_t::success;
        });
    } else {
        // TODO: Need to be implemented. We need to create a BtreeRangeRemoveRequest and put the entire range in the
        // request, which should naturally collapse the tree and remove all the nodes. To generate the entire range we
        // have 2 choices:
        // a) Do a traversal to the left most and right most and implement a btree node method to get first and last key
        // from leaf node and put that in range and traverse again.
        // b) Generate a magical BtreeKey called "min" and "max" and put that in the range. However the user of the
        // Btree should understand this and should handle in their compare function.
    }
}
#endif

template < typename K, typename V >
uint64_t Btree< K, V >::get_btree_node_cnt() const {
    uint64_t cnt = 1; /* increment it for root */
    m_btree_lock.lock_shared();
    cnt += get_child_node_cnt(m_root_node_info.bnode_id());
    m_btree_lock.unlock_shared();
    return cnt;
}

template < typename K, typename V >
uint64_t Btree< K, V >::get_child_node_cnt(bnodeid_t bnodeid) const {
    uint64_t cnt{0};
    BtreeNodePtr node;
    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return cnt; }
    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p = node->get_nth_key< K >(i, false);
            cnt += get_child_node_cnt(p.bnode_id()) + 1;
            ++i;
        }
        if (node->has_valid_edge()) { cnt += get_child_node_cnt(node->edge_id()) + 1; }
    }
    unlock_node(node, acq_lock);
    return cnt;
}

template < typename K, typename V >
void Btree< K, V >::to_string_internal(bnodeid_t bnodeid, std::string& buf) const {
    BtreeNodePtr node;

    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
    fmt::format_to(std::back_inserter(buf), "{}\n", node->to_string(true /* print_friendly */));

    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            to_string_internal(p.bnode_id(), buf);
            ++i;
        }
        if (node->has_valid_edge()) { to_string_internal(node->edge_id(), buf); }
    }
    unlock_node(node, acq_lock);
}

template < typename K, typename V >
void Btree< K, V >::to_custom_string_internal(bnodeid_t bnodeid, std::string& buf,
                                              BtreeNode::ToStringCallback< K, V > const& cb) const {
    BtreeNodePtr node;

    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
    fmt::format_to(std::back_inserter(buf), "{}\n", node->to_custom_string(cb));

    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            to_custom_string_internal(p.bnode_id(), buf, cb);
            ++i;
        }
        if (node->has_valid_edge()) { to_custom_string_internal(node->edge_id(), buf, cb); }
    }
    unlock_node(node, acq_lock);
}

template < typename K, typename V >
void Btree< K, V >::to_dot_keys(bnodeid_t bnodeid, std::string& buf,
                                std::map< uint32_t, std::vector< uint64_t > >& l_map,
                                std::map< uint64_t, BtreeVisualizeVariables >& info_map) const {
    BtreeNodePtr node;
    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
    fmt::format_to(std::back_inserter(buf), "{}\n", node->to_dot_keys());
    l_map[node->level()].push_back(node->node_id());
    info_map[node->node_id()].midPoint = node->is_leaf() ? 0 : node->total_entries() / 2;
    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            to_dot_keys(p.bnode_id(), buf, l_map, info_map);
            info_map[p.bnode_id()].parent = node->node_id();
            info_map[p.bnode_id()].index = i;
            ++i;
        }
        if (node->has_valid_edge()) {
            to_dot_keys(node->edge_id(), buf, l_map, info_map);
            info_map[node->edge_id()].parent = node->node_id();
            info_map[node->edge_id()].index = node->total_entries();
        }
    }
    unlock_node(node, acq_lock);
}

template < typename K, typename V >
void Btree< K, V >::validate_sanity_child(const BtreeNodePtr& parent_node, uint32_t ind) const {
    BtreeLinkInfo child_info;
    K child_first_key;
    K child_last_key;
    K parent_key;

    parent_node->get_nth_value(ind, &child_info, false /* copy */);
    BtreeNodePtr child_node = nullptr;
    auto ret = m_bt_private->read_node(child_info.bnode_id(), child_node);
    BT_REL_ASSERT_EQ(ret, btree_status_t::success, "read failed, reason: {}", ret);
    if (child_node->total_entries() == 0) {
        auto parent_entries = parent_node->total_entries();
        if (!child_node->is_leaf()) { // leaf node or edge node can have 0 entries
            BT_REL_ASSERT_EQ(((parent_node->has_valid_edge() && ind == parent_entries)), true);
        }
        return;
    }
    child_node->get_first_key(&child_first_key);
    child_node->get_last_key(&child_last_key);
    BT_REL_ASSERT_LE(child_first_key.compare(&child_last_key), 0);
    if (ind == parent_node->total_entries()) {
        BT_REL_ASSERT_EQ(parent_node->has_valid_edge(), true);
        if (ind > 0) {
            parent_node->get_nth_key< K >(ind - 1, &parent_key, false);
            BT_REL_ASSERT_GT(child_first_key.compare(&parent_key), 0);
            BT_REL_ASSERT_LT(parent_key.compare_start(&child_first_key), 0);
        }
    } else {
        parent_node->get_nth_key< K >(ind, &parent_key, false);
        BT_REL_ASSERT_LE(child_first_key.compare(&parent_key), 0)
        BT_REL_ASSERT_LE(child_last_key.compare(&parent_key), 0)
        BT_REL_ASSERT_GE(parent_key.compare_start(&child_first_key), 0)
        BT_REL_ASSERT_GE(parent_key.compare_start(&child_first_key), 0)
        if (ind != 0) {
            parent_node->get_nth_key< K >(ind - 1, &parent_key, false);
            BT_REL_ASSERT_GT(child_first_key.compare(&parent_key), 0)
            BT_REL_ASSERT_LT(parent_key.compare_start(&child_first_key), 0)
        }
    }
}

template < typename K, typename V >
void Btree< K, V >::validate_sanity_next_child(const BtreeNodePtr& parent_node, uint32_t ind) const {
    BtreeLinkInfo child_info;
    K child_key;
    K parent_key;

    if (parent_node->has_valid_edge()) {
        if (ind == parent_node->total_entries()) { return; }
    } else {
        if (ind == parent_node->total_entries() - 1) { return; }
    }
    parent_node->get_nth_value(ind + 1, &child_info, false /* copy */);

    BtreeNodePtr child_node = nullptr;
    auto ret = m_bt_private->read_node(child_info.bnode_id(), child_node);
    BT_REL_ASSERT_EQ(ret, btree_status_t::success, "read failed, reason: {}", ret);

    if (child_node->total_entries() == 0) {
        auto parent_entries = parent_node->total_entries();
        if (!child_node->is_leaf()) { // leaf node can have 0 entries
            BT_REL_ASSERT_EQ(((parent_node->has_valid_edge() && ind == parent_entries) || (ind = parent_entries - 1)),
                             true);
        }
        return;
    }
    /* in case of merge next child will never have zero entries otherwise it would have been merged */
    BT_NODE_REL_ASSERT_NE(child_node->total_entries(), 0, child_node);
    child_node->get_first_key(&child_key);
    parent_node->get_nth_key< K >(ind, &parent_key, false);
    BT_REL_ASSERT_GT(child_key.compare(&parent_key), 0)
    BT_REL_ASSERT_LT(parent_key.compare_start(&child_key), 0)
}

template < typename K, typename V >
void Btree< K, V >::print_node(const bnodeid_t& bnodeid) const {
    std::string buf;
    BtreeNodePtr node;

    m_btree_lock.lock_shared();
    locktype_t acq_lock = locktype_t::READ;
    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { goto done; }
    buf = node->to_string(true /* print_friendly */);
    unlock_node(node, acq_lock);

done:
    m_btree_lock.unlock_shared();

    BT_LOG(INFO, "Node: <{}>", buf);
}

template < typename K, typename V >
void Btree< K, V >::append_route_trace(BtreeRequest& req, const BtreeNodePtr& node, btree_event_t event,
                                       uint32_t start_idx, uint32_t end_idx) const {
    if (req.m_route_tracing) {
        req.m_route_tracing->emplace_back(trace_route_entry{.node_id = node->node_id(),
                                                            .node = node.get(),
                                                            .start_idx = start_idx,
                                                            .end_idx = end_idx,
                                                            .num_entries = node->total_entries(),
                                                            .level = node->level(),
                                                            .is_leaf = node->is_leaf(),
                                                            .event = event});
    }
}
} // namespace homestore
