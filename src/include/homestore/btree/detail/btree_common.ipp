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
btree_status_t Btree< K, V >::do_destroy(uint64_t& n_freed_nodes, void* context) {
    return post_order_traversal(locktype_t::WRITE,
                                [this, &n_freed_nodes, context](const auto& node, bool is_leaf) -> btree_status_t {
                                    free_node(node, locktype_t::WRITE, context);
                                    ++n_freed_nodes;
                                    return btree_status_t::node_freed;
                                });
}

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
void Btree< K, V >::to_string(bnodeid_t bnodeid, std::string& buf) const {
    BtreeNodePtr node;

    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
    fmt::format_to(std::back_inserter(buf), "{}\n", node->to_string(true /* print_friendly */));

    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            to_string(p.bnode_id(), buf);
            ++i;
        }
        if (node->has_valid_edge()) { to_string(node->edge_id(), buf); }
    }
    unlock_node(node, acq_lock);
}

template < typename K, typename V >
void Btree< K, V >::to_string_keys(bnodeid_t bnodeid, std::string& buf) const {
    BtreeNodePtr node;

    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
    fmt::format_to(std::back_inserter(buf), "{}\n", node->to_string_keys());

    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            to_string_keys(p.bnode_id(), buf);
            ++i;
        }
        if (node->has_valid_edge()) { to_string_keys(node->edge_id(), buf); }
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
    auto ret = read_node_impl(child_info.bnode_id(), child_node);
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
    auto ret = read_node_impl(child_info.bnode_id(), child_node);
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
    if (req.route_tracing) {
        req.route_tracing->emplace_back(trace_route_entry{.node_id = node->node_id(),
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
