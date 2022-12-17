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

template < typename K, typename V >
btree_status_t Btree< K, V >::do_sweep_query(BtreeNodePtr& my_node, BtreeQueryRequest< K >& qreq,
                                             std::vector< std::pair< K, V > >& out_values) const {
    btree_status_t ret = btree_status_t::success;
    if (my_node->is_leaf()) {
        BT_NODE_DBG_ASSERT_GT(qreq.batch_size(), 0, my_node);

        auto count = 0U;
        BtreeNodePtr next_node = nullptr;

        do {
            if (next_node) {
                unlock_node(my_node, locktype_t::READ);
                my_node = next_node;
            }

            uint32_t start_ind{0};
            uint32_t end_ind{0};
            auto cur_count =
                my_node->template get_all< K, V >(qreq.next_range(), qreq.batch_size() - count, start_ind, end_ind);
            for (auto idx{start_ind}; idx < (start_ind + cur_count); ++idx) {
                call_on_read_kv_cb(my_node, idx, qreq);
                my_node->add_nth_obj_to_list(idx, &out_values, true);
            }
            count += cur_count;

            // If this is not the last entry found, then surely we have reached the end of search criteria
            if ((end_ind + 1) < my_node->total_entries()) { break; }

            // Keep querying sibling nodes
            if (count < qreq.batch_size()) {
                // Before reading a sibling node, validate if the current node last key is already same as end key. This
                // avoids reading from a sibling node.
                if (my_node->get_last_key< K >().compare(qreq.input_range().end_key()) >= 0) { break; }
                if (my_node->next_bnode() == empty_bnodeid) { break; }
                ret = read_and_lock_node(my_node->next_bnode(), next_node, locktype_t::READ, locktype_t::READ,
                                         qreq.m_op_context);
                if (ret != btree_status_t::success) { break; }
            } else {
                ret = btree_status_t::has_more;
                break;
            }
        } while (true);

        unlock_node(my_node, locktype_t::READ);
        return ret;
    }

    BtreeLinkInfo start_child_info;
    [[maybe_unused]] const auto [isfound, idx] = my_node->find(qreq.next_key(), &start_child_info, false);
    ASSERT_IS_VALID_INTERIOR_CHILD_INDX(isfound, idx, my_node);

    BtreeNodePtr child_node;
    ret = read_and_lock_node(start_child_info.bnode_id(), child_node, locktype_t::READ, locktype_t::READ,
                             qreq.m_op_context);
    unlock_node(my_node, locktype_t::READ);
    if (ret != btree_status_t::success) { return ret; }
    return (do_sweep_query(child_node, qreq, out_values));
}

template < typename K, typename V >
btree_status_t Btree< K, V >::do_traversal_query(const BtreeNodePtr& my_node, BtreeQueryRequest< K >& qreq,
                                                 std::vector< std::pair< K, V > >& out_values) const {
    btree_status_t ret = btree_status_t::success;
    uint32_t idx;

    if (my_node->is_leaf()) {
        BT_NODE_LOG_ASSERT_GT(qreq.batch_size(), 0, my_node);

        uint32_t start_ind = 0, end_ind = 0;
        auto cur_count = my_node->get_all(qreq.next_range(), qreq.batch_size() - (uint32_t)out_values.size(), start_ind,
                                          end_ind, &out_values);

        if (cur_count) {
            for (auto idx{start_ind}; idx < (start_ind + cur_count); ++idx) {
                call_on_read_kv_cb(my_node, idx, qreq);
                // my_node->add_nth_obj_to_list(idx, &out_values, true);
            }
        }

        unlock_node(my_node, locktype_t::READ);
        if (ret != btree_status_t::success || out_values.size() >= qreq.batch_size()) {
            if (out_values.size() >= qreq.batch_size()) { ret = btree_status_t::has_more; }
        }

        return ret;
    }

    const auto [start_isfound, start_idx] = my_node->find(qreq.next_key(), nullptr, false);
    auto [end_is_found, end_idx] = my_node->find(qreq.input_range().end_key(), nullptr, false);
    bool unlocked_already = false;

    if (start_idx == my_node->total_entries() && !(my_node->has_valid_edge())) {
        goto done; // no results found
    } else if (end_idx == my_node->total_entries() && !(my_node->has_valid_edge())) {
        --end_idx; // end is not valid
    }

    BT_NODE_LOG_ASSERT_LE(start_idx, end_idx, my_node);
    idx = start_idx;

    while (idx <= end_idx) {
        BtreeLinkInfo child_info;
        my_node->get_nth_value(idx, &child_info, false);
        BtreeNodePtr child_node = nullptr;
        locktype_t child_cur_lock = locktype_t::READ;
        ret = read_and_lock_node(child_info.bnode_id(), child_node, child_cur_lock, child_cur_lock, nullptr);
        if (ret != btree_status_t::success) { break; }

        if (idx == end_idx) {
            // If we have reached the last index, unlock before traversing down, because we no longer need
            // this lock. Holding this lock will impact performance unncessarily.
            unlock_node(my_node, locktype_t::READ);
            unlocked_already = true;
        }
        // TODO - pass sub range if child is leaf
        ret = do_traversal_query(child_node, qreq, out_values);
        if (ret == btree_status_t::has_more) { break; }
        ++idx;
    }
done:
    if (!unlocked_already) { unlock_node(my_node, locktype_t::READ); }

    return ret;
}

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
btree_status_t do_serialzable_query(const BtreeNodePtr& my_node, BtreeSerializableQueryRequest& qreq,
                                    std::vector< std::pair< K, V > >& out_values) {

    btree_status_t ret = btree_status_t::success;
    if (my_node->is_leaf) {
        auto count = 0;
        auto start_result = my_node->find(qreq.get_start_of_range(), nullptr, nullptr);
        auto start_ind = start_result.end_of_search_index;

        auto end_result = my_node->find(qreq.get_end_of_range(), nullptr, nullptr);
        auto end_ind = end_result.end_of_search_index;
        if (!end_result.found) { end_ind--; } // not found entries will point to 1 ind after last in range.

        ind = start_ind;
        while ((ind <= end_ind) && (count < qreq.batch_size())) {
            K key;
            V value;
            my_node->get_nth_element(ind, &key, &value, false);

            if (!qreq.m_match_item_cb || qreq.m_match_item_cb(key, value)) {
                out_values.emplace_back(std::make_pair< K, V >(key, value));
                count++;
            }
            ind++;
        }

        bool has_more = ((ind >= start_ind) && (ind < end_ind));
        if (!has_more) {
            unlock_node(my_node, locktype_t::READ);
            get_tracker(qreq)->pop();
            return success;
        }

        return has_more;
    }

    BtreeNodeId start_child_ptr, end_child_ptr;
    auto start_ret = my_node->find(qreq.get_start_of_range(), nullptr, &start_child_ptr);
    ASSERT_IS_VALID_INTERIOR_CHILD_INDX(start_ret, my_node);
    auto end_ret = my_node->find(qreq.get_end_of_range(), nullptr, &end_child_ptr);
    ASSERT_IS_VALID_INTERIOR_CHILD_INDX(end_ret, my_node);

    BtreeNodePtr child_node;
    if (start_ret.end_of_search_index == end_ret.end_of_search_index) {
        BT_LOG_ASSERT_CMP(start_child_ptr, ==, end_child_ptr, my_node);

        ret = read_and_lock_node(start_child_ptr.node_id(), child_node, locktype_t::READ, locktype_t::READ, nullptr);
        if (ret != btree_status_t::success) {
            unlock_node(my_node, locktype_t::READ);
            return ret;
        }
        unlock_node(my_node, locktype_t::READ);

        // Pop the last node and push this child node
        get_tracker(qreq)->pop();
        get_tracker(qreq)->push(child_node);
        return do_serialzable_query(child_node, qreq, search_range, out_values);
    } else {
        // This is where the deviation of tree happens. Do not pop the node out of lock tracker
        bool has_more = false;

        for (auto i = start_ret.end_of_search_index; i <= end_ret.end_of_search_index; i++) {
            BtreeNodeId child_ptr;
            my_node->get_nth_value(i, &child_ptr, false);
            ret = read_and_lock_node(child_ptr.node_id(), child_node, locktype_t::READ, locktype_t::READ, nullptr);
            if (ret != btree_status_t::success) {
                unlock_node(my_node, locktype_t::READ);
                return ret;
            }

            get_tracker(qreq)->push(child_node);

            ret = do_serialzable_query(child_node, qreq, out_values);
            if (ret == BTREE_AGAIN) {
                BT_LOG_ASSERT_CMP(out_values.size(), ==, qreq.batch_size(), );
                break;
            }
        }

        if (ret == BTREE_SUCCESS) {
            unlock_node(my_node, locktype_t::READ);
            HS_DEBUG_ASSERT_EQ(get_tracker(qreq)->top(), my_node);
            get_tracker(qreq)->pop();
        }
        return ret;
    }
}
#endif

#ifdef SERIALIZABLE_QUERY_IMPLEMENTATION
btree_status_t sweep_query(BtreeQueryRequest< K >& qreq, std::vector< std::pair< K, V > >& out_values) {
    COUNTER_INCREMENT(m_metrics, btree_read_ops_count, 1);
    qreq.init_batch_range();

    m_btree_lock.lock_shared();

    BtreeNodePtr root;
    btree_status_t ret = btree_status_t::success;

    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::READ, locktype_t::READ, nullptr);
    if (ret != btree_status_t::success) { goto out; }

    ret = do_sweep_query(root, qreq, out_values);
out:
    m_btree_lock.unlock_shared();

#ifndef NDEBUG
    check_lock_debug();
#endif
    return ret;
}

btree_status_t serializable_query(BtreeSerializableQueryRequest& qreq, std::vector< std::pair< K, V > >& out_values) {
    qreq.init_batch_range();

    m_btree_lock.lock_shared();
    BtreeNodePtr node;
    btree_status_t ret;

    if (qreq.is_empty_cursor()) {
        // Initialize a new lock tracker and put inside the cursor.
        qreq.cursor().m_locked_nodes = std::make_unique< BtreeLockTrackerImpl >(this);

        BtreeNodePtr root;
        ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::READ, locktype_t::READ, nullptr);
        if (ret != btree_status_t::success) { goto out; }
        get_tracker(qreq)->push(root); // Start tracking the locked nodes.
    } else {
        node = get_tracker(qreq)->top();
    }

    ret = do_serialzable_query(node, qreq, out_values);
out:
    m_btree_lock.unlock_shared();

    // TODO: Assert if key returned from do_get is same as key requested, incase of perfect match

#ifndef NDEBUG
    check_lock_debug();
#endif

    return ret;
}

BtreeLockTrackerImpl* get_tracker(BtreeSerializableQueryRequest& qreq) {
    return (BtreeLockTrackerImpl*)qreq->get_cursor.m_locked_nodes.get();
}

template < typename K, typename V >
class BtreeLockTrackerImpl : public BtreeLockTracker {
public:
    BtreeLockTrackerImpl(btree_t* bt) : m_bt(bt) {}

    virtual ~BtreeLockTrackerImpl() {
        while (m_nodes.size()) {
            auto& p = m_nodes.top();
            m_bt->unlock_node(p.first, p.second);
            m_nodes.pop();
        }
    }

    void push(const BtreeNodePtr& node, locktype_t locktype) { m_nodes.emplace(std::make_pair<>(node, locktype)); }

    std::pair< BtreeNodePtr, locktype_t > pop() {
        HS_ASSERT_CMP(DEBUG, m_nodes.size(), !=, 0);
        std::pair< BtreeNodePtr, locktype_t > p;
        if (m_nodes.size()) {
            p = m_nodes.top();
            m_nodes.pop();
        } else {
            p = std::make_pair<>(nullptr, locktype_t::LOCKTYPE_NONE);
        }

        return p;
    }

    BtreeNodePtr top() { return (m_nodes.size == 0) ? nullptr : m_nodes.top().first; }

private:
    btree_t m_bt;
    std::stack< std::pair< BtreeNodePtr, locktype_t > > m_nodes;
};
#endif
} // namespace homestore
