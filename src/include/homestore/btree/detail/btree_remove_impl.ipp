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
template < typename ReqT >
btree_status_t Btree< K, V >::remove(ReqT& req) {
    static_assert(std::is_same_v< ReqT, BtreeSingleRemoveRequest > ||
                      std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > > ||
                      std::is_same_v< ReqT, BtreeRemoveAnyRequest< K > >,
                  "remove api is called with non remove request type");

    locktype_t acq_lock = locktype_t::READ;
    m_btree_lock.lock_shared();

retry:
    btree_status_t ret = btree_status_t::success;
    auto cpg = bt_cp_guard();
    req.m_op_context = cpg.context(cp_consumer_t::INDEX_SVC);

    BtreeNodePtr root;
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, acq_lock, acq_lock, req.m_op_context);
    if (ret == btree_status_t::cp_mismatch) {
        goto retry;
    } else if (ret != btree_status_t::success) {
        goto out;
    }

    if (root->total_entries() == 0) {
        if (root->is_leaf()) {
            // There are no entries in btree.
            unlock_node(root, acq_lock);
            m_btree_lock.unlock_shared();
            ret = btree_status_t::not_found;
            goto out;
        }

        BT_NODE_LOG_ASSERT_EQ(root->has_valid_edge(), true, root, "Orphaned root with no entries and no edge");
        unlock_node(root, acq_lock);
        m_btree_lock.unlock_shared();

        ret = check_collapse_root(req);
        if (ret != btree_status_t::success && ret != btree_status_t::merge_not_required &&
            ret != btree_status_t::cp_mismatch) {
            LOGERROR("check collapse read failed btree name {}", m_bt_cfg.name());
            goto out;
        }

        // We must have gotten a new root, need to start from scratch.
        m_btree_lock.lock_shared();
        goto retry;
    } else if (root->is_leaf() && (acq_lock != locktype_t::WRITE)) {
        // Root is a leaf, need to take write lock, instead of read, retry
        unlock_node(root, acq_lock);
        acq_lock = locktype_t::WRITE;
        goto retry;
    } else {
        ret = do_remove(root, acq_lock, req);
        if ((ret == btree_status_t::retry) || (ret == btree_status_t::cp_mismatch)) {
            // Need to start from top down again, since there was a merge nodes in-between
            acq_lock = locktype_t::READ;
            goto retry;
        }
    }
    m_btree_lock.unlock_shared();

out:
#ifndef NDEBUG
    check_lock_debug();
#endif
    return ret;
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::do_remove(const BtreeNodePtr& my_node, locktype_t curlock, ReqT& req) {
    btree_status_t ret = btree_status_t::success;
    bool at_least_one_child_modified{false};
    if (my_node->is_leaf()) {
        BT_NODE_DBG_ASSERT_EQ(curlock, locktype_t::WRITE, my_node);

        uint32_t removed_count{0};
        bool modified{false};
#ifndef NDEBUG
        my_node->validate_key_order< K >();
#endif

        if constexpr (std::is_same_v< ReqT, BtreeSingleRemoveRequest >) {
            if ((modified = my_node->remove_one(req.key(), nullptr, req.m_outval))) { ++removed_count; }
        } else if constexpr (std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > >) {
            removed_count = to_variant_node(my_node)->multi_remove(req.working_range(), req.m_filter_cb);
            modified = (removed_count != 0);
            req.shift_working_range();
        } else if constexpr (std::is_same_v< ReqT, BtreeRemoveAnyRequest< K > >) {
            if ((modified = my_node->remove_any(req.m_range, req.m_outkey, req.m_outval))) { ++removed_count; }
        }
#ifndef NDEBUG
        my_node->validate_key_order< K >();
#endif
        if (modified) {
            write_node(my_node, req.m_op_context);
            COUNTER_DECREMENT(m_metrics, btree_obj_count, removed_count);
            if (req.m_route_tracing) { append_route_trace(req, my_node, btree_event_t::REMOVE); }
        }

        unlock_node(my_node, curlock);
        return modified ? btree_status_t::success : btree_status_t::not_found;
    }

retry:
    locktype_t child_cur_lock = locktype_t::NONE;
    uint32_t curr_idx;
    uint32_t start_idx{0};
    uint32_t end_idx{0};

    auto unlock_lambda = [this](const BtreeNodePtr& node, locktype_t& cur_lock) {
        unlock_node(node, cur_lock);
        cur_lock = locktype_t::NONE;
    };

    // Get the childPtr for given key.
    if constexpr (std::is_same_v< ReqT, BtreeSingleRemoveRequest >) {
        auto const [found, idx] = my_node->find(req.key(), nullptr, false);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(found, idx, my_node);
        end_idx = start_idx = idx;
        if (false) { goto out_return; } // Please the compiler
    } else if constexpr (std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > >) {
        auto const matched = my_node->match_range< K >(req.working_range(), start_idx, end_idx);
        if (!matched) {
            ret = btree_status_t::not_found;
            goto out_return;
        }
    } else if constexpr (std::is_same_v< ReqT, BtreeRemoveAnyRequest< K > >) {
        auto const matched = my_node->match_range< K >(req.m_range, start_idx, end_idx);
        if (!matched) {
            ret = btree_status_t::not_found;
            goto out_return;
        }
        end_idx = start_idx = (end_idx - start_idx) / 2; // Pick the middle, TODO: Ideally we need to pick random
    }

    if (req.m_route_tracing) { append_route_trace(req, my_node, btree_event_t::READ, start_idx, end_idx); }
    curr_idx = start_idx;
    while (curr_idx <= end_idx) {
        BtreeLinkInfo child_info;
        BtreeNodePtr child_node;
        ret = get_child_and_lock_node(my_node, curr_idx, child_info, child_node, locktype_t::READ, locktype_t::WRITE,
                                      req.m_op_context);
        if (ret != btree_status_t::success) { goto out_return; }
        child_cur_lock = child_node->is_leaf() ? locktype_t::WRITE : locktype_t::READ;

        if (child_node->is_merge_needed(m_bt_cfg)) {
            // If child node is minimal and can be merged
            uint32_t node_end_idx = my_node->total_entries();
            if (!my_node->has_valid_edge()) { --node_end_idx; }
            if (node_end_idx > (curr_idx + m_bt_cfg.m_max_merge_nodes - 1)) {
                node_end_idx = curr_idx + m_bt_cfg.m_max_merge_nodes - 1;
            }

            if (node_end_idx > curr_idx) {
                // If we are unable to upgrade the node, ask the caller to retry.
                ret = upgrade_node_locks(my_node, child_node, curlock, child_cur_lock, req.m_op_context);
                if (ret != btree_status_t::success) { goto out_return; }

                ret = merge_nodes(my_node, child_node, curr_idx, node_end_idx, req.m_op_context);
                if ((ret != btree_status_t::success) && (ret != btree_status_t::merge_not_required)) {
                    unlock_lambda(child_node, child_cur_lock);
                    goto out_return;
                } else if (ret == btree_status_t::success) {
                    if (req.m_route_tracing) { append_route_trace(req, child_node, btree_event_t::MERGE); }
                    unlock_lambda(child_node, child_cur_lock);
                    COUNTER_INCREMENT(m_metrics, btree_merge_count, 1);
                    goto retry;
                } else if (ret == btree_status_t::merge_not_required) {
                    BT_NODE_LOG(DEBUG, my_node, "merge is not required for child = {} keys: {}", curr_idx,
                                child_node->to_string());
                }
            }
        }

        // Get subrange if it is a range update
        if constexpr (std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > >) {
            if (child_node->is_leaf()) {
                // We get the trimmed range only for leaf because this is where we will be removing keys. In interior
                // nodes, keys are always propogated from the lower nodes.
                if (curr_idx < my_node->total_entries()) {
                    K child_end_key = my_node->get_nth_key< K >(curr_idx, true);
                    if (child_end_key.compare(req.working_range().end_key()) < 0) {
                        req.trim_working_range(std::move(child_end_key), true /* inclusive child key */);
                    }

                    BT_NODE_LOG(DEBUG, my_node, "Subrange:idx=[{}-{}],c={},working={}", start_idx, end_idx, curr_idx,
                                req.working_range().to_string());
                }
            }
        }

#ifndef NDEBUG
        if (child_node->total_entries()) {
            if (curr_idx != my_node->total_entries()) { // not edge
                BT_NODE_DBG_ASSERT_LE(
                    child_node->get_last_key< K >().compare(my_node->get_nth_key< K >(curr_idx, false)), 0, my_node);
            }

            if (curr_idx > 0) { // not first child
                BT_NODE_DBG_ASSERT_GT(
                    child_node->get_first_key< K >().compare(my_node->get_nth_key< K >(curr_idx - 1, false)), 0,
                    my_node);
            }
        }
#endif

        if (curr_idx == end_idx) {
            // If we have reached the last index, unlock before traversing down, because we no longer need
            // this lock. Holding this lock will impact performance unncessarily.
            unlock_lambda(my_node, curlock);
        }

        ret = do_remove(child_node, child_cur_lock, req);
        if (ret == btree_status_t::success) { at_least_one_child_modified = true; }
        ++curr_idx;
    }

out_return:
    // Warning: Do not access childNode or myNode beyond this point, since it would
    // have been unlocked by the recursive function and it could also been deleted.
    if (curlock != locktype_t::NONE) { unlock_lambda(my_node, curlock); }
    return (at_least_one_child_modified) ? btree_status_t::success : ret;
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::check_collapse_root(ReqT& req) {
    if (!m_bt_cfg.m_merge_turned_on) { return btree_status_t::merge_not_required; }
    BtreeNodePtr child;
    BtreeNodePtr root;
    btree_status_t ret = btree_status_t::success;

    m_btree_lock.lock();
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::WRITE, locktype_t::WRITE, req.m_op_context);
    if (ret != btree_status_t::success) { goto done; }

    if (root->total_entries() != 0 || root->is_leaf()) {
        // some other thread collapsed root already
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

    BT_NODE_DBG_ASSERT_EQ(root->has_valid_edge(), true, root);
    ret = read_and_lock_node(root->edge_id(), child, locktype_t::WRITE, locktype_t::WRITE, req.m_op_context);
    if (ret != btree_status_t::success) {
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

    ret = m_bt_private->on_root_changed(child, req.m_op_context);
    if (ret != btree_status_t::success) {
        unlock_node(child, locktype_t::WRITE);
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

    if (req.m_route_tracing) { append_route_trace(req, root, btree_event_t::MERGE); }

    remove_node(root, locktype_t::WRITE, req.m_op_context);
    m_root_node_info = child->link_info();
    unlock_node(child, locktype_t::WRITE);
    COUNTER_DECREMENT(m_metrics, btree_depth, 1);

done:
    m_btree_lock.unlock();
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::merge_nodes(const BtreeNodePtr& parent_node, const BtreeNodePtr& leftmost_node,
                                          uint32_t start_idx, uint32_t end_idx, CPContext* context) {
    if (!m_bt_cfg.m_merge_turned_on) { return btree_status_t::merge_not_required; }

    auto read_child_node = [this, context](BtreeNodePtr const& parent_node, uint32_t idx,
                                           BtreeNodePtr& child_node) -> btree_status_t {
        if (idx == parent_node->total_entries()) {
            BT_NODE_LOG_ASSERT(parent_node->has_valid_edge(), parent_node,
                               "Assertion failure, expected valid edge for parent node");
        }

        BtreeLinkInfo child_info;
        parent_node->get_nth_value(idx, &child_info, false /* copy */);

        auto const ret =
            read_and_lock_node(child_info.bnode_id(), child_node, locktype_t::WRITE, locktype_t::WRITE, context);
        if (ret == btree_status_t::success) { BT_NODE_LOG_ASSERT_EQ(child_node->is_node_deleted(), false, child_node); }
        return ret;
    };

    auto erase_last_node_in_list = [this, &leftmost_node](BtreeNodeList& list, bool node_removal, CPContext* context) {
        auto& node = list.back();
        if (node_removal) {
            remove_node(node, locktype_t::NONE, context);
        } else {
            unlock_node(node, locktype_t::WRITE);
        }
        list.erase(list.end() - 1);
    };

    btree_status_t ret{btree_status_t::success};
    BtreeNodeList old_nodes;
    BtreeNodeList new_nodes;
    old_nodes.reserve(3);
    new_nodes.reserve(3);

    // Loop variables
    BtreeNodePtr old_node{nullptr};
    BtreeNodePtr cloned_new_node{clone_temp_node(*leftmost_node)};
    BtreeNodePtr new_node{cloned_new_node};
    uint32_t idx = start_idx + 1;
    uint32_t src_cursor{0};
    bool dst_filled{false};
    BtreeNodePtr last_new_node{nullptr};
    bnodeid_t next_node_id;

    while (idx <= end_idx) {
        if (old_node == nullptr) {
            ret = read_child_node(parent_node, idx, old_node);
            if (ret != btree_status_t::success) { goto out; }

            old_nodes.push_back(old_node);
            src_cursor = 0;
        }

        if (new_node == nullptr) {
            new_node = leftmost_node->is_leaf() ? create_leaf_node(context) : create_interior_node(context);
            new_nodes.emplace_back(new_node);
        }

        if (idx == end_idx) {
            // Special handling for the last node, we will do the merge of last old node, only if that node can be
            // completely placed/appended into the new node.
            auto const copied = new_node->append_copy_in_upto_size(*old_node, src_cursor, m_bt_cfg.ideal_fill_size(),
                                                                   /*copy_only_if_fits=*/true);
            if (!copied) {
                // Last old node doesn't fit fully into the new node, it is possible that previous old nodes fits into
                // one new node and we created a second new node, but the last old node doesn't completely fit into the
                // new last node and hence did not move anything. In that case, we can skip the empty new node.
                if (new_node->total_entries() == 0) {
                    erase_last_node_in_list(new_nodes, /*node_removal=*/true, context);
                }
                erase_last_node_in_list(old_nodes, /*node_removal=*/false, context);
            }
            break;
        } else {
            new_node->append_copy_in_upto_size(*old_node, src_cursor, m_bt_cfg.ideal_fill_size(),
                                               /*copy_only_if_fits=*/false);
            if (src_cursor == old_node->total_entries()) {
                // We have copied all the entries from old_node, so we can move onto next old node
                old_node = nullptr;
                ++idx;
            } else {
                // Looks like we have filled the new node, so we need to create a new one
                new_node = nullptr;
            }
        }
    }

    // We commit the merge, only if we actually remove at least 1 node by merging.
    if (new_nodes.size() >= old_nodes.size()) {
        ret = btree_status_t::merge_not_required;
        goto out;
    }

    // Remove excess entries from the parent node
    parent_node->remove(start_idx + new_nodes.size() + 1, start_idx + old_nodes.size());

    // parent_node->remove(start_idx + 1, start_idx + old_nodes.size());

    // Update all the new node entries to parent and while iterating update their node links.
    idx = start_idx + new_nodes.size();
    next_node_id = old_nodes.back()->next_bnode();
    for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
        (*it)->set_next_bnode(next_node_id);
        auto this_node_id = (*it)->node_id();
        if ((*it)->total_entries()) {
            parent_node->update(idx--, (*it)->get_last_key< K >(), BtreeLinkInfo{this_node_id, 0});
        }
        next_node_id = this_node_id;
    }

    // We need to copy the cloned node back to leftmost_node and update it with latest next node
    leftmost_node->overwrite(*cloned_new_node);
    leftmost_node->set_next_bnode(next_node_id);
    if (leftmost_node->total_entries()) {
        leftmost_node->inc_link_version();
        parent_node->update(start_idx, leftmost_node->get_last_key< K >(), leftmost_node->link_info());
    }

    ret = m_bt_private->transact_nodes(new_nodes, old_nodes, leftmost_node, parent_node, context);

out:
    // Do free/unlock based on success/failure in reverse order
    if (ret != btree_status_t::success) {
        for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
            unlock_node(*it, locktype_t::WRITE);
        }

        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            remove_node(*it, locktype_t::NONE, context);
        }
    }

    return ret;
}

#if 0
template < typename K, typename V >
btree_status_t Btree< K, V >::merge_nodes(const BtreeNodePtr& parent_node, const BtreeNodePtr& leftmost_node,
                                          uint32_t start_idx, uint32_t end_idx, CPContext* context) {
    if (!m_bt_cfg.m_merge_turned_on) { return btree_status_t::merge_not_required; }
    btree_status_t ret{btree_status_t::success};
    BtreeNodeList old_nodes;
    BtreeNodeList new_nodes;
    BtreeNodePtr new_node;
    uint32_t total_size{0};
    uint32_t balanced_size{0};
    int32_t available_size{0};
    uint32_t num_nodes{0};

    struct _leftmost_src_info {
        std::vector< uint32_t > ith_nodes;
        uint32_t last_node_upto{
            std::numeric_limits< uint32_t >::max()}; // Upto num entries it can copy in the last node
    };
    struct _src_cursor_info {
        uint32_t ith_node;
        uint32_t nth_entry{0};
    };

    auto plast_key = parent_node->get_last_key< K >();
    _leftmost_src_info leftmost_src;
    _src_cursor_info src_cursor;

    total_size = leftmost_node->occupied_size();
    for (auto indx = start_idx + 1; indx <= end_idx; ++indx) {
        if (indx == parent_node->total_entries()) {
            BT_NODE_LOG_ASSERT(parent_node->has_valid_edge(), parent_node,
                               "Assertion failure, expected valid edge for parent_node");
        }

        BtreeLinkInfo child_info;
        parent_node->get_nth_value(indx, &child_info, false /* copy */);

        BtreeNodePtr child;
        ret = read_and_lock_node(child_info.bnode_id(), child, locktype_t::WRITE, locktype_t::WRITE, context);
        if (ret != btree_status_t::success) { goto out; }
        BT_NODE_LOG_ASSERT_EQ(child->is_node_deleted(), false, child);

        old_nodes.push_back(child);
        // Todo: need a more precise calculation considering compacted size for prefix nodes because when merge happens
        // compaction will occur for both leftmost and new nodes. This calculation makes available size not be balanced
        // for the leftmost node and new nodes.
        total_size += child->occupied_size();
    }

    // Determine if packing the nodes would result in reducing the number of nodes, if so go with that. If else
    // we revert back to rebalancing the nodes.
    num_nodes = (total_size == 0) ? 1 : (total_size - 1) / m_bt_cfg.ideal_fill_size() + 1;
    if (num_nodes >= (old_nodes.size() + 1)) {
        // Only option is to rebalance the nodes across. If we are asked not to do so, skip it.
        if (!m_bt_cfg.m_rebalance_turned_on) {
            ret = btree_status_t::merge_not_required;
            goto out;
        }
    }

    balanced_size = (total_size == 0) ? 0 : (total_size - 1) / num_nodes + 1;
    if (leftmost_node->occupied_size() > balanced_size) {
        // If for some reason balancing increases the current size, give up.
        // TODO: Is this a real case, isn't happening would mean some sort of bug in calculation of is_merge_needed?
        BT_NODE_DBG_ASSERT(false, leftmost_node,
                           "Didn't expect current size is more than balanced size without rebalancing");
        ret = btree_status_t::merge_not_required;
        goto out;
    }

    // First try to see how many entries you can fit in the leftmost node within the balanced size. We are checking
    // leftmost node as special case without moving, because that is the only node which is modified in-place and
    // hence doing a dry run and if for some reason there is a problem in balancing the nodes, then it is easy to
    // give up.
    available_size = static_cast< int32_t >(balanced_size) - leftmost_node->occupied_size();
    src_cursor.ith_node = old_nodes.size();
    for (uint32_t i{0}; (i < old_nodes.size() && available_size >= 0); ++i) {
        leftmost_src.ith_nodes.push_back(i);
        // TODO: check whether value size of the node is greater than available_size? If so nentries is 0. Suppose
        // if a node contains one entry and the value size is much bigger than available size
        auto const nentries = old_nodes[i]->num_entries_by_size(0, available_size);
        if ((old_nodes[i]->total_entries() - nentries) == 0) { // Entire node goes in
            available_size -= old_nodes[i]->occupied_size();
            // For prefix nodes, compaction will make the size smaller, so we can compact saving to available size;
            // hence it cannot get negative.
            if (old_nodes[i]->get_node_type() == btree_node_type::PREFIX) {
                auto cur_node = static_cast< FixedPrefixNode< K, V >* >(old_nodes[i].get());
                available_size += cur_node->compact_saving();
            }
            BT_NODE_DBG_ASSERT_EQ(available_size >= 0, true, leftmost_node, "negative available size");
            if (i >= old_nodes.size() - 1) {
                src_cursor.ith_node = i + 1;
                src_cursor.nth_entry = std::numeric_limits< uint32_t >::max();
                leftmost_src.last_node_upto = nentries;
                BT_NODE_LOG(DEBUG, parent_node, "MERGE: no new nodes is supposed to be created");
            }
            // we reach the end so the "else" statement gets no chance to run
        } else {
            src_cursor.ith_node = i;
            src_cursor.nth_entry = nentries;
            leftmost_src.last_node_upto = nentries;
            break;
        }
    }

    // We are ready to keep copying all the old nodes from src cursor to new nodes
    available_size = 0;
    while (src_cursor.ith_node < old_nodes.size()) {
        if (available_size == 0) {
            new_node = leftmost_node->is_leaf() ? create_leaf_node(context) : create_interior_node(context);
            if (new_node == nullptr) {
                ret = btree_status_t::merge_failed;
                goto out;
            }
            new_node->set_level(leftmost_node->level());
            available_size = balanced_size;
            new_nodes.emplace_back(new_node);
        }

        auto& old_ith_node = old_nodes[src_cursor.ith_node];
        auto const nentries = new_node->copy_by_size(*old_ith_node, src_cursor.nth_entry, available_size);
        total_size -= new_node->occupied_size();
        if (old_ith_node->total_entries() == (src_cursor.nth_entry + nentries)) {
            // Copied entire node
            ++src_cursor.ith_node;
            src_cursor.nth_entry = 0;
            available_size = balanced_size - new_node->occupied_size();
        } else {
            //  If it is the last node supposed to be, check if the remaining entries can be copied and not creating
            //  a new nodes. This will make the last new node a little skewed from balanced size due to large
            //  key/values but avoid making extra new node.
            if (new_nodes.size() == num_nodes - 1 && total_size < new_node->available_size()) {
                available_size = new_node->available_size();
                src_cursor.nth_entry += nentries;
            } else {
                src_cursor.nth_entry += nentries;
                available_size = 0;
            }
        }
    }

    // There are degenerate case (especially if the first key/value is very big) that number of resultant nodes are
    // more than initial number of nodes before rebalance. In those cases, just give up the merging and hope for a
    // better merge next time.
    if (new_nodes.size() > old_nodes.size()) {
        ret = btree_status_t::merge_not_required;
        goto out;
    }

    // There is a case where we are rebalancing and the second node which rebalanced didn't move any size, in that
    // case the first node is going to be exactly same and we will do again merge, so bail out here.
    if ((new_nodes.size() == old_nodes.size()) && (old_nodes[0]->occupied_size() >= new_nodes[0]->occupied_size())) {
        ret = btree_status_t::merge_not_required;
        goto out;
    }

    if (!K::is_fixed_size()) {
        // we first calculate the least amount of space being released after removing excess children. the key size
        // cannot be taken account; so we know for sure that value (i.e., linkinfo) and also its record will be
        // freed. If the end_idx is the parent's edge, the space is not released eventually.
        auto excess_releasing_nodes =
            old_nodes.size() - new_nodes.size() - (parent_node->total_entries() == end_idx) ? 1 : 0;
        auto minimum_releasing_excess_size = excess_releasing_nodes * (BtreeLinkInfo::get_fixed_size());

        // aside from releasing size due to excess node, K::get_max_size is needed for each updating element
        // at worst case (linkinfo and record remain the same for old and new nodes). The number of updating
        // elements are the size of the new nodes (the last key of the last new node is not getting updated; hence
        // excluded) plus the leftmost node.
        if (parent_node->available_size() + minimum_releasing_excess_size <
            (1 + new_nodes.size() ? new_nodes.size() - 1 : 0) * K::get_max_size()) {
            BT_NODE_LOG(DEBUG, parent_node,
                        "Merge is needed, however after merge, the parent MAY not have enough space to accommodate the "
                        "new keys, so not proceeding with merge");
            ret = btree_status_t::merge_not_required;
            goto out;
        }
    }

    // Now it is time to commit things and at this point no going back, since in-place write nodes are modified
    {
        for (uint32_t i{0}; i < leftmost_src.ith_nodes.size(); ++i) {
            auto const idx = leftmost_src.ith_nodes[i];
            leftmost_node->copy_by_entries(*old_nodes[idx], 0,
                                           (i == leftmost_src.ith_nodes.size() - 1)
                                               ? leftmost_src.last_node_upto
                                               : std::numeric_limits< uint32_t >::max());
        }
        // std::string parent_node_step1 = parent_node->to_string();

        // First remove the excess entries between new nodes and old nodes
        auto excess = old_nodes.size() - new_nodes.size();
        if (excess) {
            parent_node->remove(start_idx + 1, start_idx + excess);
            end_idx -= excess;
        }

        // std::string parent_node_step2 = parent_node->to_string();

        // Update all the new node entries to parent and while iterating update their node links
        auto cur_idx = end_idx;
        BtreeNodePtr last_new_node = nullptr;
        bnodeid_t next_node_id = old_nodes.back()->next_bnode();
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            (*it)->set_next_bnode(next_node_id);
            auto this_node_id = (*it)->node_id();
            if ((*it)->total_entries())
                parent_node->update(cur_idx--, (*it)->get_last_key< K >(), BtreeLinkInfo{this_node_id, 0});
            last_new_node = *it;
            next_node_id = this_node_id;
        }

        // std::string parent_node_step3 = parent_node->to_string();

        // Finally update the leftmost node with latest key
        leftmost_node->set_next_bnode(next_node_id);
        if (leftmost_node->total_entries()) {
            leftmost_node->inc_link_version();
            parent_node->update(start_idx, leftmost_node->get_last_key< K >(), leftmost_node->link_info());
        }

        if (parent_node->total_entries() && !parent_node->has_valid_edge()) {
            if (parent_node->compare_nth_key(plast_key, parent_node->total_entries() - 1)) {
                auto last_node = new_nodes.size() > 0 ? new_nodes[new_nodes.size() - 1] : leftmost_node;
                last_node->inc_link_version();
                parent_node->update(parent_node->total_entries() - 1, plast_key, last_node->link_info());
            }
        }

#ifndef NDEBUG
        // BT_DBG_ASSERT(!parent_node_step1.empty() && !parent_node_step2.empty() && !parent_node_step3.empty(),
        //               "Empty string");
        // check if the link version of parent for each key info match the link version of its child
        BtreeLinkInfo child_info;
        if (ret == btree_status_t::success) {
            for (uint32_t idx = 0; idx < new_nodes.size(); idx++) {
                parent_node->get_nth_value(start_idx + 1 + idx, &child_info, false /* copy */);
                BT_NODE_DBG_ASSERT_EQ(child_info.link_version(), new_nodes[idx]->link_version(), parent_node,
                                      "mismatch of link version of new nodes in successful merge");
            }
            parent_node->get_nth_value(start_idx, &child_info, false /* copy */);
            BT_NODE_DBG_ASSERT_EQ(child_info.link_version(), leftmost_node->link_version(), parent_node,
                                  "parent_node, mismatch of link version of leftmost node in successful merge");
        } else {
            for (uint32_t idx = 0; idx < old_nodes.size(); idx++) {
                parent_node->get_nth_value(start_idx + 1 + idx, &child_info, false /* copy */);
                BT_NODE_DBG_ASSERT_EQ(child_info.link_version(), old_nodes[idx]->link_version(), parent_node,
                                      "mismatch of link version of old nodes in unsuccessful merge");
            }
            parent_node->get_nth_value(start_idx, &child_info, false /* copy */);
            BT_NODE_DBG_ASSERT_EQ(child_info.link_version(), leftmost_node->link_version(), parent_node,
                                  "parent_node, mismatch of link version of leftmost node in unsuccessful merge");
        }

        if (leftmost_node->total_entries() && (start_idx < parent_node->total_entries())) {
            BT_NODE_DBG_ASSERT_LE(
                leftmost_node->get_last_key< K >().compare(parent_node->get_nth_key< K >(start_idx, false)), 0,
                parent_node);
        }

        auto idx = start_idx + 1;
        for (const auto& node : new_nodes) {
            if (idx == parent_node->total_entries()) { break; }
            BT_NODE_DBG_ASSERT_GT(node->get_first_key< K >().compare(parent_node->get_nth_key< K >(idx - 1, false)), 0,
                                  parent_node);
            BT_NODE_DBG_ASSERT_LE(node->get_last_key< K >().compare(parent_node->get_nth_key< K >(idx, false)), 0,
                                  parent_node);
            ++idx;
        }
#endif

        ret = m_bt_private->transact_nodes(new_nodes, old_nodes, leftmost_node, parent_node, context);
    }

out:
    // Do free/unlock based on success/failure in reverse order
    if (ret != btree_status_t::success) {
        for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
            BT_NODE_LOG(DEBUG, (*it).get(), "Unlocking this node as part of unsuccessful merge");
            unlock_node(*it, locktype_t::WRITE);
        }
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            BT_NODE_LOG(DEBUG, (*it).get(), "Freeing this new node as part of unsuccessful merge");
            remove_node(*it, locktype_t::NONE, context);
        }
    }
    return ret;
}
#endif
} // namespace homestore
