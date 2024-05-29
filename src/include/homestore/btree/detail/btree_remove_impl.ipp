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
btree_status_t Btree< K, V >::do_remove(const BtreeNodePtr& my_node, locktype_t curlock, ReqT& req) {
    btree_status_t ret = btree_status_t::success;
    btree_status_t at_least_one_child_modified = btree_status_t::not_found;
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
            if (req.route_tracing) { append_route_trace(req, my_node, btree_event_t::REMOVE); }
        }

        unlock_node(my_node, curlock);
        return modified ? btree_status_t::success : btree_status_t::not_found;
    }

retry:
    locktype_t child_cur_lock = locktype_t::NONE;
    uint32_t curr_idx;
    uint32_t start_idx{0};
    uint32_t end_idx{0};

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

    if (req.route_tracing) { append_route_trace(req, my_node, btree_event_t::READ, start_idx, end_idx); }
    curr_idx = start_idx;
    while (curr_idx <= end_idx) {
        BtreeLinkInfo child_info;
        BtreeNodePtr child_node;
        ret = get_child_and_lock_node(my_node, curr_idx, child_info, child_node, locktype_t::READ, locktype_t::WRITE,
                                      req.m_op_context);
        if (ret != btree_status_t::success) {
            unlock_node(my_node, curlock);
            return ret;
        }

        // Check if child node is minimal.
        child_cur_lock = child_node->is_leaf() ? locktype_t::WRITE : locktype_t::READ;
        if (child_node->is_merge_needed(m_bt_cfg) || is_repair_needed(child_node, child_info)) {
            uint32_t node_end_idx = my_node->total_entries();
            if (!my_node->has_valid_edge()) { --node_end_idx; }
            if (node_end_idx > (curr_idx + m_bt_cfg.m_max_merge_nodes - 1)) {
                node_end_idx = curr_idx + m_bt_cfg.m_max_merge_nodes - 1;
            }

            if (node_end_idx > curr_idx) {
                // If we are unable to upgrade the node, ask the caller to retry.
                ret = upgrade_node_locks(my_node, child_node, curlock, child_cur_lock, req.m_op_context);
                if (ret != btree_status_t::success) { return ret; }
                curlock = child_cur_lock = locktype_t::WRITE;

                if (is_repair_needed(child_node, child_info)) {
                    ret = repair_merge(my_node, child_node, curr_idx, req.m_op_context);
                } else {
                    ret = merge_nodes(my_node, child_node, curr_idx, node_end_idx, req.m_op_context);
                }

                if ((ret != btree_status_t::success) && (ret != btree_status_t::merge_not_required)) {
                    unlock_node(child_node, locktype_t::WRITE);
                    unlock_node(my_node, locktype_t::WRITE);
                    return ret;
                }

                if (ret == btree_status_t::success) {
                    if (req.route_tracing) { append_route_trace(req, child_node, btree_event_t::MERGE); }
                    unlock_node(child_node, locktype_t::WRITE);
                    child_cur_lock = locktype_t::NONE;
                    COUNTER_INCREMENT(m_metrics, btree_merge_count, 1);
                    goto retry;
                }

                if (ret == btree_status_t::merge_not_required) {
                    BT_NODE_LOG(DEBUG, my_node, "merge is not required for child = {} keys: {}", curr_idx,
                                child_node->to_string_keys());
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
            unlock_node(my_node, curlock);
            curlock = locktype_t::NONE;
        }

        ret = do_remove(child_node, child_cur_lock, req);
        if (ret == btree_status_t::success) { at_least_one_child_modified = btree_status_t::success; }
        ++curr_idx;
    }

out_return:
    // Warning: Do not access childNode or myNode beyond this point, since it would
    // have been unlocked by the recursive function and it could also been deleted.
    if (curlock != locktype_t::NONE) { unlock_node(my_node, curlock); }
    return (at_least_one_child_modified == btree_status_t::success) ? btree_status_t::success : ret;
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

    if (req.route_tracing) { append_route_trace(req, root, btree_event_t::MERGE); }

    free_node(root, locktype_t::WRITE, req.m_op_context);
    m_root_node_info = child->link_info();
    unlock_node(child, locktype_t::WRITE);

    // TODO: Have a precommit code here to notify the change in root node id
    COUNTER_DECREMENT(m_metrics, btree_depth, 1);

done:
    m_btree_lock.unlock();
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::merge_nodes(const BtreeNodePtr& parent_node, const BtreeNodePtr& leftmost_node,
                                          uint32_t start_idx, uint32_t end_idx, void* context) {
    if (!m_bt_cfg.m_merge_turned_on) { return btree_status_t::merge_not_required; }
    btree_status_t ret{btree_status_t::success};
    folly::small_vector< BtreeNodePtr, 3 > old_nodes;
    folly::small_vector< BtreeNodePtr, 3 > new_nodes;
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
        BT_NODE_LOG_ASSERT_EQ(child->is_valid_node(), true, child);

        old_nodes.push_back(child);
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
    // leftmost node as special case without moving, because that is the only node which is modified in-place and hence
    // doing a dry run and if for some reason there is a problem in balancing the nodes, then it is easy to give up.
    available_size = static_cast< int32_t >(balanced_size) - leftmost_node->occupied_size();
    src_cursor.ith_node = old_nodes.size();
    for (uint32_t i{0}; (i < old_nodes.size() && available_size >= 0); ++i) {
        leftmost_src.ith_nodes.push_back(i);
        // TODO: check whether value size of the node is greater than available_size? If so nentries is 0. Suppose if a
        // node contains one entry and the value size is much bigger than available size
        auto const nentries = old_nodes[i]->num_entries_by_size(0, available_size);
        if ((old_nodes[i]->total_entries() - nentries) == 0) { // Entire node goes in
            available_size -= old_nodes[i]->occupied_size();
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
            new_node.reset(alloc_node(leftmost_node->is_leaf()).get());
            if (new_node == nullptr) {
                ret = btree_status_t::merge_failed;
                goto out;
            }
            new_node->set_level(leftmost_node->level());
            available_size = balanced_size;
            new_nodes.emplace_back(new_node);
        }

        auto& old_ith_node = old_nodes[src_cursor.ith_node];
        auto const nentries = new_node->copy_by_size(m_bt_cfg, *old_ith_node, src_cursor.nth_entry, available_size);
        total_size -= new_node->occupied_size();
        if (old_ith_node->total_entries() == (src_cursor.nth_entry + nentries)) {
            // Copied entire node
            ++src_cursor.ith_node;
            src_cursor.nth_entry = 0;
            available_size = balanced_size - new_node->occupied_size();
        } else {
            //  If it is the last node supposed to be, check if the remaining entries can be copied and not creating a
            //  new nodes. This will make the last new node a little skewed from balanced size due to large key/values but
            //  avoid making extra new node.
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

    // There is a case where we are rebalancing and the second node which rebalanced didn't move any size, in that case
    // the first node is going to be exactly same and we will do again merge, so bail out here.
    if ((new_nodes.size() == old_nodes.size()) && (old_nodes[0]->occupied_size() >= new_nodes[0]->occupied_size())) {
        ret = btree_status_t::merge_not_required;
        goto out;
    }

    if (!K::is_fixed_size()) {
#if 0
        // Lets see if we have enough room in parent node to accommodate changes. This is needed only if the key is not
        // fixed length. For fixed length node merge will always result in less or equal size
        auto excess_releasing_nodes =
            old_nodes.size() - new_nodes.size() - (parent_node->total_entries() == end_idx) ? 1 : 0;
        if (!parent_node->has_room_for_put(btree_put_type::INSERT, excess_releasing_nodes * K::get_max_size(),
                                           excess_releasing_nodes * BtreeLinkInfo::get_fixed_size())) {
            BT_NODE_LOG(DEBUG, parent_node,
                        "Merge is needed, however after merge, the parent MAY not have enough space to accommodate the "
                        "new keys, so not proceeding with merge");
            ret = btree_status_t::merge_not_required;
            goto out;
        }

#endif
        // we first calculate the least amount of space being released after removing excess children. the key size
        // cannot be taken account; so we know for sure that value (i.e., linkinfo) and also its record will be freed.
        // If the end_idx is the parent's edge, the space is not released eventually.
        auto excess_releasing_nodes =
            old_nodes.size() - new_nodes.size() - (parent_node->total_entries() == end_idx) ? 1 : 0;
        auto minimum_releasing_excess_size = excess_releasing_nodes * (BtreeLinkInfo::get_fixed_size());

        // aside from releasing size due to excess node, K::get_max_size is needed for each updating element
        // at worst case (linkinfo and record remain the same for old and new nodes). The number of updating elements
        // are the size of the new nodes (the last key of the last new node is not getting updated; hence excluded) plus
        // the leftmost node.
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
            leftmost_node->copy_by_entries(m_bt_cfg, *old_nodes[idx], 0,
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

#if 0
        /////////// Old code /////////////
        // Update the parent node from right to left and remove anything that is excess. While iterating
        // write the nodes with appropriate dependencies
        auto cur_idx = end_idx;
        BtreeNodePtr last_new_node = nullptr;
        bnodeid_t next_node_id = old_nodes.back()->next_bnode();
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            (*it)->set_next_bnode(next_node_id);
            auto this_node_id = (*it)->node_id();
            parent_node->update(cur_idx--, (*it)->get_last_key< K >(), BtreeLinkInfo{this_node_id, 0});
            last_new_node = *it;
            next_node_id = this_node_id;
        }
        leftmost_node->inc_link_version();
        leftmost_node->set_next_bnode(next_node_id);
        std::string parent_node_step2 = parent_node->to_string();
        if (cur_idx == parent_node->total_entries()) {
            // We do, update the left node where the merge was started and remove newly added
        }
        parent_node->update(cur_idx--, leftmost_node->get_last_key< K >(), leftmost_node->link_info());
        std::string parent_node_step3 = parent_node->to_string();
        parent_node->remove(start_idx, cur_idx);
#endif

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

        transact_write_nodes(new_nodes, leftmost_node, parent_node, context);
    }

out:
    // Do free/unlock based on success/failure in reverse order
    if (ret == btree_status_t::success) {
        for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
            BT_NODE_LOG(DEBUG, (*it).get(), "Freeing this node as part of successful merge");
            free_node(*it, locktype_t::WRITE, context);
        }
    } else {
        for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
            BT_NODE_LOG(DEBUG, (*it).get(), "Unlocking this node as part of unsuccessful merge");
            unlock_node(*it, locktype_t::WRITE);
        }
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            BT_NODE_LOG(DEBUG, (*it).get(), "Freeing this new node as part of unsuccessful merge");
            free_node(*it, locktype_t::NONE, context);
        }
    }
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::repair_merge(const BtreeNodePtr& parent_node, const BtreeNodePtr& left_child,
                                           uint32_t parent_merge_idx, void* context) {
    btree_status_t ret = btree_status_t::success;
    uint32_t upto_idx;
    folly::small_vector< BtreeNodePtr, 3 > old_nodes;
    folly::small_vector< BtreeNodePtr, 3 > new_nodes;
    bnodeid_t next_nodeid;

    // Get next 2 entries after left child which were merge would have happend, from parent point of view. The 2 entries
    // is an example, but generically it is m_max_merge_nodes - 1 from left child are gathered.
    for (auto idx = parent_merge_idx + 1; idx <= parent_merge_idx + m_bt_cfg.m_max_merge_nodes; ++idx) {
        BtreeNodePtr child_node;
        BtreeLinkInfo child_info;
        ret = get_child_and_lock_node(parent_node, idx, child_info, child_node, locktype_t::WRITE, locktype_t::WRITE,
                                      context);
        if (ret != btree_status_t::success) { goto done; }
        old_nodes.push_back(std::move(child_node));
    }

    // Collect same amount from child perspective
    next_nodeid = left_child->next_bnode();
    for (uint32_t i{0}; (i < m_bt_cfg.m_max_merge_nodes) && (next_nodeid != empty_bnodeid); ++i) {
        BtreeNodePtr child_node;
        ret = read_and_lock_node(next_nodeid, child_node, locktype_t::READ, locktype_t::READ, context);
        if (ret != btree_status_t::success) { goto done; }

        next_nodeid = child_node->next_bnode();
        new_nodes.push_back(std::move(child_node));
    }

    // Now do a diff between old and new and anything not found from old in new nodes has to be removed.
    upto_idx = new_nodes.size();
    for (auto& old_node : old_nodes) {
        for (uint32_t new_idx{0}; new_idx < new_nodes.size(); ++new_idx) {
            if (old_node->node_id() == new_nodes[new_idx]->node_id()) {
                upto_idx = std::min(upto_idx, new_idx);
                break;
            }
        }
        if (upto_idx < new_nodes.size()) { break; }
        parent_node->remove(parent_merge_idx + 1);
    }

    BT_NODE_REL_ASSERT_LE(upto_idx, old_nodes.size(), parent_node);
    for (uint32_t i{0}; i < upto_idx; ++i) {
        parent_node->insert(parent_merge_idx + 1 + i, new_nodes[i]->get_last_key< K >(),
                            BtreeLinkInfo{new_nodes[i]->node_id(), left_child->link_version()});
    }
    parent_node->update(parent_merge_idx, left_child->link_info());
    ret = transact_write_nodes(new_nodes, left_child, parent_node, context);

done:
    for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
        unlock_node(*it, locktype_t::READ);
    }

    for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
        (ret == btree_status_t::success) ? free_node(*it, locktype_t::WRITE, context)
                                         : unlock_node(*it, locktype_t::READ);
    }
    return ret;
}
} // namespace homestore
