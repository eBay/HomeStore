/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#include "btree/btree.hpp"

namespace homestore {
template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::do_remove(const BtreeNodePtr< K >& my_node, locktype_t curlock, ReqT& req) {
    btree_status_t ret = btree_status_t::success;
    if (my_node->is_leaf()) {
        BT_NODE_DBG_ASSERT_EQ(curlock, locktype_t::WRITE, my_node);

        uint32_t removed_count{0};
        bool modified{false};
#ifndef NDEBUG
        my_node->validate_key_order();
#endif

        if constexpr (std::is_same_v< ReqT, BtreeSingleRemoveRequest >) {
            if ((modified = my_node->remove_one(req.key(), nullptr, req.m_outval.get()))) { ++removed_count; }
        } else if constexpr (std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > >) {
            if (req.next_key().is_extent_key()) {
                modified = remove_extents_in_leaf(my_node, req);
            } else {
                auto& subrange = req.current_sub_range();
                auto const [start_found, start_idx] = my_node->find(subrange.start_key(), nullptr, false);
                auto [end_found, end_idx] = my_node->find(subrange.end_key(), nullptr, false);
                if (end_found) { ++end_idx; }
                for (auto idx{start_idx}; idx < end_idx; ++idx) {
                    call_on_remove_kv_cb(my_node, idx, req);
                    my_node->remove(idx);
                    modified = true;
                }
                removed_count = end_idx - start_idx;
            }
        } else if constexpr (std::is_same_v< ReqT, BtreeRemoveAnyRequest< K > >) {
            if ((modified = my_node->remove_any(req.m_range, req.m_outkey.get(), req.m_outval.get()))) {
                ++removed_count;
            }
        }
#ifndef NDEBUG
        my_node->validate_key_order();
#endif
        if (modified) {
            write_node(my_node, req.m_op_context);
            COUNTER_DECREMENT(m_metrics, btree_obj_count, removed_count);
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
    } else if constexpr (std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > >) {
        const auto count = my_node->template get_all< V >(req.next_range(), UINT32_MAX, start_idx, end_idx);
        BT_NODE_REL_ASSERT_NE(count, 0, my_node, "get_all returns 0 entries for interior node is not valid pattern");

    } else if constexpr (std::is_same_v< ReqT, BtreeRemoveAnyRequest< K > >) {
        const auto count = my_node->template get_all< V >(req.m_range, UINT32_MAX, start_idx, end_idx);
        BT_NODE_REL_ASSERT_NE(count, 0, my_node, "get_all returns 0 entries for interior node is not valid pattern");
        end_idx = start_idx = (end_idx - start_idx) / 2; // Pick the middle, TODO: Ideally we need to pick random
    }

    curr_idx = start_idx;
    while (curr_idx <= end_idx) {
        BtreeLinkInfo child_info;
        BtreeNodePtr< K > child_node;
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
                    unlock_node(child_node, locktype_t::WRITE);
                    child_cur_lock = locktype_t::NONE;
                    COUNTER_INCREMENT(m_metrics, btree_merge_count, 1);
                    goto retry;
                }
            }
        }

        // Get subrange if it is a range update
        if constexpr (std::is_same_v< ReqT, BtreeRangeRemoveRequest< K > >) {
            if (child_node->is_leaf()) {
                // We get the trimmed range only for leaf because this is where we will be removing keys. In interior
                // nodes, keys are always propogated from the lower nodes.
                bool is_inp_key_lesser;
                req.trim_working_range(
                    my_node->min_of(s_cast< const K& >(req.input_range().end_key()), curr_idx, is_inp_key_lesser),
                    is_inp_key_lesser ? req.input_range().is_end_inclusive() : true);

                BT_NODE_LOG(DEBUG, my_node, "Subrange:idx=[{}-{}],c={},working={}", start_idx, end_idx, curr_idx,
                            req.current_range().to_string());
            }
        }

#ifndef NDEBUG
        if (child_node->total_entries()) {
            if (curr_idx != my_node->total_entries()) { // not edge
                BT_NODE_DBG_ASSERT_LE(child_node->get_last_key().compare(my_node->get_nth_key(curr_idx, false)), 0,
                                      my_node);
            }

            if (curr_idx > 0) { // not first child
                BT_NODE_DBG_ASSERT_GT(child_node->get_first_key().compare(my_node->get_nth_key(curr_idx - 1, false)), 0,
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
        if (ret != btree_status_t::success) { break; }
        ++curr_idx;
    }

    // Warning: Do not access childNode or myNode beyond this point, since it would
    // have been unlocked by the recursive function and it could also been deleted.
    if (curlock != locktype_t::NONE) { unlock_node(my_node, curlock); }
    return ret;
}

template < typename K, typename V >
bool Btree< K, V >::remove_extents_in_leaf(const BtreeNodePtr< K >& node, BtreeRangeRemoveRequest< K >& rrreq) {
    if constexpr (std::is_base_of_v< ExtentBtreeKey< K >, K > && std::is_base_of_v< ExtentBtreeValue< V >, V >) {
        const BtreeKeyRange< K >& subrange = rrreq.working_range();
        const auto& start_key = static_cast< const ExtentBtreeKey< K >& >(subrange.start_key());
        const auto& end_key = static_cast< ExtentBtreeKey< K >& >(subrange.end_key());

        auto const [start_found, start_idx] = node->find(start_key, nullptr, false);
        auto const [end_found, end_idx] = node->find(end_key, nullptr, false);

        K h_k, t_k;
        V h_v, t_v;
        int64_t head_offset{0};
        int64_t tail_offset{0};
        ExtentBtreeKey< K >& head_k = static_cast< ExtentBtreeKey< K >& >(h_k);
        ExtentBtreeKey< K >& tail_k = static_cast< ExtentBtreeKey< K >& >(t_k);
        ExtentBtreeValue< V >& head_v = static_cast< ExtentBtreeValue< V >& >(h_v);
        ExtentBtreeValue< V >& tail_v = static_cast< ExtentBtreeValue< V >& >(t_v);

        if (start_found) {
            head_k = node->get_nth_key(start_idx, false);
            head_offset = head_k.distance_start(start_key);
            BT_NODE_DBG_ASSERT_GE(head_offset, 0, node, "Invalid start_key or head_k");
            if (head_offset > 0) { node->get_nth_value(start_idx, &head_v, false); }
        }
        if (end_found) {
            tail_k = node->get_nth_key(end_idx, false);
            tail_offset = end_key.distance_end(tail_k);
            BT_NODE_DBG_ASSERT_GE(tail_offset, 0, node, "Invalid end_key or tail_k");
            if (tail_offset > 0) { node->get_nth_value(end_idx, &tail_v, false); }
        }

        // Write partial head and tail kv. At this point we are committing and we can't go back and not update
        // some of the extents.
        auto idx = start_idx;
        if (end_idx == start_idx) {
            // Special case - where there is a overlap and single entry is split into 3
            auto const tail_start = tail_k.extent_length() - tail_offset;
            if (m_on_remove_cb) {
                m_on_remove_cb(head_k.extract(head_offset, tail_start - head_offset, false),
                               head_v.extract(head_offset, tail_start - head_offset, false), rrreq);
            }

            if (tail_offset > 0) {
                node->insert(end_idx + 1, tail_k.extract(tail_start, tail_offset, false),
                             tail_v.extract(tail_start, tail_offset, false));
                COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
            }

            if (head_offset > 0) {
                node->update(idx++, head_k.extract(0, head_offset, false), head_v.extract(0, head_offset, false));
            }
        } else {
            if (tail_offset > 0) {
                auto const tail_start = tail_k.extent_length() - tail_offset;
                auto const shrunk_k = tail_k.extract(tail_start, tail_offset, false);
                call_on_update_kv_cb(node, end_idx, shrunk_k, rrreq);
                node->update(end_idx, shrunk_k, tail_v.extract(tail_start, tail_offset, false));
            } else if (end_found) {
                ++end_idx;
            }
            if (head_offset > 0) {
                auto const shrunk_k = head_k.extract(0, -head_offset, false);
                call_on_update_kv_cb(node, idx, shrunk_k, rrreq);
                node->update(idx++, shrunk_k, head_v.extract(0, -head_offset, false));
            }
        }

        // Remove everything in-between
        if (idx < end_idx) {
            if (m_on_remove_cb) {
                for (auto i{idx}; i <= end_idx; ++i) {
                    call_on_remove_kv_cb(node, i, rrreq);
                }
            }
            node->remove(idx, end_idx - 1);
            COUNTER_DECREMENT(m_metrics, btree_obj_count, end_idx - idx);
        }
        return true;
    } else {
        BT_REL_ASSERT(false, "Don't expect remove_extents to be called on non-extent code path");
        return false;
    }
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::check_collapse_root(ReqT& req) {
    BtreeNodePtr< K > child;
    BtreeNodePtr< K > root;
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
btree_status_t Btree< K, V >::merge_nodes(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& leftmost_node,
                                          uint32_t start_idx, uint32_t end_idx, void* context) {
    btree_status_t ret{btree_status_t::success};
    folly::small_vector< BtreeNodePtr< K >, 3 > old_nodes;
    folly::small_vector< BtreeNodePtr< K >, 3 > new_nodes;
    BtreeNodePtr< K > new_node;
    uint32_t total_size{0};
    uint32_t balanced_size{0};
    uint32_t available_size{0};
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

    _leftmost_src_info leftmost_src;
    _src_cursor_info src_cursor;

    total_size = leftmost_node->occupied_size(m_bt_cfg);
    for (auto indx = start_idx + 1; indx <= end_idx; ++indx) {
        if (indx == parent_node->total_entries()) {
            BT_NODE_LOG_ASSERT(parent_node->has_valid_edge(), parent_node,
                               "Assertion failure, expected valid edge for parent_node: {}");
        }

        BtreeLinkInfo child_info;
        parent_node->get_nth_value(indx, &child_info, false /* copy */);

        BtreeNodePtr< K > child;
        ret = read_and_lock_node(child_info.bnode_id(), child, locktype_t::WRITE, locktype_t::WRITE, context);
        if (ret != btree_status_t::success) { goto out; }
        BT_NODE_LOG_ASSERT_EQ(child->is_valid_node(), true, child);

        old_nodes.push_back(child);
        total_size += child->occupied_size(m_bt_cfg);
    }

    // Determine if packing the nodes would result in reducing the number of nodes, if so go with that. If else
    // we revert back to rebalancing the nodes.
    num_nodes = (total_size - 1) / m_bt_cfg.ideal_fill_size() + 1;
    if (num_nodes >= (old_nodes.size() + 1)) {
        // Only option is to rebalance the nodes across. If we are asked not to do so, skip it.
        if (!m_bt_cfg.m_rebalance_turned_on) {
            ret = btree_status_t::merge_not_required;
            goto out;
        }
    }

    balanced_size = (total_size - 1) / num_nodes + 1;
    if (leftmost_node->occupied_size(m_bt_cfg) > balanced_size) {
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
    available_size = balanced_size - leftmost_node->occupied_size(m_bt_cfg);
    src_cursor.ith_node = old_nodes.size();
    for (uint32_t i{0}; (i < old_nodes.size()) && (available_size > 0); ++i) {
        leftmost_src.ith_nodes.push_back(i);
        auto const nentries = old_nodes[i]->num_entries_by_size(0, available_size);
        if ((old_nodes[i]->total_entries() - nentries) == 0) { // Entire node goes in
            available_size -= old_nodes[i]->occupied_size(m_bt_cfg);
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
            new_node = alloc_node(leftmost_node->is_leaf());
            if (new_node == nullptr) {
                ret = btree_status_t::merge_failed;
                goto out;
            }
            available_size = balanced_size;
            new_nodes.emplace_back(new_node);
        }

        auto const nentries =
            new_node->copy_by_size(m_bt_cfg, *old_nodes[src_cursor.ith_node], src_cursor.nth_entry, available_size);
        if (old_nodes[src_cursor.ith_node]->total_entries() == (src_cursor.nth_entry + nentries)) {
            // Copied entire node
            ++src_cursor.ith_node;
            src_cursor.nth_entry = 0;
            available_size = balanced_size - new_node->occupied_size(m_bt_cfg);
        } else {
            src_cursor.nth_entry += nentries;
            available_size = 0;
        }
    }

    // There are degenerate case (especially if the first key/value is very big) that number of resultant nodes are
    // more than initial number of nodes before rebalance. In those cases, just give up the merging and hope for a
    // better merge next time.
    if (new_nodes.size() > old_nodes.size()) {
        ret = btree_status_t::merge_not_required;
        goto out;
    }

    if (!K::is_fixed_size()) {
        // Lets see if we have enough room in parent node to accomodate changes. This is needed only if the key is not
        // fixed length. For fixed length node merge will always result in lesser or equal size
        int64_t post_merge_size{0};
        auto& old_node = old_nodes[leftmost_src.ith_nodes.back()];
        if (old_node->total_entries()) {
            post_merge_size += old_node->get_nth_obj_size(
                std::min(leftmost_src.last_node_upto, old_node->total_entries() - 1)); // New leftmost entry
        }
        post_merge_size -= parent_node->get_nth_obj_size(start_idx); // Previous left entry

        for (auto& node : new_nodes) {
            if (node->total_entries()) { post_merge_size += node->get_nth_obj_size(node->total_entries() - 1); }
        }

        for (auto& node : old_nodes) {
            if (node->total_entries()) { post_merge_size -= node->get_nth_obj_size(node->total_entries() - 1); }
        }

        if (post_merge_size > parent_node->available_size(m_bt_cfg)) {
            BT_NODE_LOG(DEBUG, parent_node,
                        "Merge is needed, however after merge it will add {} bytes which is more than "
                        "available_size={}, so not proceeding with merge",
                        post_merge_size, parent_node->available_size(m_bt_cfg));
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
        std::string parent_node_step1 = parent_node->to_string();

        // First remove the excess entries between new nodes and old nodes
        auto excess = old_nodes.size() - new_nodes.size();
        if (excess) {
            parent_node->remove(start_idx + 1, start_idx + excess);
            end_idx -= excess;
        }

        std::string parent_node_step2 = parent_node->to_string();

        // Update all the new node entries to parent and while iterating update their node links
        auto cur_idx = end_idx;
        BtreeNodePtr< K > last_new_node = nullptr;
        bnodeid_t next_node_id = old_nodes.back()->next_bnode();
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            (*it)->set_next_bnode(next_node_id);
            auto this_node_id = (*it)->node_id();
            parent_node->update(cur_idx--, (*it)->get_last_key(), BtreeLinkInfo{this_node_id, 0});
            last_new_node = *it;
            next_node_id = this_node_id;
        }

        std::string parent_node_step3 = parent_node->to_string();

        // Finally update the leftmost node with latest key
        leftmost_node->inc_link_version();
        leftmost_node->set_next_bnode(next_node_id);
        parent_node->update(start_idx, leftmost_node->get_last_key(), leftmost_node->link_info());

#if 0
        /////////// Old code /////////////
        // Update the parent node from right to left and remove anything that is excess. While iterating
        // write the nodes with appropriate dependencies
        auto cur_idx = end_idx;
        BtreeNodePtr< K > last_new_node = nullptr;
        bnodeid_t next_node_id = old_nodes.back()->next_bnode();
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            (*it)->set_next_bnode(next_node_id);
            auto this_node_id = (*it)->node_id();
            parent_node->update(cur_idx--, (*it)->get_last_key(), BtreeLinkInfo{this_node_id, 0});
            last_new_node = *it;
            next_node_id = this_node_id;
        }
        leftmost_node->inc_link_version();
        leftmost_node->set_next_bnode(next_node_id);
        std::string parent_node_step2 = parent_node->to_string();
        if (cur_idx == parent_node->total_entries()) {
            // We do, update the left node where the merge was started and remove newly added
        }
        parent_node->update(cur_idx--, leftmost_node->get_last_key(), leftmost_node->link_info());
        std::string parent_node_step3 = parent_node->to_string();
        parent_node->remove(start_idx, cur_idx);
#endif

#ifndef NDEBUG
        BT_DBG_ASSERT(!parent_node_step1.empty() && !parent_node_step2.empty() && !parent_node_step3.empty(),
                      "Empty string");
        if (leftmost_node->total_entries() && (start_idx < parent_node->total_entries())) {
            BT_NODE_DBG_ASSERT_LE(leftmost_node->get_last_key().compare(parent_node->get_nth_key(start_idx, false)), 0,
                                  parent_node);
        }

        auto idx = start_idx + 1;
        for (const auto& node : new_nodes) {
            if (idx == parent_node->total_entries()) { break; }
            BT_NODE_DBG_ASSERT_GT(node->get_first_key().compare(parent_node->get_nth_key(idx - 1, false)), 0,
                                  parent_node);
            BT_NODE_DBG_ASSERT_LE(node->get_last_key().compare(parent_node->get_nth_key(idx, false)), 0, parent_node);
            ++idx;
        }
#endif

        transact_write_nodes(new_nodes, leftmost_node, parent_node, context);
    }

out:
    // Do free/unlock based on success/failure in reverse order
    if (ret == btree_status_t::success) {
        for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
            free_node(*it, locktype_t::WRITE, context);
        }
    } else {
        for (auto it = old_nodes.rbegin(); it != old_nodes.rend(); ++it) {
            unlock_node(*it, locktype_t::WRITE);
        }
        for (auto it = new_nodes.rbegin(); it != new_nodes.rend(); ++it) {
            free_node(*it, locktype_t::NONE, context);
        }
    }
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::repair_merge(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& left_child,
                                           uint32_t parent_merge_idx, void* context) {
    btree_status_t ret = btree_status_t::success;
    uint32_t upto_idx;
    folly::small_vector< BtreeNodePtr< K >, 3 > old_nodes;
    folly::small_vector< BtreeNodePtr< K >, 3 > new_nodes;
    bnodeid_t next_nodeid;

    // Get next 2 entries after left child which were merge would have happend, from parent point of view. The 2 entries
    // is an example, but generically it is m_max_merge_nodes - 1 from left child are gathered.
    for (auto idx = parent_merge_idx + 1; idx <= parent_merge_idx + m_bt_cfg.m_max_merge_nodes; ++idx) {
        BtreeNodePtr< K > child_node;
        BtreeLinkInfo child_info;
        ret = get_child_and_lock_node(parent_node, idx, child_info, child_node, locktype_t::WRITE, locktype_t::WRITE,
                                      context);
        if (ret != btree_status_t::success) { goto done; }
        old_nodes.push_back(std::move(child_node));
    }

    // Collect same amount from child perspective
    next_nodeid = left_child->next_bnode();
    for (uint32_t i{0}; (i < m_bt_cfg.m_max_merge_nodes) && (next_nodeid != empty_bnodeid); ++i) {
        BtreeNodePtr< K > child_node;
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
        parent_node->insert(parent_merge_idx + 1 + i, new_nodes[i]->get_last_key(),
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

#if 0
template < typename K, typename V >
btree_status_t Btree< K, V >::merge_nodes(const BtreeNodePtr< K >& parent_node, uint32_t start_idxx, uint32_t end_idxx,
                                          void* context) {
    btree_status_t ret = btree_status_t::merge_failed;
    std::vector< BtreeNodePtr< K > > child_nodes;
    std::vector< BtreeNodePtr< K > > old_nodes;
    std::vector< BtreeNodePtr< K > > replace_nodes;
    std::vector< BtreeNodePtr< K > > new_nodes;
    std::vector< BtreeNodePtr< K > > deleted_nodes;
    BtreeNodePtr< K > left_most_node;
    K last_pkey; // last key of parent node
    bool last_pkey_valid = false;
    uint32_t balanced_size;
    BtreeNodePtr< K > merge_node;
    K last_ckey; // last key in child
    uint32_t parent_insert_indx = start_idxx;
#ifndef NDEBUG
    uint32_t total_child_entries = 0;
    uint32_t new_entries = 0;
    K last_debug_ckey;
    K new_last_debug_ckey;
    BtreeNodePtr< K > last_node;
#endif
    K child_pkey;

    /* Try to take a lock on all nodes participating in merge*/
    for (auto indx = start_idxx; indx <= end_idxx; ++indx) {
        if (indx == parent_node->total_entries()) {
            BT_NODE_LOG_ASSERT(parent_node->has_valid_edge(), parent_node,
                               "Assertion failure, expected valid edge for parent_node: {}");
        }

        BtreeLinkInfo child_info;
        parent_node->get_nth_value(indx, &child_info, false /* copy */);

        BtreeNodePtr< K > child;
        ret = read_and_lock_node(child_info.bnode_id(), child, locktype_t::WRITE, locktype_t::WRITE, context);
        if (ret != btree_status_t::success) { goto out; }
        BT_NODE_LOG_ASSERT_EQ(child->is_valid_node(), true, child);

        /* check if left most node has space */
        if (indx == start_idxx) {
            balanced_size = m_bt_cfg.ideal_fill_size();
            left_most_node = child;
            if (left_most_node->occupied_size(m_bt_cfg) > balanced_size) {
                /* first node doesn't have any free space. we can exit now */
                ret = btree_status_t::merge_not_required;
                goto out;
            }
        } else {
            bool is_allocated = true;
            /* pre allocate the new nodes. We will free the nodes which are not in use later */
            auto new_node = alloc_node(child->is_leaf(), is_allocated, child);
            if (is_allocated) {
                /* we are going to allocate new blkid of all the nodes except the first node.
                 * Note :- These blkids will leak if we fail or crash before writing entry into
                 * journal.
                 */
                old_nodes.push_back(child);
                COUNTER_INCREMENT_IF_ELSE(m_metrics, child->is_leaf(), btree_leaf_node_count, btree_int_node_count, 1);
            }
            /* Blk IDs can leak if it crash before writing it to a journal */
            if (new_node == nullptr) {
                ret = btree_status_t::space_not_avail;
                goto out;
            }
            new_nodes.push_back(new_node);
        }
#ifndef NDEBUG
        total_child_entries += child->total_entries();
        last_debug_ckey = child->get_last_key();
#endif
        child_nodes.push_back(child);
    }

    if (end_idxx != parent_node->total_entries()) {
        /* If it is not edge we always preserve the last key in a given merge group of nodes.*/
        parent_node->get_nth_key(end_idxx, last_pkey, true);
        last_pkey_valid = true;
    }

    merge_node = left_most_node;
    /* We can not fail from this point. Nodes will be modified in memory. */
    for (uint32_t i = 0; i < new_nodes.size(); ++i) {
        auto occupied_size = merge_node->occupied_size(m_bt_cfg);
        if (occupied_size < balanced_size) {
            uint32_t pull_size = balanced_size - occupied_size;
            merge_node->move_in_from_right_by_size(m_bt_cfg, *(new_nodes[i]), pull_size);
            if (new_nodes[i]->total_entries() == 0) {
                /* this node is freed */
                deleted_nodes.push_back(new_nodes[i]);
                continue;
            }
        }

        /* update the last key of merge node in parent node */
        last_ckey = merge_node->get_last_key(); // last key in child
        BtreeLinkInfo ninfo(merge_node->node_id());
        parent_node->update(parent_insert_indx, last_ckey, ninfo);
        ++parent_insert_indx;

        merge_node->set_next_bnode(new_nodes[i]->node_id()); // link them
        merge_node = new_nodes[i];
        if (merge_node != left_most_node) {
            /* left most node is not replaced */
            replace_nodes.push_back(merge_node);
        }
    }

    /* update the latest merge node */
    last_ckey = merge_node->get_last_key();
    if (last_pkey_valid) {
        BT_NODE_DBG_ASSERT_LE(last_ckey.compare(last_pkey), 0, parent_node);
        last_ckey = last_pkey;
    }

    /* update the last key */
    {
        BtreeLinkInfo ninfo(merge_node->node_id());
        parent_node->update(parent_insert_indx, last_ckey, ninfo);
        ++parent_insert_indx;
    }

    /* remove the keys which are no longer used */
    if ((parent_insert_indx) <= end_idxx) { parent_node->remove(parent_insert_indx, end_idxx); }

    // TODO: Validate if empty child_pkey on last_key or edge has any impact on journal/precommit
    if (start_idxx < parent_node->total_entries()) {
        child_pkey = parent_node->get_nth_key(start_idxx, true);
        BT_NODE_REL_ASSERT_EQ(start_idxx, (parent_insert_indx - 1), parent_node, "it should be last index");
    }

    merge_node_precommit(false, parent_node, parent_insert_indx, left_most_node, &old_nodes, &replace_nodes, context);

#if 0
    /* write the journal entry */
    if (BtreeStoreType == btree_store_type::SSD_BTREE) {
        auto j_iob = btree_store_t::make_journal_entry(journal_op::BTREE_MERGE, false /* is_root */, bcp,
                                                       {parent_node->node_id(), parent_node->node_gen()});
        K child_pkey;
        if (start_idxx < parent_node->total_entries()) {
            parent_node->get_nth_key(start_idxx, &child_pkey, true);
            BT_REL_ASSERT_CMP(start_idxx, ==, (parent_insert_indx - 1), parent_node, "it should be last index");
        }
        btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::inplace_write, left_most_node, bcp,
                                              child_pkey.get_blob());
        for (auto& node : old_nodes) {
            btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::removal, node, bcp);
        }
        uint32_t insert_indx = 0;
        for (auto& node : replace_nodes) {
            K child_pkey;
            if ((start_idxx + insert_indx) < parent_node->total_entries()) {
                parent_node->get_nth_key(start_idxx + insert_indx, &child_pkey, true);
                BT_REL_ASSERT_CMP((start_idxx + insert_indx), ==, (parent_insert_indx - 1), parent_node,
                                      "it should be last index");
            }
            btree_store_t::append_node_to_journal(j_iob, bt_journal_node_op::creation, node, bcp,
                                                  child_pkey.get_blob());
            ++insert_indx;
        }
        BT_REL_ASSERT_CMP((start_idxx + insert_indx), ==, parent_insert_indx, parent_node, "it should be same");
        btree_store_t::write_journal_entry(m_btree_store.get(), bcp, j_iob);
    }
#endif

    if (replace_nodes.size() > 0) {
        /* write the right most node */
        write_node(replace_nodes[replace_nodes.size() - 1], nullptr, context);
        if (replace_nodes.size() > 1) {
            /* write the middle nodes */
            for (int i = replace_nodes.size() - 2; i >= 0; --i) {
                write_node(replace_nodes[i], replace_nodes[i + 1], context);
            }
        }
        /* write the left most node */
        write_node(left_most_node, replace_nodes[0], context);
    } else {
        /* write the left most node */
        write_node(left_most_node, nullptr, context);
    }

    /* write the parent node */
    write_node(parent_node, left_most_node, context);

#ifndef NDEBUG
    for (const auto& n : replace_nodes) {
        new_entries += n->total_entries();
    }

    new_entries += left_most_node->total_entries();
    BT_DBG_ASSERT_EQ(total_child_entries, new_entries);

    if (replace_nodes.size()) {
        replace_nodes[replace_nodes.size() - 1]->get_last_key(&new_last_debug_ckey);
        last_node = replace_nodes[replace_nodes.size() - 1];
    } else {
        new_last_debug_ckey = left_most_node->get_last_key();
        last_node = left_most_node;
    }
    if (last_debug_ckey.compare(&new_last_debug_ckey) != 0) {
        LOGINFO("{}", last_node->to_string());
        if (deleted_nodes.size() > 0) { LOGINFO("{}", (deleted_nodes[deleted_nodes.size() - 1]->to_string())); }
        BT_DBG_ASSERT(false, "compared failed");
    }
#endif
    /* free nodes. It actually gets freed after cp is completed */
    for (const auto& n : old_nodes) {
        free_node(n, locktype_t::WRITE, context);
    }
    for (const auto& n : deleted_nodes) {
        free_node(n, locktype_t::WRITE, context);
    }
    ret = btree_status_t::success;
out:
#ifndef NDEBUG
    uint32_t freed_entries = deleted_nodes.size();
    uint32_t scan_entries = end_idxx - start_idxx - freed_entries + 1;
    for (uint32_t i = 0; i < scan_entries; ++i) {
        if (i < (scan_entries - 1)) { validate_sanity_next_child(parent_node, (uint32_t)start_idxx + i); }
        validate_sanity_child(parent_node, (uint32_t)start_idxx + i);
    }
#endif
    // Loop again in reverse order to unlock the nodes. freeable nodes need to be unlocked and freed
    for (uint32_t i = child_nodes.size() - 1; i != 0; i--) {
        unlock_node(child_nodes[i], locktype_t::WRITE);
    }
    unlock_node(child_nodes[0], locktype_t::WRITE);
    if (ret != btree_status_t::success) {
        /* free the allocated nodes */
        for (const auto& n : new_nodes) {
            free_node(n, locktype_t::WRITE, context);
        }
    }
    return ret;
}
#endif
} // namespace homestore
