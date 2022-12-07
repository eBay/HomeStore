/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal, Harihara Kadayam
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

template < typename K >
static bool is_repair_needed(const BtreeNodePtr< K >& child_node, const BtreeLinkInfo& child_info) {
    return child_info.link_version() != child_node->link_version();
}

/* This function does the heavy lifiting of co-ordinating inserts. It is a recursive function which walks
 * down the tree.
 *
 * NOTE: It expects the node it operates to be locked (either read or write) and also the node should not be
 * full.
 *
 * Input:
 * myNode      = Node it operates on
 * curLock     = Type of lock held for this node
 * req         = Req with information of current key/value to insert
 */
template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::do_put(const BtreeNodePtr< K >& my_node, locktype_t curlock, ReqT& req) {
    btree_status_t ret = btree_status_t::success;

    if (my_node->is_leaf()) {
        /* update the leaf node */
        BT_NODE_LOG_ASSERT_EQ(curlock, locktype_t::WRITE, my_node);
        ret = mutate_write_leaf_node(my_node, req);
        unlock_node(my_node, curlock);
        return ret;
    }

retry:
    uint32_t start_idx{0};
    uint32_t end_idx{0};
    uint32_t curr_idx;

    if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
        const auto count = my_node->template get_all< V >(req.next_range(), UINT32_MAX, start_idx, end_idx);
        if (count == 0) {
            BT_NODE_LOG_ASSERT(false, my_node, "get_all returns 0 entries for interior node is not valid pattern");
            ret = btree_status_t::retry;
            goto out;
        }
    } else if constexpr (std::is_same_v< ReqT, BtreeSinglePutRequest >) {
        auto const [found, idx] = my_node->find(req.key(), nullptr, true);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(found, idx, my_node);
        end_idx = start_idx = idx;
    }

    BT_NODE_DBG_ASSERT((curlock == locktype_t::READ || curlock == locktype_t::WRITE), my_node, "unexpected locktype {}",
                       curlock);

    curr_idx = start_idx;
    while (curr_idx <= end_idx) { // iterate all matched childrens
#if 0
#ifdef _PRERELEASE
        if (curr_idx - start_idx > 1 && homestore_flip->test_flip("btree_leaf_node_split")) {
            ret = btree_status_t::retry;
            goto out;
        }
#endif
#endif
        locktype_t child_cur_lock = locktype_t::NONE;

        // Get the childPtr for given key.
        BtreeLinkInfo child_info;
        BtreeNodePtr< K > child_node;
        ret = get_child_and_lock_node(my_node, curr_idx, child_info, child_node, locktype_t::READ, locktype_t::WRITE,
                                      req.m_op_context);
        if (ret != btree_status_t::success) {
            if (ret == btree_status_t::not_found) {
                // Either the node was updated or mynode is freed. Just proceed again from top.
                /* XXX: Is this case really possible as we always take the parent lock and never
                 * release it.
                 */
                ret = btree_status_t::retry;
            }
            goto out;
        }

        // Directly get write lock for leaf, since its an insert.
        child_cur_lock = (child_node->is_leaf()) ? locktype_t::WRITE : locktype_t::READ;

        // If the child and child_info link in the parent mismatch, we need to do btree repair, it might have
        // encountered a crash in-between the split or merge and only partial commit happened.
        if (is_split_needed(child_node, m_bt_cfg, req) || is_repair_needed(child_node, child_info)) {
            ret = upgrade_node_locks(my_node, child_node, curlock, child_cur_lock, req.m_op_context);
            if (ret != btree_status_t::success) {
                BT_NODE_LOG(DEBUG, my_node, "Upgrade of node lock failed, retrying from root");
                curlock = locktype_t::NONE; // upgrade_node_lock releases all locks on failure
                child_cur_lock = locktype_t::NONE;
                goto out;
            }
            curlock = child_cur_lock = locktype_t::WRITE;

            if (is_repair_needed(child_node, child_info)) {
                ret = repair_split(my_node, child_node, curr_idx, req.m_op_context);
            } else {
                K split_key;
                ret = split_node(my_node, child_node, curr_idx, &split_key, req.m_op_context);
            }
            unlock_node(child_node, locktype_t::WRITE);
            child_cur_lock = locktype_t::NONE;

            if (ret != btree_status_t::success) {
                goto out;
            } else {
                COUNTER_INCREMENT(m_metrics, btree_split_count, 1);
                goto retry; // After split, retry search and walk down.
            }
        }

        // Get subrange if it is a range update
        if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
            if (child_node->is_leaf()) {
                // We get the trimmed range only for leaf because this is where we will be inserting keys. In
                // interior nodes, keys are always propogated from the lower nodes.
                bool is_inp_key_lesser;
                req.trim_working_range(
                    my_node->min_of(s_cast< const K& >(req.input_range().end_key()), curr_idx, is_inp_key_lesser),
                    is_inp_key_lesser ? req.input_range().is_end_inclusive() : true);

                BT_NODE_LOG(DEBUG, my_node, "Subrange:idx=[{}-{}],c={},working={}", start_idx, end_idx, curr_idx,
                            req.working_range().to_string());
            }
        }

#ifndef NDEBUG
        K ckey, pkey;
        if (curr_idx != my_node->total_entries()) { // not edge
            pkey = my_node->get_nth_key(curr_idx, true);
            if (child_node->total_entries() != 0) {
                ckey = child_node->get_last_key();
                if (!child_node->is_leaf()) {
                    BT_NODE_DBG_ASSERT_EQ(ckey.compare(pkey), 0, my_node);
                } else {
                    BT_NODE_DBG_ASSERT_LE(ckey.compare(pkey), 0, my_node);
                }
            }
            // BT_NODE_DBG_ASSERT_EQ((is_range_put_req(req) || k.compare(pkey) <= 0), true, child_node);
        }
        if (curr_idx > 0) { // not first child
            pkey = my_node->get_nth_key(curr_idx - 1, true);
            if (child_node->total_entries() != 0) {
                ckey = child_node->get_first_key();
                BT_NODE_DBG_ASSERT_GE(ckey.compare(pkey), 0, child_node);
            }
            // BT_NODE_DBG_ASSERT_EQ((is_range_put_req(req) || k.compare(pkey) >= 0), true, my_node);
        }
#endif
        if (curr_idx == end_idx) {
            // If we have reached the last index, unlock before traversing down, because we no longer need
            // this lock. Holding this lock will impact performance unncessarily.
            unlock_node(my_node, curlock);
            curlock = locktype_t::NONE;
        }

        ret = do_put(child_node, child_cur_lock, req);
        if (ret != btree_status_t::success) { goto out; }

        ++curr_idx;
    }
out:
    if (curlock != locktype_t::NONE) { unlock_node(my_node, curlock); }
    return ret;
    // Warning: Do not access childNode or myNode beyond this point, since it would
    // have been unlocked by the recursive function and it could also been deleted.
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::mutate_write_leaf_node(const BtreeNodePtr< K >& my_node, ReqT& req) {
    btree_status_t ret = btree_status_t::success;
    if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
        const BtreeKeyRange< K >& subrange = req.working_range();

        if (subrange.start_key().is_extent_key()) {
            ret = mutate_extents_in_leaf(my_node, req);
        } else {
            auto const [start_found, start_idx] = my_node->find(subrange.start_key(), nullptr, false);
            auto const [end_found, end_idx] = my_node->find(subrange.end_key(), nullptr, false);
            if (req.m_put_type != btree_put_type::REPLACE_ONLY_IF_EXISTS) {
                BT_DBG_ASSERT(false, "For non-extent keys range-update should be really update and cannot insert");
                ret = btree_status_t::not_supported;
            } else {
                for (auto idx{start_idx}; idx <= end_idx; ++idx) {
                    my_node->update(idx, *req.m_newval);
                }
            }
            // update cursor in intermediate search state
            req.set_cursor_key(subrange.end_key());
        }
    } else if constexpr (std::is_same_v< ReqT, BtreeSinglePutRequest >) {
        if (!my_node->put(req.key(), req.value(), req.m_put_type, req.m_existing_val.get())) {
            ret = btree_status_t::put_failed;
        }
        COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
    }

    if ((ret == btree_status_t::success) || (ret == btree_status_t::has_more)) {
        write_node(my_node, req.m_op_context);
    }
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::mutate_extents_in_leaf(const BtreeNodePtr< K >& node, BtreeRangePutRequest< K >& rpreq) {
    if constexpr (std::is_base_of_v< ExtentBtreeKey< K >, K > && std::is_base_of_v< ExtentBtreeValue< V >, V >) {
        const BtreeKeyRange< K >& subrange = rpreq.current_sub_range();
        const auto& start_key = static_cast< const ExtentBtreeKey< K >& >(subrange.start_key());
        const auto& end_key = static_cast< ExtentBtreeKey< K >& >(subrange.end_key());
        ExtentBtreeValue< V >* new_value = static_cast< ExtentBtreeValue< V >* >(rpreq.m_newval.get());
        btree_status_t ret{btree_status_t::success};

        BT_DBG_ASSERT_EQ(start_key.extent_length(), 1, "Search range start key can't be multiple extents");
        BT_DBG_ASSERT_EQ(end_key.extent_length(), 1, "Search range end key can't be multiple extents");

        if (!can_extents_auto_merge()) {
            BT_REL_ASSERT(false, "Yet to support non-auto merge range of extents in range put");
            return btree_status_t::not_supported;
        }

        bool retry{false};
        auto const [start_found, start_idx] = node->find(start_key, nullptr, false);
        do {
            auto const [end_found, end_idx] = node->find(end_key, nullptr, false);
            ExtentBtreeKey const new_k = start_key.combine(end_key);
            auto idx = start_idx;

            { // Scope this to avoid head_k and tail_k are used beyond
                K h_k, t_k;
                V h_v, t_v;
                int64_t head_offset{0};
                int64_t tail_offset{0};
                ExtentBtreeKey< K >& head_k = static_cast< ExtentBtreeKey< K >& >(h_k);
                ExtentBtreeKey< K >& tail_k = static_cast< ExtentBtreeKey< K >& >(t_k);
                ExtentBtreeValue< V >& head_v = static_cast< ExtentBtreeValue< V >& >(h_v);
                ExtentBtreeValue< V >& tail_v = static_cast< ExtentBtreeValue< V >& >(t_v);

                // Get the residue head and tail key first if it is present, before updating any fields, otherwise
                // updating fields will modify the other entry.
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

                // Shortcut to simple update of the existing range, which is a normal case. Its a simple update only
                // if the value we are replacing is all equal sized for every extent piece (which is normal use
                // cases of the extents)
                if (start_found && end_found && (head_offset == 0) && (tail_offset == 0) && (start_idx == end_idx) &&
                    new_value->is_equal_sized()) {
                    call_on_update_kv_cb(node, start_idx, new_k, rpreq);
                    node->update(start_idx, new_k, new_value->shift(new_k.extent_length(), false));
                    break;
                }

                // Do size check, first check if we can accomodate the keys if checked conservatively. Thats most
                // common case and thus efficient. Next we go aggressively, the more aggressive the check, more
                // performance impact.
                //
                // First level check: Try assuming the entire value + 2 keys + 2 records to be inserted. If there is
                // a space available, no need any additional check.
                auto const record_size = (2 * (new_k.serialized_size() + node->get_record_size()));
                auto size_needed = new_value->extracted_size(0, new_k.extent_length()) + record_size;

                auto const available_space = node->available_size(m_bt_cfg);
                if (size_needed > available_space) {
                    BT_NODE_DBG_ASSERT_EQ(retry, false, node, "Don't expect multiple attempts of size not available");

                    // Second level check: Take into account the head and tail overlapped space and see if it saves
                    // some
                    if (head_offset > 0) {
                        size_needed -= (head_v.serialized_size() - head_v.extracted_size(0, head_offset));
                    }
                    if (tail_offset > 0) { size_needed -= tail_v.extracted_size(0, tail_offset); }

                    if (size_needed > available_space) {
                        // Third level check: Walk through every entry in the about to remove list and account for
                        // theirs
                        V tmp_v;
                        for (auto i = start_idx; i < end_idx; ++i) {
                            node->get_nth_value(i, &tmp_v, false);
                            size_needed -= (node->get_nth_key(i, false).serialized_size() + tmp_v.serialized_size());
                        }

                        // If still size is not enough, no other option other than trimming down the keys and retry
                        if (size_needed > available_space) {
                            auto const nextents = new_value->num_extents_fit(available_space - record_size);
                            end_key = new_k.extract(0, nextents, true);
                            retry = true;
                            ret = btree_status_t::has_more;
                            continue;
                        }
                    }
                }
                retry = false;

                // Write partial head and tail kv. At this point we are committing and we can't go back and not
                // update some of the extents.
                if (end_idx == start_idx) {
                    // Special case - where there is a overlap and single entry is split into 3
                    auto const tail_start = tail_k.extent_length() - tail_offset;
                    if (m_on_remove_cb) {
                        m_on_remove_cb(head_k.extract(head_offset, tail_start - head_offset, false),
                                       head_v.extract(head_offset, tail_start - head_offset, false), rpreq);
                    }

                    if (tail_offset > 0) {
                        node->insert(end_idx + 1, tail_k.extract(tail_start, tail_offset, false),
                                     tail_v.extract(tail_start, tail_offset, false));
                        COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
                    }

                    if (head_offset > 0) {
                        node->update(idx++, head_k.extract(0, head_offset, false),
                                     head_v.extract(0, head_offset, false));
                    }
                } else {
                    if (tail_offset > 0) {
                        auto const tail_start = tail_k.extent_length() - tail_offset;
                        auto const shrunk_k = tail_k.extract(tail_start, tail_offset, false);
                        call_on_update_kv_cb(node, end_idx, shrunk_k, rpreq);
                        node->update(end_idx, shrunk_k, tail_v.extract(tail_start, tail_offset, false));
                    } else if (end_found) {
                        ++end_idx;
                    }

                    if (head_offset > 0) {
                        auto const shrunk_k = head_k.extract(0, -head_offset, false);
                        call_on_update_kv_cb(node, idx, shrunk_k, rpreq);
                        node->update(idx++, shrunk_k, head_v.extract(0, -head_offset, false));
                    }
                }
            }

            // Remove everything in-between
            if (idx < end_idx) {
                if (m_on_remove_cb) {
                    for (auto i{idx}; i <= end_idx; ++i) {
                        call_on_remove_kv_cb(node, i, rpreq);
                    }
                }
                node->remove(idx, end_idx - 1);
                COUNTER_DECREMENT(m_metrics, btree_obj_count, end_idx - idx);
            }

            // Now we should have enough room to insert the combined entry
            node->insert(idx, new_k, new_value->shift(new_k.extent_length()));
            COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
        } while (retry);

        rpreq.set_cursor_key(end_key);
        return ret;
    } else {
        BT_REL_ASSERT(false, "Don't expect mutate_extents to be called on non-extent code path");
        return btree_status_t::not_supported;
    }
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::check_split_root(ReqT& req) {
    K split_key;
    BtreeNodePtr< K > child_node = nullptr;
    btree_status_t ret = btree_status_t::success;
    BtreeNodePtr< K > root;
    BtreeNodePtr< K > new_root;

    m_btree_lock.lock();
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::WRITE, locktype_t::WRITE, req.m_op_context);
    if (ret != btree_status_t::success) { goto done; }

    if (!is_split_needed(root, m_bt_cfg, req) && !is_repair_needed(root, m_root_node_info)) {
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

    new_root = alloc_interior_node();
    if (new_root == nullptr) {
        ret = btree_status_t::space_not_avail;
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

    BT_NODE_LOG(DEBUG, root, "Root node is full, creating new root node", new_root->node_id());
    child_node = std::move(root);
    root = std::move(new_root);
    BT_NODE_DBG_ASSERT_EQ(root->total_entries(), 0, root);

    if (is_repair_needed(child_node, m_root_node_info)) {
        ret = repair_split(root, child_node, root->total_entries(), req.m_op_context);
    } else {
        ret = split_node(root, child_node, root->total_entries(), &split_key, req.m_op_context);
    }

    if (ret != btree_status_t::success) {
        free_node(root, locktype_t::WRITE, req.m_op_context);
        root = std::move(child_node);
        unlock_node(root, locktype_t::WRITE);
    } else {
        m_root_node_info = BtreeLinkInfo{root->node_id(), root->link_version()};
        unlock_node(child_node, locktype_t::WRITE);
        COUNTER_INCREMENT(m_metrics, btree_depth, 1);
    }

done:
    m_btree_lock.unlock();
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::split_node(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node,
                                         uint32_t parent_ind, BtreeKey* out_split_key, void* context) {
    BtreeNodePtr< K > child_node1 = child_node;
    BtreeNodePtr< K > child_node2 = child_node1->is_leaf() ? alloc_leaf_node() : alloc_interior_node();

    if (child_node2 == nullptr) { return (btree_status_t::space_not_avail); }

    btree_status_t ret = btree_status_t::success;

    child_node2->set_next_bnode(child_node1->next_bnode());
    child_node1->set_next_bnode(child_node2->node_id());
    uint32_t child1_filled_size = m_bt_cfg.node_data_size() - child_node1->available_size(m_bt_cfg);

    auto split_size = m_bt_cfg.split_size(child1_filled_size);
    uint32_t res = child_node1->move_out_to_right_by_size(m_bt_cfg, *child_node2, split_size);

    BT_NODE_REL_ASSERT_GT(res, 0, child_node1,
                          "Unable to split entries in the child node"); // means cannot split entries
    BT_NODE_DBG_ASSERT_GT(child_node1->total_entries(), 0, child_node1);

    // In an unlikely case where parent node has no room to accomodate the child key, we need to un-split and then
    // free up the new node. This situation could happen on variable key, where the key max size is purely
    // an estimation. This logic allows the max size to be declared more optimistically than say 1/4 of node
    // which will have substantially large number of splits and performance constraints.
    if (out_split_key->serialized_size() > parent_node->available_size(m_bt_cfg)) {
        uint32_t move_in_res = child_node1->copy_by_entries(m_bt_cfg, *child_node2, 0, child_node2->total_entries());
        BT_NODE_REL_ASSERT_EQ(move_in_res, res, child_node1,
                              "The split key size is more than estimated parent available space, but when revert is "
                              "attempted it fails. Continuing can cause data loss, so crashing");
        free_node(child_node2, locktype_t::WRITE, context);

        // Mark the parent_node itself to be split upon next retry.
        bt_thread_vars()->force_split_node = parent_node;
        return btree_status_t::retry;
    }

    child_node1->inc_link_version();

    // Update the existing parent node entry to point to second child ptr.
    parent_node->update(parent_ind, child_node2->link_info());

    // Insert the last entry in first child to parent node
    *out_split_key = child_node1->get_last_key();

    // If key is extent then we always insert the tail portion of the extent key in the parent node
    if (out_split_key->is_extent_key()) {
        parent_node->insert(parent_ind, ((ExtentBtreeKey< K >*)out_split_key)->extract_end(false),
                            child_node1->link_info());
    } else {
        parent_node->insert(parent_ind, *out_split_key, child_node1->link_info());
    }

    BT_NODE_DBG_ASSERT_GT(child_node2->get_first_key().compare(*out_split_key), 0, child_node2);
    BT_NODE_LOG(DEBUG, parent_node, "Split child_node={} with new_child_node={}, split_key={}", child_node1->node_id(),
                child_node2->node_id(), out_split_key->to_string());

    ret = transact_write_nodes({child_node2}, child_node1, parent_node, context);

    // NOTE: Do not access parentInd after insert, since insert would have
    // shifted parentNode to the right.
    return ret;
}

template < typename K, typename V >
template < typename ReqT >
bool Btree< K, V >::is_split_needed(const BtreeNodePtr< K >& node, const BtreeConfig& cfg, ReqT& req) const {
    if (bt_thread_vars()->force_split_node && (bt_thread_vars()->force_split_node == node)) {
        bt_thread_vars()->force_split_node = nullptr;
        return true;
    }

    int64_t size_needed = 0;
    if (!node->is_leaf()) { // if internal node, size is atmost one additional entry, size of K/V
        size_needed = K::get_estimate_max_size() + BtreeLinkInfo::get_fixed_size() + node->get_record_size();
    } else if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
        const BtreeKey& next_key = req.next_key();

        if (next_key.is_extent_key()) {
            // For extent keys we expect to write atleast first value in the req along with 2 possible keys
            // in case of splitting existing key
            auto val = static_cast< const ExtentBtreeValue< V >* >(req.m_newval.get());
            size_needed = val->extracted_size(0, 1) + 2 * (next_key.serialized_size() + node->get_record_size());
        } else {
            size_needed = req.m_newval->serialized_size();
            if (req.m_put_type != btree_put_type::REPLACE_ONLY_IF_EXISTS) {
                size_needed += next_key.serialized_size() + node->get_record_size();
            }
        }
    } else if constexpr (std::is_same_v< ReqT, BtreeSinglePutRequest >) {
        size_needed = req.key().serialized_size() + req.value().serialized_size() + node->get_record_size();
    }
    int64_t alreadyFilledSize = cfg.node_data_size() - node->available_size(cfg);
    return (alreadyFilledSize + size_needed >= cfg.ideal_fill_size());
}

template < typename K, typename V >
btree_status_t Btree< K, V >::repair_split(const BtreeNodePtr< K >& parent_node, const BtreeNodePtr< K >& child_node1,
                                           uint32_t parent_split_idx, void* context) {
    parent_node->update(parent_split_idx, BtreeLinkInfo{child_node1->next_bnode(), child_node1->link_version()});
    parent_node->insert(parent_split_idx, child_node1->get_last_key(), child_node1->link_info());
    return write_node(parent_node, context);
}

#if 0
template < typename K, typename V >
int64_t Btree< K, V >::compute_single_put_needed_size(const V& current_val, const V& new_val) const {
    return new_val.serialized_size() - current_val.serialized_size();
}

template < typename K, typename V >
int64_t Btree< K, V >::compute_range_put_needed_size(const std::vector< std::pair< K, V > >& existing_kvs,
                                                     const V& new_val) const {
    return new_val.serialized_size() * existing_kvs.size();
}

template < typename K, typename V >
btree_status_t
Btree< K, V >::custom_kv_select_for_write(uint8_t node_version, const std::vector< std::pair< K, V > >& match_kv,
                                          std::vector< std::pair< K, V > >& replace_kv, const BtreeKeyRange& range,
                                          const BtreeRangePutRequest& rpreq) const {
    for (const auto& [k, v] : match_kv) {
        replace_kv.push_back(std::make_pair(k, (V&)rpreq.m_newval));
    }
    return btree_status_t::success;
}
#endif

#if 0
template < typename K, typename V >
btree_status_t Btree< K, V >::get_start_and_end_idx(const BtreeNodePtr< K >& node, BtreeMutateRequest& req,
                                                    int& start_idx, int& end_idx) {
    btree_status_t ret = btree_status_t::success;
    if (is_range_put_req(req)) {
        /* just get start/end index from get_all. We don't release the parent lock until this
         * key range is not inserted from start_idx to end_idx.
         */
        node->template get_all< V >(to_range_put_req(req).next_range(), UINT32_MAX, (uint32_t&)start_idx,
                                    (uint32_t&)end_idx);
    } else {
        auto [found, idx] = node->find(to_single_put_req(req).key(), nullptr, true);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(found, idx, node);
        end_idx = start_idx = (int)idx;
    }

    if (start_idx > end_idx) {
        BT_NODE_LOG_ASSERT(false, node, "start ind {} greater than end ind {}", start_idx, end_idx);
        ret = btree_status_t::retry;
    }
    return ret;
}
#endif

} // namespace homestore