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
btree_status_t Btree< K, V >::do_put(const BtreeNodePtr& my_node, locktype_t curlock, ReqT& req) {
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
        const auto matched = my_node->match_range(req.working_range(), start_idx, end_idx);
        if (!matched) {
            BT_NODE_LOG_ASSERT(false, my_node, "match_range returns 0 entries for interior node is not valid pattern");
            ret = btree_status_t::put_failed;
            goto out;
        }
    } else if constexpr (std::is_same_v< ReqT, BtreeSinglePutRequest >) {
        auto const [found, idx] = my_node->find(req.key(), nullptr, true);
        ASSERT_IS_VALID_INTERIOR_CHILD_INDX(found, idx, my_node);
        end_idx = start_idx = idx;
    }

    BT_NODE_DBG_ASSERT((curlock == locktype_t::READ || curlock == locktype_t::WRITE), my_node, "unexpected locktype {}",
                       curlock);

    if (req.route_tracing) { append_route_trace(req, my_node, btree_event_t::READ, start_idx, end_idx); }

    curr_idx = start_idx;
    while (curr_idx <= end_idx) { // iterate all matched childrens
#if 0
#ifdef _PRERELEASE
        if (curr_idx - start_idx > 1 && iomgr_flip::instance()->test_flip("btree_leaf_node_split")) {
            ret = btree_status_t::retry;
            goto out;
        }
#endif
#endif
        locktype_t child_cur_lock = locktype_t::NONE;

        // Get the childPtr for given key.
        BtreeLinkInfo child_info;
        BtreeNodePtr child_node;
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
        if (is_split_needed(child_node, req) || is_repair_needed(child_node, child_info)) {
            ret = upgrade_node_locks(my_node, child_node, curlock, child_cur_lock, req.m_op_context);
            if (ret != btree_status_t::success) {
                BT_NODE_LOG(DEBUG, my_node, "Upgrade of node lock failed, retrying from root");
                curlock = locktype_t::NONE; // upgrade_node_lock releases all locks on failure
                child_cur_lock = locktype_t::NONE;
                goto out;
            }
            curlock = child_cur_lock = locktype_t::WRITE;

            if (is_repair_needed(child_node, child_info)) {
                BT_NODE_LOG(TRACE, child_node, "Node repair needed");
                ret = repair_split(my_node, child_node, curr_idx, req.m_op_context);
            } else {
                K split_key;
                BT_NODE_LOG(TRACE, my_node, "Split node needed");
                ret = split_node(my_node, child_node, curr_idx, &split_key, req.m_op_context);
            }
            unlock_node(child_node, locktype_t::WRITE);
            child_cur_lock = locktype_t::NONE;

            if (ret != btree_status_t::success) {
                goto out;
            } else {
                if (req.route_tracing) { append_route_trace(req, child_node, btree_event_t::SPLIT); }
                COUNTER_INCREMENT(m_metrics, btree_split_count, 1);
                goto retry; // After split, retry search and walk down.
            }
        }

        // Get subrange if it is a range update
        if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
            if (child_node->is_leaf()) {
                // We get the trimmed range only for leaf because this is where we will be inserting keys. In
                // interior nodes, keys are always propogated from the lower nodes.
                if (curr_idx < my_node->total_entries()) {
                    K child_end_key = my_node->get_nth_key< K >(curr_idx, true);
                    if (child_end_key.compare(req.working_range().end_key()) < 0) {
                        req.trim_working_range(std::move(child_end_key), true /* inclusive child key */);
                    }
                }

                BT_NODE_LOG(DEBUG, my_node, "Subrange:idx=[{}-{}],c={},working={}", start_idx, end_idx, curr_idx,
                            req.working_range().to_string());
            }
        }

#ifndef NDEBUG
        K ckey, pkey;
        if (curr_idx != my_node->total_entries()) { // not edge
            pkey = my_node->get_nth_key< K >(curr_idx, true);
            if (child_node->total_entries() != 0) {
                ckey = child_node->get_last_key< K >();
                if (!child_node->is_leaf()) {
                    BT_NODE_DBG_ASSERT_EQ(ckey.compare(pkey), 0, my_node);
                } else {
                    BT_NODE_DBG_ASSERT_LE(ckey.compare(pkey), 0, my_node);
                }
            }
            // BT_NODE_DBG_ASSERT_EQ((is_range_put_req(req) || k.compare(pkey) <= 0), true, child_node);
        }
        if (curr_idx > 0) { // not first child
            pkey = my_node->get_nth_key< K >(curr_idx - 1, true);
            if (child_node->total_entries() != 0) {
                ckey = child_node->get_first_key< K >();
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
btree_status_t Btree< K, V >::mutate_write_leaf_node(const BtreeNodePtr& my_node, ReqT& req) {
    btree_status_t ret = btree_status_t::success;
    if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
        K last_failed_key;
        ret = to_variant_node(my_node)->multi_put(req.working_range(), req.input_range().start_key(), *req.m_newval,
                                                  req.m_put_type, &last_failed_key, req.m_filter_cb);
        if (ret == btree_status_t::has_more) {
            req.shift_working_range(std::move(last_failed_key), true /* make it including last_failed_key */);
        } else if (ret == btree_status_t::success) {
            req.shift_working_range();
        }
    } else if constexpr (std::is_same_v< ReqT, BtreeSinglePutRequest >) {
        if (!to_variant_node(my_node)->put(req.key(), req.value(), req.m_put_type, req.m_existing_val,
                                           req.m_filter_cb)) {
            ret = btree_status_t::put_failed;
        }
        COUNTER_INCREMENT(m_metrics, btree_obj_count, 1);
    }

    if ((ret == btree_status_t::success) || (ret == btree_status_t::has_more)) {
        if (req.route_tracing) { append_route_trace(req, my_node, btree_event_t::MUTATE); }
        write_node(my_node, req.m_op_context);
    }
    return ret;
}

template < typename K, typename V >
template < typename ReqT >
btree_status_t Btree< K, V >::check_split_root(ReqT& req) {
    K split_key;
    BtreeNodePtr child_node = nullptr;
    btree_status_t ret = btree_status_t::success;
    BtreeNodePtr root;
    BtreeNodePtr new_root;

    m_btree_lock.lock();
    ret = read_and_lock_node(m_root_node_info.bnode_id(), root, locktype_t::WRITE, locktype_t::WRITE, req.m_op_context);
    if (ret != btree_status_t::success) { goto done; }

    if (!is_split_needed(root, req) && !is_repair_needed(root, m_root_node_info)) {
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

    new_root = alloc_interior_node();
    if (new_root == nullptr) {
        ret = btree_status_t::space_not_avail;
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }
    new_root->set_level(root->level() + 1);

    BT_NODE_LOG(DEBUG, root, "Root node is full, creating new root node={}", new_root->node_id());
    child_node = std::move(root);
    root = std::move(new_root);
    BT_NODE_DBG_ASSERT_EQ(root->total_entries(), 0, root);

    ret = prepare_node_txn(root, child_node, req.m_op_context);
    if (ret != btree_status_t::success) {
        free_node(root, locktype_t::WRITE, req.m_op_context);
        root = std::move(child_node);
        unlock_node(root, locktype_t::WRITE);
        goto done;
    }

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
        if (req.route_tracing) { append_route_trace(req, child_node, btree_event_t::SPLIT); }

        m_root_node_info = BtreeLinkInfo{root->node_id(), root->link_version()};
        unlock_node(child_node, locktype_t::WRITE);
        COUNTER_INCREMENT(m_metrics, btree_depth, 1);
        update_new_root_info(root->node_id(), root->link_version());
    }

done:
    m_btree_lock.unlock();
    return ret;
}

template < typename K, typename V >
btree_status_t Btree< K, V >::split_node(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node,
                                         uint32_t parent_ind, K* out_split_key, void* context) {
    BtreeNodePtr child_node1 = child_node;
    BtreeNodePtr child_node2;
    child_node2.reset(child_node1->is_leaf() ? alloc_leaf_node().get() : alloc_interior_node().get());

    if (child_node2 == nullptr) { return (btree_status_t::space_not_avail); }

    btree_status_t ret = btree_status_t::success;

    child_node2->set_next_bnode(child_node1->next_bnode());
    child_node1->set_next_bnode(child_node2->node_id());
    child_node2->set_level(child_node1->level());
    uint32_t child1_filled_size = m_bt_cfg.node_data_size() - child_node1->available_size();

    auto split_size = m_bt_cfg.split_size(child1_filled_size);
    uint32_t res = child_node1->move_out_to_right_by_size(m_bt_cfg, *child_node2, split_size);

    BT_NODE_REL_ASSERT_GT(res, 0, child_node1,
                          "Unable to split entries in the child node"); // means cannot split entries
    BT_NODE_DBG_ASSERT_GT(child_node1->total_entries(), 0, child_node1);

    // Insert the last entry in first child to parent node
    *out_split_key = child_node1->get_last_key< K >();

    BT_NODE_LOG(TRACE, parent_node, "Available space for split entry={}", parent_node->available_size());

    child_node1->inc_link_version();

    // Update the existing parent node entry to point to second child ptr.
    parent_node->update(parent_ind, child_node2->link_info());
    parent_node->insert(parent_ind, *out_split_key, child_node1->link_info());

    BT_NODE_DBG_ASSERT_GT(child_node2->get_first_key< K >().compare(*out_split_key), 0, child_node2);
    BT_NODE_LOG(DEBUG, parent_node, "Split child_node={} with new_child_node={}, split_key={}", child_node1->node_id(),
                child_node2->node_id(), out_split_key->to_string());
    BT_NODE_LOG(DEBUG, child_node1, "Left child");
    BT_NODE_LOG(DEBUG, child_node2, "Right child");

    ret = transact_write_nodes({child_node2}, child_node1, parent_node, context);

    // NOTE: Do not access parentInd after insert, since insert would have
    // shifted parentNode to the right.
    return ret;
}

template < typename K, typename V >
template < typename ReqT >
bool Btree< K, V >::is_split_needed(const BtreeNodePtr& node, ReqT& req) const {
    if (!node->is_leaf()) { // if internal node, size is atmost one additional entry, size of K/V
        return !node->has_room_for_put(btree_put_type::UPSERT, K::get_max_size(), BtreeLinkInfo::get_fixed_size());
    } else if constexpr (std::is_same_v< ReqT, BtreeRangePutRequest< K > >) {
        return !node->has_room_for_put(req.m_put_type, req.first_key_size(), req.m_newval->serialized_size());
    } else if constexpr (std::is_same_v< ReqT, BtreeSinglePutRequest >) {
        return !node->has_room_for_put(req.m_put_type, req.key().serialized_size(), req.value().serialized_size());
    } else {
        return false;
    }
}

template < typename K, typename V >
btree_status_t Btree< K, V >::repair_split(const BtreeNodePtr& parent_node, const BtreeNodePtr& child_node1,
                                           uint32_t parent_split_idx, void* context) {
    parent_node->update(parent_split_idx, BtreeLinkInfo{child_node1->next_bnode(), child_node1->link_version()});
    parent_node->insert(parent_split_idx, child_node1->get_last_key< K >(), child_node1->link_info());
    return write_node(parent_node, context);
}
} // namespace homestore
