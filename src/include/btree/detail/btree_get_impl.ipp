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
btree_status_t Btree< K, V >::do_get(const BtreeNodePtr< K >& my_node, ReqT& greq) const {
    btree_status_t ret{btree_status_t::success};
    bool found{false};
    uint32_t idx;

    if (my_node->is_leaf()) {
        if constexpr (std::is_same_v< BtreeGetAnyRequest< K >, ReqT >) {
            std::tie(found, idx) = my_node->get_any(greq.m_range, greq.m_outkey.get(), greq.m_outval.get(), true, true);
            if (found) { call_on_read_kv_cb(my_node, idx, greq); }
        } else if constexpr (std::is_same_v< BtreeSingleGetRequest, ReqT >) {
            std::tie(found, idx) = my_node->find(greq.key(), greq.m_outval.get(), true);
            if (found) { call_on_read_kv_cb(my_node, idx, greq); }
        }
        if (!found) { ret = btree_status_t::not_found; }
        unlock_node(my_node, locktype_t::READ);
        return ret;
    }

    BtreeLinkInfo child_info;
    if constexpr (std::is_same_v< BtreeGetAnyRequest< K >, ReqT >) {
        std::tie(found, idx) = my_node->find(greq.m_range.start_key(), &child_info, true);
    } else if constexpr (std::is_same_v< BtreeSingleGetRequest, ReqT >) {
        std::tie(found, idx) = my_node->find(greq.key(), &child_info, true);
    }

    ASSERT_IS_VALID_INTERIOR_CHILD_INDX(found, idx, my_node);
    BtreeNodePtr< K > child_node;
    ret = read_and_lock_node(child_info.bnode_id(), child_node, locktype_t::READ, locktype_t::READ, greq.m_op_context);
    if (ret != btree_status_t::success) { goto out; }

    unlock_node(my_node, locktype_t::READ);
    return (do_get(child_node, greq));

out:
    unlock_node(my_node, locktype_t::READ);
    return ret;
}
} // namespace homestore
