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
std::pair<uint64_t,uint64_t> Btree< K, V >::compute_node_count()  {
    uint64_t leaf_cnt = 0;
    uint64_t interior_cnt = 0;
    m_btree_lock.lock_shared();
    get_child_node_count(m_root_node_info.bnode_id(), interior_cnt, leaf_cnt);
    m_total_leaf_nodes = leaf_cnt;
    m_total_interior_nodes= interior_cnt;
    m_btree_lock.unlock_shared();
    return {interior_cnt, leaf_cnt};
}

template < typename K, typename V >
uint16_t Btree< K, V >::compute_btree_depth()  {
    m_btree_lock.lock_shared();
    BtreeNodePtr root;
    locktype_t acq_lock = locktype_t::READ;
    if (read_and_lock_node(m_root_node_info.bnode_id(), root, acq_lock, acq_lock, nullptr) != btree_status_t::success){ return -1; }
    m_btree_depth = root->level();
    unlock_node(root, acq_lock);
    m_btree_lock.unlock_shared();
    return m_btree_depth;
}

template < typename K, typename V >
void Btree< K, V >::get_child_node_count(bnodeid_t bnodeid, uint64_t& interior_cnt, uint64_t& leaf_cnt) const {
    BtreeNodePtr node;
    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return ; }
    if(node->is_leaf()) {
        ++leaf_cnt;
    } else {
        ++interior_cnt;
    }
    if (!node->is_leaf()) {
        if(node->level()==1){
                leaf_cnt += node->total_entries() + (node->has_valid_edge()?1:0);
        }else{
            uint32_t i = 0;
            while (i < node->total_entries()) {
                BtreeLinkInfo p;
                node->get_nth_value(i, &p, false);
                get_child_node_count(p.bnode_id(), interior_cnt, leaf_cnt);
                ++i;
            }
            if (node->has_valid_edge()) {get_child_node_count(node->edge_id(), interior_cnt, leaf_cnt); }
        }
    }
    unlock_node(node, acq_lock);
    return ;
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
void Btree< K, V >::to_custom_string_internal(bnodeid_t bnodeid, std::string& buf, to_string_cb_t< K, V > const& cb,
                                              int nindent) const {
    BtreeNodePtr node;

    locktype_t acq_lock = locktype_t::READ;

    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return; }
    if (nindent < 0) { nindent = node->level(); }
    std::string tabs(3 * (nindent - node->level()), ' ');
    fmt::format_to(std::back_inserter(buf), "{}{}\n", tabs, node->to_custom_string(cb));

    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            to_custom_string_internal(p.bnode_id(), buf, cb, nindent);
            ++i;
        }
        if (node->has_valid_edge()) { to_custom_string_internal(node->edge_id(), buf, cb, nindent); }
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
uint64_t Btree< K, V >::count_keys(bnodeid_t bnodeid) const {
    if (bnodeid == 0) { bnodeid = this->root_node_id(); }
    BtreeNodePtr node;
    locktype_t acq_lock = locktype_t::READ;
    if (read_and_lock_node(bnodeid, node, acq_lock, acq_lock, nullptr) != btree_status_t::success) { return 0; }
    uint64_t result = 0;
    if (!node->is_leaf()) {
        uint32_t i = 0;
        while (i < node->total_entries()) {
            BtreeLinkInfo p;
            node->get_nth_value(i, &p, false);
            result += count_keys(p.bnode_id());
            ++i;
        }
        if (node->has_valid_edge()) { result += count_keys(node->edge_id()); }
    } else {
        result = node->total_entries();
    }
    unlock_node(node, acq_lock);
    return result;
}

template <typename K, typename V>
void Btree<K, V>::validate_node_child_relation(BtreeNodePtr node, BtreeNodePtr& last_child_node) const {
    if (node->is_leaf()) { return; }
    uint32_t nentries = node->has_valid_edge() ? node->total_entries() + 1 : node->total_entries();
    BtreeNodePtr previous_child = nullptr;
    for (uint32_t ind = 0; ind < nentries; ++ind) {
        BtreeLinkInfo child_info;
        node->get_nth_value(ind, &child_info, false /* copy */);
        if (child_info.bnode_id() == empty_bnodeid) {
            throw std::runtime_error(fmt::format("{}-th child of node [{}] info has empty bnode_id", ind, node->to_string()));
        }
        BtreeNodePtr child_node;
        if (auto ret = read_node_impl(child_info.bnode_id(), child_node); ret != btree_status_t::success) {
            throw std::runtime_error(fmt::format("Failed to read child node [{}] of node [{}]", child_info.bnode_id(), node->to_string()));
        }
        if (ind == nentries - 1) { last_child_node = child_node; }
        if (child_node->is_node_deleted()) {
            throw std::runtime_error(fmt::format("Child node [{}] is deleted for parent [{}]", child_node->to_string(), node->to_string()));
        }
        if (child_node->level() != node->level() - 1) {
            throw std::runtime_error(fmt::format("Child node level mismatch node [{}] child level: {}, expected: {}",child_node->to_string(), child_node->level(), node->level() - 1));
        }

        K child_first_key = child_node->get_first_key< K >();
        K child_last_key = child_node->get_last_key< K >();
        K parent_nth_key;

         if(child_node->total_entries() >0) {
              if(ind< node->total_entries()){
                 parent_nth_key= node->get_nth_key<K>(ind, false /* copy */);
                if(child_first_key.compare(parent_nth_key) > 0) {
                    throw std::runtime_error(fmt::format("{}-th Child node [{}] first key is less than its corresponding parent node [{}] key",ind,child_node->to_string(),node->to_string()));
                    }
                if(child_last_key.compare(parent_nth_key) > 0) {
                    throw std::runtime_error(fmt::format("{}-th Child node [{}] last key is greater than its corresponding parent node [{}] key",ind, child_node->to_string(), node->to_string()));
                    }
               }

        } else if (!child_node->is_leaf() && !child_node->has_valid_edge()) {
            throw std::runtime_error(fmt::format("Interior Child node [{}] cannot be empty", child_node->to_string()));
        }

        if(ind > 0){
            if (previous_child->next_bnode()!= child_node->node_id())     {
                throw std::runtime_error(fmt::format("Broken child linkage: {}-th Child node [{}] node id is not equal to previous child node [{}] next node",ind, child_node->to_string(), child_node->node_id(), previous_child->to_string()));
            }
            K last_parent_key = node->get_nth_key< K >(ind-1, false /* copy */);
            K previous_child_last_key = previous_child->get_last_key< K >();
            if(child_node->total_entries()){
                 if (previous_child->total_entries() && child_first_key.compare(previous_child_last_key) <= 0) {
                    throw std::runtime_error(fmt::format("Child node [{}] first key is not greater than previous child node [{}] last key",child_node->to_string(), previous_child->to_string()));
                }
                if(child_first_key.compare(last_parent_key) <= 0) {
                    throw std::runtime_error(fmt::format("Child node [{}] first key is not greater than previous key ({}-th) parent node [{}] key ",child_node->to_string(),ind-1, node->to_string()));
                }
            }
        }

        previous_child = child_node;
    }
	if(node->has_valid_edge() && last_child_node->is_leaf() && last_child_node->next_bnode()!=empty_bnodeid) {
		// If the last child node is a leaf and has a next_bnode, it cannot be a valid edge.
		throw std::runtime_error(fmt::format("Last child node [{}] of node [{}] is the last child but has next_bnode",
                                 last_child_node->to_string(), node->to_string()));
	}
	if(node->has_valid_edge() && !last_child_node->is_leaf() && !last_child_node->has_valid_edge()) {
 		throw std::runtime_error(fmt::format("Last child node [{}] of edge node [{}] is not edge",
                                 last_child_node->to_string(), node->to_string()));
	}
	if(!node->has_valid_edge() && last_child_node->is_leaf() && last_child_node->next_bnode()==empty_bnodeid){
		throw std::runtime_error(fmt::format("node [{}] is not edge but last child node [{}] is leaf and has no next_bnode",
                                 node->to_string(),last_child_node->to_string()));
	}
	if(!node->has_valid_edge() && !last_child_node->is_leaf() && last_child_node->has_valid_edge()){
		throw std::runtime_error(fmt::format("node [{}] is not edge but last child node [{}] has valid edge",
                                 node->to_string(), last_child_node->to_string()));
	}
}

template < typename K, typename V >
void Btree< K, V >::validate_next_node_relation(BtreeNodePtr node, BtreeNodePtr neighbor_node,
                                                BtreeNodePtr last_child_node) const {
    K last_key = node->get_last_key< K >();

    if (neighbor_node->total_entries() == 0 && !neighbor_node->has_valid_edge() && last_child_node &&last_child_node->next_bnode() != empty_bnodeid) {
        throw std::runtime_error(fmt::format("neighbor [{}] has no entries nor valid edge but the last child, [{}] of the parent [{}] has next node id {}",neighbor_node->to_string(),  last_child_node->to_string(), node->to_string(), last_child_node->next_bnode()));
    }
    if ((neighbor_node->total_entries() != 0 || neighbor_node->has_valid_edge()) && last_child_node &&last_child_node->next_bnode() == empty_bnodeid) {
          throw std::runtime_error(fmt::format("neighbor [{}] has entries or valid edge but the last child, [{}] of the parent [{}] has no next node id",neighbor_node->to_string(),  last_child_node->to_string(), node->to_string()));
    }

    if (neighbor_node->is_node_deleted()) {
        throw std::runtime_error(fmt::format("Neighbor node [{}] is deleted " , neighbor_node->to_string()));
    }
    if (neighbor_node->level() != node->level()) {
        throw std::runtime_error(fmt::format("Neighbor node [{}] level {} mismatch vs node [{}] level {}",
                                 neighbor_node->to_string(), neighbor_node->level(), node->to_string(),
                                 node->level()));
    }
    K neighbor_first_key = neighbor_node->get_first_key< K >();
    auto neighbor_entities = neighbor_node->total_entries();
    if (neighbor_entities && neighbor_first_key.compare(last_key) < 0) {
        throw std::runtime_error(fmt::format("Neighbor's first key {} is not greater than node's last key {} (node=[{}], neighbor=[{}])",
                                             neighbor_first_key.to_string(), last_key.to_string(), node->to_string(), neighbor_node->to_string()));
    }
    if (!node->is_leaf()) {
        if (!neighbor_node->has_valid_edge() && !neighbor_entities) {
            throw std::runtime_error(fmt::format("Interior neighbor node [{}] is empty ", neighbor_node->to_string()));
        }
        BtreeLinkInfo first_neighbor_info;
        neighbor_node->get_nth_value(0, &first_neighbor_info, false /* copy */);
        if (last_child_node->next_bnode() != first_neighbor_info.bnode_id()) {
            throw std::runtime_error(fmt::format("Last child node's next_bnode (child=[{}]) does not match neighbor's first bnode_id (neighbor=[{}])", last_child_node->to_string(), neighbor_node->to_string()));

        }
    }
}

template <typename K, typename V>
void Btree<K, V>::validate_node(const bnodeid_t& bnodeid) const {
    BtreeNodePtr node;
    if (auto ret = read_node_impl(bnodeid, node); ret != btree_status_t::success) {
        throw std::runtime_error(fmt::format("node read failed for bnodeid: {} reason: {}", bnodeid, ret));
    } else {
        try {
            if (node->is_node_deleted()) { return; }
            auto nentities = node->total_entries();
            if (!node->is_leaf() && !nentities && !node->has_valid_edge()) {
				throw std::runtime_error(fmt::format("Node [{}] has no entries and no valid edge", node->to_string()));
			}
            if (node->is_leaf() && node->has_valid_edge()) {
				 throw std::runtime_error(fmt::format("node [{}] is leaf but has valid edge", node->to_string()));
			}
            if(!node->validate_key_order<K>()){
				throw std::runtime_error(fmt::format("unsorted node's entries [{}]", node->to_string()));
			}

            BtreeNodePtr last_child_node;
            validate_node_child_relation(node, last_child_node);

            auto neighbor_id = node->next_bnode();
            if (neighbor_id != empty_bnodeid && node->has_valid_edge()) {
				throw std::runtime_error(fmt::format("node [{}] has valid edge but next_bnode is not empty", node->to_string()));
			}
            if (!node->is_leaf() && neighbor_id == empty_bnodeid && !node->has_valid_edge()) {
				throw std::runtime_error(fmt::format("node [{}] is interior but has no valid edge and next_bnode is empty", node->to_string()));
			 }
            if (bnodeid == neighbor_id) {
			      throw std::runtime_error(fmt::format("node [{}] has next_bnode same as itself", node->to_string()));
			}

            if (neighbor_id != empty_bnodeid) {
                BtreeNodePtr neighbor_node;
                if (auto ret = read_node_impl(neighbor_id, neighbor_node); ret != btree_status_t::success) {
					throw std::runtime_error(fmt::format("reading neighbor node of [{}] failed for bnodeid: {} reason : {}", node->to_string(), neighbor_id, ret));
                }
                validate_next_node_relation(node, neighbor_node, last_child_node);
            }
        } catch (const std::exception& e) {
            LOGERROR("Validation failed for bnodeid: {} error: {}", bnodeid, e.what());
            throw;
        }
    }
}


template < typename K, typename V >
void Btree< K, V >::sanity_sub_tree(bnodeid_t bnodeid) const {
    if (bnodeid == 0) { bnodeid = m_root_node_info.bnode_id(); }
    BtreeNodePtr node;
    if (auto ret = read_node_impl(bnodeid, node); ret != btree_status_t::success) {
        LOGINFO("reading node failed for bnodeid: {} reason: {}", bnodeid, ret);
    } else {
        node->validate_key_order< K >();
        if (node->is_leaf()) { return; }
        uint32_t nentries = node->has_valid_edge() ? node->total_entries() + 1 : node->total_entries();
        std::vector< bnodeid_t > child_id_list;
        child_id_list.reserve(nentries);
        BT_REL_ASSERT_NE(node->has_valid_edge() && node->next_bnode() != empty_bnodeid, true,
                         "node {} has valid edge and next id is not empty", node->to_string());
        for (uint32_t i = 0; i < nentries; ++i) {
            validate_sanity_child(node, i);
            BtreeLinkInfo child_info;
            node->get_nth_value(i, &child_info, false /* copy */);
            child_id_list.push_back(child_info.bnode_id());
        }
        for (auto child_id : child_id_list) {
            sanity_sub_tree(child_id);
        }
    }
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
    BT_REL_ASSERT_NE(child_node->is_node_deleted(), true, "child node {} is deleted", child_node->to_string());
    if (ind >= parent_node->total_entries()) {
        BT_REL_ASSERT_EQ(parent_node->has_valid_edge(), true);
        if (ind > 0) { parent_key = parent_node->get_nth_key< K >(ind - 1, false); }
    } else {
        parent_key = parent_node->get_nth_key< K >(ind, false);
    }
    K previous_parent_key;
    if (ind > 0 && parent_node->total_entries() > 0) {
        previous_parent_key = parent_node->get_nth_key< K >(ind - 1, false);
    }
    for (uint32_t i = 0; i < child_node->total_entries(); ++i) {
        K cur_child_key = child_node->get_nth_key< K >(i, false);
        if(ind < parent_node->total_entries()){
            BT_REL_ASSERT_LE(cur_child_key.compare(parent_key), 0, " child {} {}-th key is greater than its parent's {} {}-th key", child_node->to_string(), i , parent_node->to_string(), ind);
            if(ind>0) {
                if(cur_child_key.compare(previous_parent_key) <= 0){
                    // there can be a transient case where a key appears in two children. When the replay is done, it should be fixed
                    // Consider the example Parent P, children C1, C2, C3, C4. A key is deleted resulting in a merge and C3 deleted, and the same key is inserted in the current cp
                    // Our case is that P is dirtied, C3 deleted, C4 updated and flushed. During recover, we will keep C3 and P remains the same.
                    // Since C4 is flushed, the key that was removd and inserted will showup in C3 and C4.
                    // After the replay post recovery, C3 should be gone and the tree is valid again.
                    BT_LOG(DEBUG, "child {} {}-th key is less than or equal to its parent's {} {}-th key", child_node->to_string(), i, parent_node->to_string(), ind - 1);
                }
            }

        } else {
            BT_REL_ASSERT_GT(cur_child_key.compare(parent_key), 0,
                             " child {} {}-th key is greater than its parent {} {}-th key", child_node->to_string(), i,
                             parent_node->to_string(), ind);
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
    child_key = child_node->get_first_key< K >();
    parent_node->get_nth_key< K >(ind, &parent_key, false);
    BT_REL_ASSERT_GT(child_key.compare(&parent_key), 0)
    BT_REL_ASSERT_LT(parent_key.compare_start(&child_key), 0);
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
