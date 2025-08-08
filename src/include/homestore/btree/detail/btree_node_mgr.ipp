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
#include <homestore/btree/node_variant/simple_node.hpp>
#include <homestore/btree/node_variant/varlen_node.hpp>
#include <homestore/btree/node_variant/prefix_node.hpp>
#include <sisl/fds/utils.hpp>
// #include <iomgr/iomgr_flip.hpp>

#include <chrono>

namespace homestore {
template < typename T, typename... Args >
static BtreeNode* do_create_node(BtreeNode::Allocator::Token token, Args&&... args) {
    uint8_t* ptr = BtreeNode::Allocator::get(token).alloc_btree_node(sizeof(T));
    T* node = new (ptr) T(std::forward< Args >(args)..., token);
    return dynamic_cast< BtreeNode* >(node);
}

template < typename K, typename V, typename... Args >
static BtreeNode* do_form_node(btree_node_type node_type, BtreeNode::Allocator::Token token, Args&&... args) {
    BtreeNode* n{nullptr};
    switch (node_type) {
    case btree_node_type::VAR_OBJECT:
        n = do_create_node< VarObjSizeNode< K, V > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::FIXED:
        n = do_create_node< SimpleNode< K, V > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::VAR_VALUE:
        n = do_create_node< VarValueSizeNode< K, V > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::VAR_KEY:
        n = do_create_node< VarKeySizeNode< K, V > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::FIXED_PREFIX:
        n = do_create_node< FixedPrefixNode< K, V > >(token, std::forward< Args >(args)...);
        break;

    default:
        RELEASE_ASSERT(false, "Unsupported node type {}", node_type);
        break;
    }
    return n;
}

#if 0
template < typename V, typename... Args >
static BtreeNode* do_form_node(btree_node_type node_type, BtreeNode::Allocator::Token token, Args&&... args) {
    BtreeNode* n{nullptr};
    switch (node_type) {
    case btree_node_type::VAR_OBJECT:
        n = is_leaf ? do_create_node< VarObjSizeNode< K, V > >(token, std::forward< Args >(args)...)
                    : do_create_node< VarObjSizeNode< K, BtreeLinkInfo > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::FIXED:
        n = is_leaf ? do_create_node< SimpleNode< K, V > >(token, std::forward< Args >(args)...)
                    : do_create_node< SimpleNode< K, BtreeLinkInfo > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::VAR_VALUE:
        n = is_leaf ? do_create_node< VarValueSizeNode< K, V > >(token, std::forward< Args >(args)...)
                    : do_create_node< VarValueSizeNode< K, BtreeLinkInfo > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::VAR_KEY:
        n = is_leaf ? do_create_node< VarKeySizeNode< K, V > >(token, std::forward< Args >(args)...)
                    : do_create_node< VarKeySizeNode< K, BtreeLinkInfo > >(token, std::forward< Args >(args)...);
        break;

    case btree_node_type::PREFIX:
        n = is_leaf ? do_create_node< FixedPrefixNode< K, V > >(token, std::forward< Args >(args)...)
                    : do_create_node< FixedPrefixNode< K, BtreeLinkInfo > >(token, std::forward< Args >(args)...);
        break;

    default:
        RELEASE_ASSERT(false, "Unsupported node type {}", node_type);
        break;
    }
    return n;
}
#endif

template < typename K, typename V >
BtreeNodePtr Btree< K, V >::new_node(bnodeid_t id, bool is_leaf, BtreeNode::Allocator::Token token) const {
    BtreeNodePtr n;
    if (is_leaf) {
        n = BtreeNodePtr{do_form_node< K, V >(m_bt_cfg.leaf_node_type(), token, id, is_leaf, m_bt_cfg.node_size())};
    } else {
        n = BtreeNodePtr{
            do_form_node< K, BtreeLinkInfo >(m_bt_cfg.interior_node_type(), token, id, is_leaf, m_bt_cfg.node_size())};
    }
    return n;
}

template < typename K, typename V >
BtreeNodePtr Btree< K, V >::load_node(uint8_t* node_buf, bnodeid_t id, BtreeNode::Allocator::Token token) const {
    BtreeNodePtr n;
    if (BtreeNode::identify_leaf_node(node_buf)) {
        n = BtreeNodePtr{do_form_node< K, V >(m_bt_cfg.leaf_node_type(), token, node_buf, id)};
    } else {
        n = BtreeNodePtr{do_form_node< K, BtreeLinkInfo >(m_bt_cfg.interior_node_type(), token, node_buf, id)};
    }
    return n;
}

#if 0
template < typename K, typename V >
BtreeNode* Btree< K, V >::load_node(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf,
                                    BtreeNode::Allocator::Token token) const {
    BtreeNode* n{nullptr};
    btree_node_type node_type = is_leaf ? m_bt_cfg.leaf_node_type() : m_bt_cfg.interior_node_type();

    switch (node_type) {
    case btree_node_type::VAR_OBJECT:
        n = is_leaf
            ? do_create_node< VarObjSizeNode< K, V > >(token, node_buf, id, init_buf, true, m_bt_cfg.node_size())
            : do_create_node< VarObjSizeNode< K, BtreeLinkInfo > >(token, node_buf, id, init_buf, false,
                                                                   m_bt_cfg.node_size());
        break;

    case btree_node_type::FIXED:
        n = is_leaf ? do_create_node< SimpleNode< K, V > >(token, node_buf, id, init_buf, true, m_bt_cfg.node_size())
                    : do_create_node< SimpleNode< K, BtreeLinkInfo > >(token, node_buf, id, init_buf, false,
                                                                       m_bt_cfg.node_size());
        break;

    case btree_node_type::VAR_VALUE:
        n = is_leaf
            ? do_create_node< VarValueSizeNode< K, V > >(token, node_buf, id, init_buf, true, m_bt_cfg.node_size())
            : do_create_node< VarValueSizeNode< K, BtreeLinkInfo > >(token, node_buf, id, init_buf, false,
                                                                     m_bt_cfg.node_size());
        break;

    case btree_node_type::VAR_KEY:
        n = is_leaf
            ? do_create_node< VarKeySizeNode< K, V > >(token, node_buf, id, init_buf, true, m_bt_cfg.node_size())
            : do_create_node< VarKeySizeNode< K, BtreeLinkInfo > >(token, node_buf, id, init_buf, false,
                                                                   m_bt_cfg.node_size());
        break;

    case btree_node_type::PREFIX:
        n = is_leaf
            ? do_create_node< FixedPrefixNode< K, V > >(token, node_buf, id, init_buf, true, m_bt_cfg.node_size())
            : do_create_node< FixedPrefixNode< K, BtreeLinkInfo > >(token, node_buf, id, init_buf, false,
                                                                    m_bt_cfg.node_size());
        break;

    default:
        BT_REL_ASSERT(false, "Unsupported node type {}", node_type);
        break;
    }

    return n;
}
#endif
} // namespace homestore
