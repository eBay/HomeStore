//
// Created by Kadayam, Hari on 30/01/18.
//

#include "btree_node.h"
#include "simple_node.hpp"

namespace homeds { namespace btree {

#define DecBNodeType(ret)                     \
    template<btree_type BtreeType,            \
            typename K,                       \
            typename V,                       \
            btree_node_type InteriorNodeType, \
            btree_node_type LeafNodeType,     \
            size_t NodeSize >                 \
    ret BtreeNodeDeclType::

template<btree_type BtreeType,
            typename K,
            typename V,
            btree_node_type InteriorNodeType,
            btree_node_type LeafNodeType,
            size_t NodeSize >
BtreeNodeDeclType::BtreeNode() {
    init_btree_node();
}

#if 0
DecBNodeType(typename BtreeSpecificImplDeclType::HeaderType *) get_impl_node() {
    return &m_node_impl_header;
}
#endif

DecBNodeType(void) init_btree_node() {
    m_common_header.upgraders.set(0);
}

/************* CRUD on a node ************/
DecBNodeType(bool) put(const BtreeKey &key, const BtreeValue &val, PutType put_type) {
    return call_variant_method(this, put, key, val, put_type);
}

DecBNodeType(bool) remove_one(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
    return call_physical_method(this, remove_one, range, outkey, outval);
}

DecBNodeType(void) get(int ind, BtreeValue *outval, bool copy) const {
    call_variant_method_const(this, get, ind, outval, copy);
}

DecBNodeType(void) insert(const BtreeKey &key, const BtreeValue &val) {
    call_physical_method(this, insert, key, val);
}

DecBNodeType(void) insert(int ind, const BtreeKey &key, const BtreeValue &val) {
    call_variant_method(this, insert, ind, key, val);
}

DecBNodeType(void) remove(int ind) {
    call_variant_method(this, remove, ind);
}

DecBNodeType(void) update(int ind, const BtreeValue &val) {
    call_variant_method(this, update, ind, val);
}

DecBNodeType(void) update(int ind, const BtreeKey &key, const BtreeValue &val) {
    call_variant_method(this, update, ind, key, val);
}

DecBNodeType(auto) find(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) const {
    return call_physical_method_const(this, find, range, outkey, outval);
}

#ifndef NDEBUG
DecBNodeType(std::string) to_string() const {
    return call_variant_method_const(this, to_string);
}
#endif

/* Provides the occupied data size within the node */
DecBNodeType(bool) is_leaf() const {
    return call_variant_method_const(this, is_leaf);
}
DecBNodeType(void) set_leaf(bool leaf) {
    call_variant_method(this, set_leaf, leaf);
}
DecBNodeType(uint32_t) get_total_entries() const {
    return call_variant_method_const(this, get_total_entries);
}
DecBNodeType(uint32_t) get_available_size(const BtreeConfig &cfg) const {
    return call_variant_method_const(this, get_available_size, cfg);
}
DecBNodeType(bnodeid_t) get_node_id() const {
    return call_variant_method_const(this, get_node_id);
}
DecBNodeType(bnodeid_t) get_next_bnode() const {
    return call_variant_method_const(this, get_next_bnode);
}
DecBNodeType(void) set_next_bnode(bnodeid_t b) {
    call_variant_method(this, set_next_bnode, b);
}
DecBNodeType(bnodeid_t) get_edge_id() const {
    return call_variant_method_const(this, get_edge_id);
}
DecBNodeType(void) set_edge_id(bnodeid_t edge) {
    call_variant_method(this, set_edge_id, edge);
}
DecBNodeType(void) get_last_key(BtreeKey *out_lastkey) {
    call_variant_method(this, get_last_key, out_lastkey);
}
DecBNodeType(void) get_first_key(BtreeKey *out_firstkey) {
    call_variant_method(this, get_first_key, out_firstkey);
}
DecBNodeType(uint64_t) get_gen() const {
    return call_variant_method_const(this, get_gen);
}
DecBNodeType(void) inc_gen() {
    call_variant_method(this, inc_gen);
}
DecBNodeType(void) set_gen(uint64_t g) {
    call_variant_method(this, set_gen, g);
}
DecBNodeType(void) set_valid_node(bool valid) {
    call_variant_method(this, set_valid_node, valid);
}
DecBNodeType(bool) is_valid_node() const {
    return call_variant_method_const(this, is_valid_node);
}
///////////// Move and Delete related operations on a node //////////////
DecBNodeType(bool) is_split_needed(const BtreeConfig &cfg, const BtreeKey &k, const BtreeValue &v, int *out_ind_hint) const {
    return call_variant_method_const(this, is_split_needed, cfg, k, v, out_ind_hint);
}
DecBNodeType(bool) is_merge_needed(const BtreeConfig &cfg) const {
    return call_variant_method_const(this, is_merge_needed, cfg);
}
DecBNodeType(uint32_t) get_occupied_size(const BtreeConfig &cfg) const {
    return call_physical_method_const(this, get_occupied_size, cfg);
}
DecBNodeType(void) get_adjacent_indicies(uint32_t cur_ind, vector< int > &indices_list, uint32_t max_indices) const {
    call_physical_method_const(this, get_adjacent_indicies, cur_ind, indices_list, max_indices);
}

/* Following methods need to make best effort to move from other node upto provided entries or size. It should
 * return how much it was able to move actually (either entries or size)
 */
DecBNodeType(uint32_t) move_out_to_right_by_entries(const BtreeConfig &cfg,
                                                    boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                                    uint32_t nentries) {
    return call_variant_method(this, move_out_to_right_by_entries, cfg, to_variant_node(other_node.get()), nentries);
}

DecBNodeType(uint32_t) move_out_to_right_by_size(const BtreeConfig &cfg,
                                                 boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                                 uint32_t size) {
    return call_variant_method(this, move_out_to_right_by_size, cfg, to_variant_node(other_node.get()), size);
}

DecBNodeType(uint32_t) move_in_from_right_by_entries(const BtreeConfig &cfg,
                                                     boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                                     uint32_t nentries) {
    return call_variant_method(this, move_in_from_right_by_entries, cfg, to_variant_node(other_node.get()), nentries);
}
DecBNodeType(uint32_t) move_in_from_right_by_size(const BtreeConfig &cfg,
                                                  boost::intrusive_ptr<BtreeNodeDeclType> &other_node,
                                                  uint32_t size) {
    return call_variant_method(this, move_in_from_right_by_size, cfg, to_variant_node(other_node.get()), size);
}

DecBNodeType(void) lock(homeds::thread::locktype l) {
    if (l == homeds::thread::LOCKTYPE_NONE) {
        return;
    } else if (l == homeds::thread::LOCKTYPE_READ) {
        m_common_header.lock.lock_shared();
    } else {
        m_common_header.lock.lock();
    }
}

DecBNodeType(void) unlock(homeds::thread::locktype l) {
    if (l == homeds::thread::LOCKTYPE_NONE) {
        return;
    } else if (l == homeds::thread::LOCKTYPE_READ) {
        m_common_header.lock.unlock_shared();
    } else {
        m_common_header.lock.unlock();
    }
}

DecBNodeType(void) lock_upgrade() {
    m_common_header.upgraders.increment(1);
    this->unlock(homeds::thread::LOCKTYPE_READ);
    this->lock(homeds::thread::LOCKTYPE_WRITE);
}

DecBNodeType(void) lock_acknowledge() {
    m_common_header.upgraders.decrement(1);
}

DecBNodeType(bool) any_upgrade_waiters() {
    return (!m_common_header.upgraders.testz());
}

#if 0
template<btree_type BtreeType,
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize >
void intrusive_ptr_add_ref(BtreeNodeDeclType *n) {
    BtreeSpecificImplDeclType::ref_node(n);
}

template<btree_type BtreeType,
        typename K,
        typename V,
        btree_node_type InteriorNodeType,
        btree_node_type LeafNodeType,
        size_t NodeSize >
void intrusive_ptr_release(BtreeNodeDeclType *n) {
    if (BtreeSpecificImplDeclType::deref_node(n)) {
        n->~BtreeNodeDeclType();
        BtreeNodeAllocator<NodeSize>::deallocate((uint8_t *)n);
    }
}
#endif

DecBNodeType(uint32_t) get_nth_obj_size(int ind) const {
    return call_variant_method_const(this, get_nth_obj_size, ind);
}

DecBNodeType(void) get_nth_key(int ind, BtreeKey *outkey, bool copy) const {
    return call_variant_method_const(this, get_nth_key, ind, outkey, copy);
}

DecBNodeType(void) get_nth_value(int ind, BtreeValue *outval, bool copy) const {
    return call_variant_method_const(this, get_nth_value, ind, outval, copy);
}

// Compares the nth key (n=ind) with given key (cmp_key) and returns -1, 0, 1 if cmp_key <=> nth_key respectively
DecBNodeType(int) compare_nth_key(const BtreeKey &cmp_key, int ind) const {
    return call_variant_method_const(this, compare_nth_key, cmp_key, ind);
}

}}
