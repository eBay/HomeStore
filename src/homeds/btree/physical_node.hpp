/*
 * abstract_node.hpp
 *
 *  Created on: 16-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <iostream>
#include <cassert>
#include <pthread.h>
#include "btree_internal.h"
#include <folly/SharedMutex.h>
#include "homeds/thread/lock.hpp"
#include "homeds/utility/atomic_counter.hpp"

using namespace std;

namespace homeds { namespace btree {

#if 0
#define container_of(ptr, type, member) ({                      \
        (type *)( (char *)ptr - offsetof(type, member) );})
#endif

#define EDGE_ENTRY_INDEX    INVALID_POOL_NEXT

typedef struct __attribute__((__packed__)) {
    bnodeid_t node_id;
    bnodeid_t next_node;

    uint32_t nentries:27;
    uint32_t node_type:3;
    uint32_t leaf :1;
    uint32_t valid_node :1;

    uint64_t node_gen;
    bnodeid_t edge_entry;
} persistent_hdr_t;

#define PhysicalNodeDeclType  PhysicalNode<VNode, K, V, NodeSize>
template <typename VNode, typename K, typename V, size_t NodeSize>
class PhysicalNode {
protected:
    persistent_hdr_t m_pers_header;
    uint8_t m_node_area[0];

 public:
    PhysicalNode(bnodeid_t* id, bool init) {
        if (init) {
            set_leaf(true);
            set_total_entries(0);
            set_next_bnode(bnodeid_t(INVALID_BNODEID,0));
            set_gen(0);
            set_valid_node(true);
            set_edge_id(bnodeid_t(INVALID_BNODEID,0));
            set_node_id(*id);
        } else {
            assert(get_node_id() == *id);
        }
    }

    PhysicalNode(bnodeid_t id, bool init) {
        if (init) {
            set_leaf(true);
            set_total_entries(0);
            set_next_bnode(bnodeid_t(INVALID_BNODEID,0));
            set_gen(0);
            set_valid_node(true);
            set_edge_id(bnodeid_t(INVALID_BNODEID,0));
            set_node_id(id);
        } else {
            assert(get_node_id() == id);
        }
    }

    ~PhysicalNode() {
    }

    persistent_hdr_t *get_persistent_header() {
        return &m_pers_header;
    }

    uint32_t get_total_entries() const {
        return m_pers_header.nentries;
    }

    void set_total_entries(uint32_t n) {
        get_persistent_header()->nentries = n;
    }

    void inc_entries() {
        get_persistent_header()->nentries++;
    }

    void dec_entries() {
        get_persistent_header()->nentries--;
    }

    void add_entries(uint32_t addn) {
        get_persistent_header()->nentries += addn;
    }

    void sub_entries(uint32_t subn) {
        get_persistent_header()->nentries -= subn;
    }

    void set_node_id(bnodeid_t id) {
        get_persistent_header()->node_id = id;
    }

    bnodeid_t get_node_id() const {
        return m_pers_header.node_id;
    }

    bool is_leaf() const {
        return m_pers_header.leaf;
        //return get_persistent_header()->leaf;
    }

    void set_leaf(bool leaf) {
        get_persistent_header()->leaf = leaf;
    }

    btree_node_type get_node_type() const {
        return (btree_node_type) m_pers_header.node_type;
    }

    void set_node_type(btree_node_type t) {
        get_persistent_header()->node_type = t;
    }

    uint64_t get_gen() const {
        return m_pers_header.node_gen;
    }

    void inc_gen() {
        get_persistent_header()->node_gen++;
    }

    void flip_pc_gen_flag() {
        get_persistent_header()->node_id.m_pc_gen_flag = get_persistent_header()->node_id.m_pc_gen_flag?0:1;
    }
    
    void set_gen(uint64_t g) {
        get_persistent_header()->node_gen = g;
    }

    void set_valid_node(bool valid) {
        get_persistent_header()->valid_node = (valid ? 1 : 0);
    }

    bool is_valid_node() const {
        return m_pers_header.valid_node;
    }

    uint8_t *get_node_area_mutable() {
        return m_node_area;
    }

    const uint8_t *get_node_area() const {
        return m_node_area;
    }

    uint32_t get_occupied_size(const BtreeConfig &cfg) const {
        return (cfg.get_node_area_size() - to_variant_node_const()->get_available_size(cfg));
    }

    uint32_t get_suggested_min_size(const BtreeConfig &cfg) const {
        return cfg.get_max_key_size();
    }

    bool is_merge_needed(const BtreeConfig &cfg) const {
        return (get_occupied_size(cfg) < get_suggested_min_size(cfg));
    }

    bnodeid_t get_next_bnode() const {
        return m_pers_header.next_node;
    }

    void set_next_bnode(bnodeid_t b) {
        get_persistent_header()->next_node = b;
    }

    bnodeid_t get_edge_id() const {
        return m_pers_header.edge_entry;
    }

    void set_edge_id(bnodeid_t edge) {
        get_persistent_header()->edge_entry = edge;
    }

    ////////// Top level functions (CRUD on a node) //////////////////
    // Find the slot where the key is present. If not present, return the closest location for the key.
    // Assumption: Node lock is already taken
    auto find(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) const {
        auto result = bsearch(-1, get_total_entries(), range);
        if (result.end_of_search_index == get_total_entries()) {
            if (has_valid_edge()) {
                result.found = true;
            } else {
                assert(!result.found);
                return result;
            }
        }

        if (outval) {
            to_variant_node_const()->get(result.end_of_search_index, outval, true /* copy */);
        }

        if (!range.is_simple_search() && outkey) {
            to_variant_node_const()->get_nth_key(result.end_of_search_index, outkey, true /* copy */);
        }

        return result;
    }

    void get_last_key(BtreeKey *out_lastkey) {
        return to_variant_node()->get_nth_key(get_total_entries() - 1, out_lastkey, false);
    }

    void get_first_key(BtreeKey *out_firstkey) {
        return to_variant_node()->get_nth_key(0, out_firstkey, false);
    }

    bool put(const BtreeKey &key, const BtreeValue &val, PutType put_type, std::shared_ptr<BtreeValue> &existing_val) {
        auto result = find(key, nullptr, nullptr);
        bool ret = true;

        if (put_type == INSERT_ONLY_IF_NOT_EXISTS) {
            if (result.found) return false;
            to_variant_node()->insert(result.end_of_search_index, key, val);
        } else if (put_type == REPLACE_ONLY_IF_EXISTS) {
            if (!result.found) return false;
            to_variant_node()->update(result.end_of_search_index, key, val);
        } else if (put_type == REPLACE_IF_EXISTS_ELSE_INSERT) {
            (result.found) ? to_variant_node()->insert(result.end_of_search_index, key, val) :
                             to_variant_node()->update(result.end_of_search_index, key, val);
        } else if (put_type == APPEND_ONLY_IF_EXISTS) {
            if (!result.found) return false;
            append(result.end_of_search_index, key, val, existing_val);
        } else if (put_type == APPEND_IF_EXISTS_ELSE_INSERT) {
            (!result.found) ? to_variant_node()->insert(result.end_of_search_index, key, val) :
                             append(result.end_of_search_index, key, val, existing_val);
        } else {
            return false;
        }

        return ret;
    }

    void insert(const BtreeKey &key, const BtreeValue &val) {
        auto result = find(key, nullptr, nullptr);
        assert(!is_leaf() || (!result.found)); // We do not support duplicate keys yet
        to_variant_node()->insert(result.end_of_search_index, key, val);
    }

    bool remove_one(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        auto result = find(range, outkey, outval);
        if (!result.found) {
            return false;
        }

        to_variant_node()->remove(result.end_of_search_index);
        return true;
    }

    void append(uint32_t index, const BtreeKey &key, const BtreeValue &val, std::shared_ptr<BtreeValue> &existing_val) {
        // Get the nth value and do a callback to update its blob with the new value, being passed
        V nth_val;
        to_variant_node()->get_nth_value(index, &nth_val, false);
        nth_val.append_blob(val,existing_val);
        to_variant_node()->update(index, key, nth_val);
    }

    /* Update the key and value pair and after update if outkey and outval are non-nullptr, it fills them with
     * the key and value it just updated respectively */
    void update(const BtreeKey &key, const BtreeValue &val, BtreeKey *outkey, BtreeValue *outval) {
        auto result = find(key, outkey, outval);
        assert(result.found);
        to_variant_node()->update(result.end_of_search_index, val);
    }

    //////////// Edge Related Methods ///////////////
    void invalidate_edge() {
        set_edge_id(bnodeid_t(INVALID_BNODEID,0));
    }

    void set_edge_value(const BtreeValue &v) {
        BNodeptr *p = (BNodeptr *) &v;
        set_edge_id(p->get_node_id());
    }

    void get_edge_value(BtreeValue *v) const {
        if (is_leaf()) {
            return;
        }

        BNodeptr bnp(get_edge_id());
        uint32_t size;
        v->set_blob(bnp.get_blob());
    }

    bool has_valid_edge() const {
        if (is_leaf()) {
            return false;
        }

        BNodeptr bnp(get_edge_id());
        return (bnp.is_valid_ptr());
    }
    
    void get_adjacent_indicies(uint32_t cur_ind, vector< int > &indices_list, uint32_t max_indices) const {
        uint32_t i = 0;
        uint32_t start_ind;
        uint32_t end_ind;
        uint32_t nentries = this->get_total_entries();

        auto max_ind = ((max_indices / 2) - 1 + (max_indices % 2));
        end_ind = cur_ind + (max_indices / 2);
        if (cur_ind < max_ind) {
           end_ind += max_ind - cur_ind;
           start_ind = 0;
        } else {
           start_ind = cur_ind - max_ind;
        }

        for (i = start_ind; (i <= end_ind) && (indices_list.size() < max_indices); i++) {
            if (i == nentries) {
                if (this->has_valid_edge()) {
                    indices_list.push_back(i);
                }
                break;
            } else {
                indices_list.push_back(i);
            }
        }
    }

protected:
    auto bsearch(int start, int end, const BtreeSearchRange &range) const {
        uint32_t mid = 0;
        uint32_t min_ind_found = end;
	uint32_t second_min = end;
	uint32_t temp_end = end;
        BtreeKey *mid_key;

        struct {
            bool     found;
            uint32_t end_of_search_index;
        } ret{NO_MATCH, 0};

        while ((end - start) > 1) {
            mid = start + (end - start) / 2;

            int x = range.is_simple_search() ? to_variant_node_const()->compare_nth_key(*range.get_start_key(), mid) :
                    to_variant_node_const()->compare_nth_key_range(range, mid);
            if (x == 0) {
                ret.found = true;
                if (range.is_simple_search()) {
                    ret.end_of_search_index = mid;
                    return ret;
                }

                if (!range.is_left_leaning()) {
                    ret.end_of_search_index = mid;
                    return ret;
                }

                // If we are left leaning, keep looking for the lowest of
                // mid that matches within the range.
                if (mid < min_ind_found) {
		    second_min = min_ind_found;
                    min_ind_found = mid;
                }
                end = mid;
            } else if (x > 0) {
                end = mid;
            } else {
                start = mid;
            }
        }

        if (range.is_second_min() && (has_valid_edge() || second_min != temp_end)) {
        	  ret.end_of_search_index = ret.found ? second_min : end;
        } else {
      		  ret.end_of_search_index = ret.found ? min_ind_found : end;
	    }
        return ret;
    }

    VNode *to_variant_node() {
        return static_cast<VNode *>(this);
    }

    const VNode *to_variant_node_const() const {
        return static_cast<const VNode *>(this);
    }
}__attribute__((packed));

}
} // namespace homeds::btree
