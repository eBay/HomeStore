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
#include <isa-l/crc.h>
#include <utility/atomic_counter.hpp>

const uint16_t init_crc_16 = 0x8005;

#define MAGICAL_VALUE 0xab

using namespace std;

namespace homeds { namespace btree {

#if 0
#define container_of(ptr, type, member) ({                      \
        (type *)( (char *)ptr - offsetof(type, member) );})
#endif

#define EDGE_ENTRY_INDEX    INVALID_POOL_NEXT

typedef struct __attribute__((__packed__)) {
    uint8_t magic;
    uint16_t checksum;

    bnodeid_t node_id;
    bnodeid_t next_node;

    uint32_t nentries:27;
    uint32_t node_type:3;
    uint32_t leaf :1;
    uint32_t valid_node :1;

    uint64_t node_gen;
    bnodeid_t edge_entry;
} persistent_hdr_t;

#define physical_node_t  PhysicalNode<VNode, K, V, NodeSize>

template <typename VNode, typename K, typename V, size_t NodeSize>
class PhysicalNode {
protected:
    persistent_hdr_t m_pers_header;
    uint8_t m_node_area[0];

 public:
    PhysicalNode(bnodeid_t* id, bool init) {
        if (init) {
            set_magic();
            init_checksum();
            set_leaf(true);
            set_total_entries(0);
            set_next_bnode(bnodeid_t::empty_bnodeid());
            set_gen(0);
            set_valid_node(true);
            set_edge_id(bnodeid_t::empty_bnodeid());
            set_node_id(*id);
        } else {
            assert(get_node_id() == *id);
        }
    }

    PhysicalNode(bnodeid_t id, bool init) {
        if (init) {
            set_magic();
            init_checksum();
            set_leaf(true);
            set_total_entries(0);
            set_next_bnode(bnodeid_t::empty_bnodeid());
            set_gen(0);
            set_valid_node(true);
            set_edge_id(bnodeid_t::empty_bnodeid());
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

    uint8_t get_magic() const {
        return m_pers_header.magic;
    }

    void set_magic() {
        get_persistent_header()->magic = MAGICAL_VALUE;
    }

    uint16_t get_checksum() const {
        return m_pers_header.checksum;
    }

    void init_checksum() {
        get_persistent_header()->checksum = 0;
    }

#ifndef NO_CHECKSUM
    void set_checksum(size_t size) {
        get_persistent_header()->checksum =
            crc16_t10dif(init_crc_16, m_node_area, size);
    }

    bool verify_node(size_t size) {
        return (get_magic() == MAGICAL_VALUE && get_checksum() ==
                crc16_t10dif(init_crc_16, m_node_area, size))?
            true : false;
    }
#endif

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

    uint64_t get_node_id_int() const {
        return m_pers_header.node_id.m_id;
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
        get_persistent_header()->node_id.m_pc_gen_flag = get_persistent_header()->node_id.m_pc_gen_flag ? 0 : 1;
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
    auto find(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval, bool copy_key = true,
            bool copy_val = true) const {
        auto result = bsearch(-1, get_total_entries(), range);
        if (result.end_of_search_index == (int)get_total_entries()) {
            if (has_valid_edge()) {
                result.found = true;
            } else {
                assert(!result.found);
                return result;
            }
        }

        if (outval) {
            to_variant_node_const()->get(result.end_of_search_index, outval, copy_val /* copy */);
        }

        if (!range.is_simple_search() && outkey) {
            to_variant_node_const()->get_nth_key(result.end_of_search_index, outkey, copy_key /* copy */);
        }

        return result;
    }

    auto find(const BtreeKey& find_key, BtreeValue *outval, bool copy_val = true) const {
        return find(BtreeSearchRange(find_key), nullptr, outval, false, copy_val);
    }

    void get_last_key(BtreeKey *out_lastkey) {
        return to_variant_node()->get_nth_key(get_total_entries() - 1, out_lastkey, false);
    }

    void get_first_key(BtreeKey *out_firstkey) {
        return to_variant_node()->get_nth_key(0, out_firstkey, false);
    }

    void get_var_nth_key(int i, BtreeKey *out_firstkey) {
        return to_variant_node()->get_nth_key(i, out_firstkey, false);
    }

    uint32_t get_all(const BtreeSearchRange &range, uint32_t max_count,
                                int &start_ind, int &end_ind,
                     std::vector<std::pair<K, V>> *out_values = nullptr) {
        auto count = 0U;
        // Get the start index of the search range.
        auto start_result = find(range.extract_start_of_range(), nullptr, nullptr);
        start_ind = start_result.end_of_search_index;
        if (start_result.found && !range.is_start_inclusive()) { start_ind++; }

        // Get the end index of the search range.
        auto end_result = find(range.extract_end_of_range(), nullptr, nullptr);
        end_ind = end_result.end_of_search_index;

        if ((!end_result.found && is_leaf())//end range not found in leaf
            || !range.is_end_inclusive() // end not inclusive
            || (!is_leaf() && end_ind==(int)get_total_entries() && !has_valid_edge()))// end not found coz of invalid edge for internal node
            end_ind--; 
        if(!is_leaf() && end_ind<start_ind) end_ind = start_ind;
        assert(is_leaf() || (!is_leaf() && start_ind<=end_ind));

#ifndef NDEBUG
        if(end_ind > 0 && end_ind>start_ind){
            K second_last_key;
            get_var_nth_key(end_ind-1,&second_last_key);
            assert(second_last_key.compare(range.extract_end_of_range().get_start_key())<0);
        }
        
#endif
        
        if(out_values==nullptr){
            int total = end_ind-start_ind+1;
            if(total<0)total=0;
            if(total>(int)max_count)total=max_count;
            return total;
        }
        for (auto i = start_ind; ((i <= end_ind) && (count < max_count)); i++) {
            K key;V value;
            if(i==(int)get_total_entries() && !is_leaf())
                get_edge_value(&value);//invalid key in case of edge entry for internal node
            else {
                to_variant_node()->get_nth_key(i, &key, true);
                to_variant_node()->get_nth_value(i, &value, true);
            }
            out_values->emplace_back(std::make_pair<>(key, value));
            count++;
        }
        return count;
    }
    
#if 0
    void get_nth_element(int n, BtreeKey *out_key, BtreeValue *out_val, bool is_copy) {
        if (out_key) { to_variant_node()->get_nth_key(n, out_key, is_copy); }
        if (out_val) { to_variant_node()->get_nth_value(n, out_val, is_copy); }
    }
#endif

    bool put(const BtreeKey &key, const BtreeValue &val, PutType put_type, BtreeValue &existing_val) {
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
            assert(0);
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

    void append(uint32_t index, const BtreeKey &key, const BtreeValue &val, BtreeValue &existing_val) {
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
        set_edge_id(bnodeid::empty_bnodeid());
    }

    void set_edge_value(const BtreeValue &v) {
        BtreeNodeInfo *bni = (BtreeNodeInfo *) &v;
        set_edge_id(bni->bnode_id());
    }

    void get_edge_value(BtreeValue *v) const {
        if (is_leaf()) {
            return;
        }
        v->set_blob(BtreeNodeInfo(get_edge_id()).get_blob());
    }

    bool has_valid_edge() const {
        if (is_leaf()) {
            return false;
        }

        return (get_edge_id().is_valid());
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
    
    /* Note: Both start and end are not included in search */
    auto bsearch(int start, int end, const BtreeSearchRange &range) const {
        int mid = 0;
        int initial_end = end;
        int min_ind_found = INT32_MAX;
        int second_min = INT32_MAX;
        int max_ind_found = 0;
        BtreeKey *mid_key;

        struct {
            bool found;
            int  end_of_search_index;
        } ret{false, 0};
        
        if ((end - start) <= 1) {
            return ret;
        }
        
        auto selection = range.selection_option();

        while ((end - start) > 1) {
            mid = start + (end - start) / 2;
            assert(mid >=0 && mid < (int)get_total_entries());
            int x = range.is_simple_search() ?
                    to_variant_node_const()->compare_nth_key(*range.get_start_key(), mid) :
                    to_variant_node_const()->compare_nth_key_range(range, mid);
            if (x == 0) {
                ret.found = true;
                if ((range.is_simple_search() || (selection == DO_NOT_CARE))) {
                    ret.end_of_search_index = mid;
                    return ret;
                } else if ((selection == LEFT_MOST) || (selection == SECOND_TO_THE_LEFT) || 
                            selection == BEST_FIT_TO_CLOSEST) {
                    if (mid < min_ind_found) {
                        second_min = min_ind_found;
                        min_ind_found = mid;
                    }
                    end = mid;
                } else if (selection == RIGHT_MOST) {
                    if (mid > max_ind_found) { max_ind_found = mid; }
                    start = mid;
                } else {
                    assert(0);
                }
            } else if (x > 0) {
                end = mid;
            } else {
                start = mid;
            }
        }
        

        /* TODO: this logic should be in the caller of bsearch. It will be going to make
         * bsearch interface more simpler.
         */
        if (ret.found) {
            if (selection == LEFT_MOST) {
                assert(min_ind_found != INT32_MAX);
                ret.end_of_search_index = min_ind_found;
            } else if (selection == SECOND_TO_THE_LEFT || selection == BEST_FIT_TO_CLOSEST) {
                assert(min_ind_found != INT32_MAX);
                if (second_min == INT32_MAX) {
                    if (((int)(min_ind_found + 1) < initial_end) &&
                        (to_variant_node_const()->compare_nth_key_range(range, min_ind_found+1) == 0)) {
                        // We have a min_ind_found, but not second min, so check if next is valid.
                        ret.end_of_search_index = min_ind_found + 1;
                    } else {
                        ret.end_of_search_index = min_ind_found;
                    }
                } else {
                    ret.end_of_search_index = second_min;
                }
            } else if (selection == RIGHT_MOST) {
                assert(max_ind_found != INT32_MAX);
                ret.end_of_search_index = max_ind_found;
            }
        } else if (selection == BEST_FIT_TO_CLOSEST) {
            ret.found = true;
            if (has_valid_edge()) {
                ret.end_of_search_index = end;
            } else {
                ret.end_of_search_index = end - 1;
            }
        } else {
            ret.end_of_search_index = end;
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
