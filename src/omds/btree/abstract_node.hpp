/*
 * abstract_node.hpp
 *
 *  Created on: 16-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#ifndef BTREE_ABSTRACTNODE_HPP_
#define BTREE_ABSTRACTNODE_HPP_

#include <iostream>
#include <assert.h>
#include <pthread.h>
#include "btree_internal.h"
#include <glog/logging.h>
#include "omds/thread/lock.hpp"
#include "omds/utility/atomic_counter.hpp"

using namespace std;

namespace omds {
namespace btree {

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

typedef struct __attribute__((__packed__)) {
    pthread_rwlock_t lock;
    omds::atomic_counter< uint16_t > upgraders;
    omds::atomic_counter< int16_t > refcount;
} transient_hdr_t;

template <typename K, typename V>
class AbstractNode {
protected:
    persistent_hdr_t m_pers_header;
    transient_hdr_t m_trans_header;
    uint8_t m_node_area[0];

    /*************** Class Definitions ******************
    ///////// Helper methods for CRUD on a node ////////////////////
    void insert(BtreeKey& key, BtreeValue& val);
    bool remove(BtreeKey &key);
    void update(BtreeKey& key, BtreeValue& val);

    // Find the slot where the key is present. If not present, return the closest location for the key.
    // Assumption: Node lock is already taken
    bool find(BtreeKey &key, BtreeKey *outkey, BtreeValue *outval, int *outind) const;

    void get_last_key(BtreeKey *out_lastkey);
    void get_first_key(BtreeKey *out_firstkey);

    void lock(omds::thread::locktype_t l);
    void unlock(bool deref = true);


protected:
    uint32_t bsearch(int start, int end, BtreeKey &key, bool *is_found) const;

     ************** Class Definitions ******************/

public:
    ////////// Top level functions (CRUD on a node) //////////////////
    virtual void get(int ind, BtreeValue *outval, bool copy) const = 0;
    virtual void insert(int ind, const BtreeKey &key, const BtreeValue &val) = 0;
    virtual void remove(int ind) = 0;
    virtual void update(int ind, const BtreeValue &val) = 0;
    virtual void update(int ind, const BtreeKey &key, const BtreeValue &val) = 0;

#ifndef NDEBUG
    virtual void print() = 0;
#endif

    /* Provides the occupied data size within the node */
    virtual uint32_t get_available_size(const BtreeConfig &cfg) const = 0;

    ///////////// Move and Delete related operations on a node //////////////
    virtual bool is_split_needed(const BtreeConfig &cfg, const BtreeKey &k, const BtreeValue &v,
                                 int *out_ind_hint) const = 0;

    /* Following methods need to make best effort to move from other node upto provided entries or size. It should
     * return how much it was able to move actually (either entries or size)
     */
    virtual uint32_t move_out_to_right_by_entries(const BtreeConfig &cfg, AbstractNode &other_node,
                                                  uint32_t nentries) = 0;
    virtual uint32_t move_out_to_right_by_size(const BtreeConfig &cfg, AbstractNode &other_node,
                                               uint32_t size) = 0;
    virtual uint32_t move_in_from_right_by_entries(const BtreeConfig &cfg, AbstractNode &other_node,
                                                   uint32_t nentries) = 0;
    virtual uint32_t move_in_from_right_by_size(const BtreeConfig &cfg, AbstractNode &other_node,
                                                uint32_t size) = 0;

protected:
    virtual uint32_t get_nth_obj_size(int ind) const = 0;
    virtual void get_nth_key(int ind, BtreeKey *outkey, bool copy) const = 0;
    virtual void get_nth_value(int ind, BtreeValue *outval, bool copy) const = 0;

    // Compares the nth key (n=ind) with given key (cmp_key) and returns -1, 0, 1 if cmp_key <=> nth_key respectively
    virtual int compare_nth_key(const BtreeKey &cmp_key, int ind) const = 0;

public:
    AbstractNode(bnodeid_t id, bool init_pers, bool init_trans) {
        if (init_pers) {
            set_node_type(BTREE_NODETYPE_SIMPLE);
            set_leaf(true);
            set_total_entries(0);
            set_next_bnode(INVALID_BNODEID);
            set_gen(0);
            set_valid_node(true);
            set_edge_id(INVALID_BNODEID);
            set_node_id(id);
        } else {
            assert(get_node_id() == id);
        }

        if (init_trans) {
            memset(get_transient_header(), 0, sizeof(transient_hdr_t));
            reset_reference();
            get_transient_header()->upgraders.set(0);
            int ret = pthread_rwlock_init(&get_transient_header()->lock, nullptr);
            if (ret != 0) {
                //LOG(ERROR) << "Error in initializing pthread ret=" << ret;
            }
        }
    }

    ~AbstractNode() {
        pthread_rwlock_destroy(&get_transient_header()->lock);
    }

    persistent_hdr_t *get_persistent_header() {
        return &m_pers_header;
    }

    transient_hdr_t *get_transient_header() {
        return &m_trans_header;
    }

    void lock(omds::thread::locktype l) {
        if (l == omds::thread::LOCKTYPE_NONE) {
            return;
        } else if (l == omds::thread::LOCKTYPE_READ) {
            pthread_rwlock_rdlock(&get_transient_header()->lock);
        } else {
            pthread_rwlock_wrlock(&get_transient_header()->lock);
        }

#if 0
#ifdef DEBUG
        lockedCount++;
#endif
#endif
    }

    void unlock(bool deref = true) {
        pthread_rwlock_unlock(&get_transient_header()->lock);
#if 0
#ifdef DEBUG
        lockedCount--;
#endif
#endif
    }

    void lock_upgrade() {
        get_transient_header()->upgraders.increment(1);
        this->unlock(false);
        this->lock(omds::thread::LOCKTYPE_WRITE);
    }

    void lock_acknowledge() {
        get_transient_header()->upgraders.decrement(1);
    }

    bool any_upgrade_waiters() {
        return (get_transient_header()->upgraders.testz() != 0);
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

    uint32_t get_max_entries(const BtreeConfig &cfg) const {
        return (is_leaf() ? cfg.get_max_leaf_entries_per_node() : cfg.get_max_interior_entries_per_node());
    }

    uint32_t available_slots(const BtreeConfig &cfg) {
        return (get_max_entries(cfg) - get_total_entries());
    }

    void set_node_id(bnodeid_t id) {
        get_persistent_header()->node_id = id;
    }

    bnodeid_t get_node_id() {
        return get_persistent_header()->node_id;
    }

    bool is_leaf() const {
        return m_pers_header.leaf;
        //return get_persistent_header()->leaf;
    }

    void set_leaf(bool leaf) {
        get_persistent_header()->leaf = leaf;
    }

    btree_nodetype_t get_node_type() {
        return (btree_nodetype_t) get_persistent_header()->node_type;
    }

    void set_node_type(btree_nodetype_t t) {
        get_persistent_header()->node_type = t;
    }

    uint64_t get_gen() {
        return get_persistent_header()->node_gen;
    }

    void inc_gen() {
        get_persistent_header()->node_gen++;
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

    void ref_node() {
        get_transient_header()->refcount.increment();
    }

    bool deref_node() {
        return get_transient_header()->refcount.decrement_testz();
    }

    void reset_reference() {
        get_transient_header()->refcount.set(0);
    }

    int16_t get_reference() const {
        return (m_trans_header.refcount.get());
    }

    uint8_t *get_node_area_mutable() {
        return m_node_area;
    }

    const uint8_t *get_node_area() const {
        return m_node_area;
    }

    uint32_t get_node_area_size(const BtreeConfig &cfg) const {
        return (uint32_t) (cfg.get_node_size() - (get_node_area() - (uint8_t *)this));
    }

    uint32_t get_occupied_size(const BtreeConfig &cfg) const {
        return (get_node_area_size(cfg) - get_available_size(cfg));
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
            get(result.end_of_search_index, outval, true /* copy */);
        }

        if (!range.is_simple_search() && outkey) {
            get_nth_key(result.end_of_search_index, outkey, true /* copy */);
        }

        return result;
    }

    virtual void get_last_key(BtreeKey *out_lastkey) {
        return get_nth_key(get_total_entries() - 1, out_lastkey, false);
    }

    virtual void get_first_key(BtreeKey *out_firstkey) {
        return get_nth_key(0, out_firstkey, false);
    }

    bool put(const BtreeKey &key, const BtreeValue &val, PutType put_type) {
        auto result = find(key, nullptr, nullptr);
        bool ret = true;

        if (put_type == INSERT_ONLY_IF_NOT_EXISTS) {
            if (result.found) return false;
            insert(result.end_of_search_index, key, val);
        } else if (put_type == REPLACE_ONLY_IF_EXISTS) {
            if (!result.found) return false;
            update(result.end_of_search_index, key, val);
        } else if (put_type == REPLACE_IF_EXISTS_ELSE_INSERT) {
            (result.found) ? insert(result.end_of_search_index, key, val) : update(result.end_of_search_index, key, val);
        } else if (put_type == APPEND_ONLY_IF_EXISTS) {
            if (!result.found) return false;
            append(result.end_of_search_index, key, val);
        } else if (put_type == APPEND_IF_EXISTS_ELSE_INSERT) {
            (result.found) ? insert(result.end_of_search_index, key, val) : append(result.end_of_search_index, key, val);
        } else {
            return false;
        }

        return ret;
    }

    void insert(const BtreeKey &key, const BtreeValue &val) {
        auto result = find(key, nullptr, nullptr);
        assert(!is_leaf() || (!result.found)); // We do not support duplicate keys yet
        insert(result.end_of_search_index, key, val);
    }

    bool remove_one(const BtreeSearchRange &range, BtreeKey *outkey, BtreeValue *outval) {
        auto result = find(range, outkey, outval);
        if (!result.found) {
            return false;
        }

        remove(result.end_of_search_index);
        return true;
    }

    void append(uint32_t index, const BtreeKey &key, const BtreeValue &val) {
        // Get the nth value and do a callback to update its blob with the new value, being passed
        V nth_val;
        get_nth_value(index, &nth_val, false);
        nth_val.append_blob(val);
        update(index, key, nth_val);
    }

    /* Update the key and value pair and after update if outkey and outval are non-nullptr, it fills them with
     * the key and value it just updated respectively */
    void update(const BtreeKey &key, const BtreeValue &val, BtreeKey *outkey, BtreeValue *outval) {
        auto result = find(key, outkey, outval);
        assert(result.found);
        update(result.end_of_search_index, val);
    }

    //////////// Edge Related Methods ///////////////
    void invalidate_edge() {
        set_edge_id(INVALID_BNODEID);
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
        int i = 0;
        int start_ind;
        int end_ind;
        uint32_t nentries = this->get_total_entries();

        start_ind = cur_ind - ((max_indices / 2) - 1 + (max_indices % 2));
        end_ind = cur_ind + (max_indices / 2);
        if (start_ind < 0) {
            end_ind -= start_ind;
            start_ind = 0;
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
        BtreeKey *mid_key;

        struct {
            bool     found;
            uint32_t end_of_search_index;
        } ret{NO_MATCH, 0};

        while ((end - start) > 1) {
            mid = start + (end - start) / 2;

            int x = compare_nth_key(*range.get_start_key(), mid);
            if (x == 0) {
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
                    min_ind_found = mid;
                }
                end = mid;
            } else if (x > 0) {
                end = mid;
            } else {
                start = mid;
            }
        }

        ret.end_of_search_index = ret.found ? min_ind_found : end;
        return ret;
    }

}__attribute__((packed));

}
} // namespace omds::btree
#endif
