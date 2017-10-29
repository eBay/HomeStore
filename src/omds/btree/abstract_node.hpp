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

#define container_of(ptr, type, member) ({                      \
        (type *)( (char *)ptr - offsetof(type,member) );})

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

class AbstractNode {
protected:
    persistent_hdr_t m_pers_header;
    transient_hdr_t m_trans_header;
    uint8_t m_nodespace[0];

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
    virtual void get(int ind, BtreeValue *outval) const = 0;

    virtual void insert(int ind, BtreeKey &key, BtreeValue &val) = 0;

    virtual void remove(int ind) = 0;

    virtual void update(int ind, BtreeValue &val) = 0;

    virtual void update(int ind, BtreeKey &key, BtreeValue &val) = 0;

#ifndef NDEBUG

    virtual void print() = 0;

#endif

    ///////////// Move and Delete related operations on a node //////////////
    virtual bool is_split_needed(BtreeConfig &cfg, BtreeKey &k, BtreeValue &v, int *out_ind_hint) const = 0;

    virtual void move_out_right(AbstractNode &other_node, uint32_t nentries) = 0;

    virtual void move_in_right(AbstractNode &other_node, uint32_t nentries) = 0;

    virtual void get_adjacent_indicies(uint32_t cur_ind, vector< int > &indices_list, uint32_t max_indices) const = 0;

protected:
    virtual uint32_t get_nth_obj_size(int ind) const = 0;

    virtual void set_nth_obj(int ind, BtreeKey &k, BtreeValue &v) = 0;

    virtual void get_nth_key(int ind, BtreeKey *outkey, bool copy) const = 0;

    virtual void get_nth_value(int ind, BtreeValue *outval, bool copy) const = 0;

    // Compares the nth key (n=ind) with given key (cmp_key) and returns -1, 0, 1 if cmp_key <=> nth_key respectively
    virtual int compare_nth_key(BtreeKey &cmp_key, int ind) const = 0;

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

    void lock(omds::thread::locktype_t l) {
        if (l == omds::thread::LOCK_NONE) {
            return;
        } else if (l == omds::thread::LOCK_READ) {
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
        this->lock(omds::thread::LOCK_WRITE);
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

    uint32_t get_max_entries(BtreeConfig &cfg) const {
        return (is_leaf() ? cfg.get_max_leaf_entries_per_node() : cfg.get_max_interior_entries_per_node());
    }

    uint32_t available_slots(BtreeConfig &cfg) {
        return (get_max_entries(cfg) - get_total_entries());
    }

//#define MINIMAL_THRESHOLD_PCT    0.40   // Should be more than 40% of space
#define MINIMAL_THRESHOLD_PCT    0.10   // Should be more than 40% of space

    bool is_minimal(BtreeConfig &cfg) {
        return is_minimal(available_slots(cfg));
    }

    bool is_minimal(uint32_t availSlots) {
        return (availSlots >= ((double) get_total_entries() * (1 - MINIMAL_THRESHOLD_PCT)));
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

    uint8_t *get_node_space() {
        return m_nodespace;
    }

    const uint8_t *get_node_space_const() const {
        return m_nodespace;
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
    bool find(BtreeKey &key, BtreeKey *outkey, BtreeValue *outval, int *outind) const {
        bool isFound = false;
        *outind = bsearch(-1, get_total_entries(), key, &isFound);
        if (*outind == get_total_entries()) {
            if (has_valid_edge()) {
                isFound = true;
            } else {
                assert(isFound == false);
                return isFound;
            }
        }

        if (outval != nullptr) {
            get(*outind, outval);
        }

        if (key.is_regex_key() && outkey != nullptr) {
            get_nth_key(*outind, outkey, true);
        }

        return isFound;
    }

    virtual void get_last_key(BtreeKey *out_lastkey) {
        return get_nth_key(get_total_entries() - 1, out_lastkey, false);
    }

    virtual void get_first_key(BtreeKey *out_firstkey) {
        return get_nth_key(0, out_firstkey, false);
    }

    void insert(BtreeKey &key, BtreeValue &val) {
        bool isFound = false;

        int ind;
        isFound = find(key, nullptr, nullptr, &ind);
        assert(!is_leaf() || (isFound == false)); // We do not support duplicate keys yet

        insert(ind, key, val);
    }

    bool remove(BtreeKey &key) {
        bool isFound = false;
        int ind;

        isFound = find(key, key.get_result_key(), nullptr, &ind);
        if (!isFound) {
            return false;
        }

        remove(ind);
        return true;
    }

    void update(BtreeKey &key, BtreeValue &val) {
        bool is_found = false;
        int ind;

        is_found = find(key, key.get_result_key(), nullptr, &ind);
        assert(is_found == true);
        update(ind, val);
    }

    //////////// Edge Related Methods ///////////////
    void invalidate_edge() {
        set_edge_id(INVALID_BNODEID);
    }

    void set_edge_value(BtreeValue &v) {
        BNodeptr *p = (BNodeptr *) &v;
        set_edge_id(p->get_node_id());
    }

    void get_edge_value(BtreeValue *v) const {
        if (is_leaf()) {
            return;
        }

        BNodeptr bnp(get_edge_id());
        uint32_t size;
        uint8_t *blob = bnp.get_blob(&size);
        v->set_blob(blob, size);
    }

    bool has_valid_edge() const {
        if (is_leaf()) {
            return false;
        }

        BNodeptr bnp(get_edge_id());
        return (bnp.is_valid_ptr());
    }

protected:
    uint32_t bsearch(int start, int end, BtreeKey &key, bool *is_found) const {
        uint32_t mid = 0;
        uint32_t min_ind_found = end;
        *is_found = false;
        BtreeKey *mid_key;

        while ((end - start) > 1) {
            mid = start + (end - start) / 2;

            int x = compare_nth_key(key, mid);

            if (x == 0) {
                *is_found = true;

                if (!key.is_regex_key()) {
                    return mid;
                }

                BtreeRegExKey &rkey = static_cast<BtreeRegExKey &>(key);
                if (!rkey.is_left_leaning()) {
                    return mid;
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

        return ((*is_found) ? min_ind_found : end);
    }

}__attribute__((packed));

}
} // namespace omds::btree
#endif
