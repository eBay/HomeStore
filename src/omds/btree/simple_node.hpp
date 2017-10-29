/*
 * simple_node.hpp
 *
 *  Created on: 16-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#ifndef BTREE_NODE_HPP_
#define BTREE_NODE_HPP_

#include "abstract_node.hpp"
#include <iostream>
#include <assert.h>
#include <pthread.h>
#include <boost/compressed_pair.hpp>

#include "btree_internal.h"

using namespace std;
using namespace boost;

namespace omds { namespace btree {

static bnodeid_t invalidEdgePtr = INVALID_BNODEID;

template< typename K, typename V >
class SimpleNode : public AbstractNode {
public:
    SimpleNode(bnodeid_t id, bool init_pers, bool init_trans) :
            AbstractNode(id, init_pers, init_trans) {
        this->set_node_type(BTREE_NODETYPE_SIMPLE);
    }

    virtual ~SimpleNode() {}

public:
#ifndef NDEBUG

    static void cast_and_print(AbstractNode *n) {
        // Not a great idea to downcast, but this is just for debugging
        if (n->is_leaf()) {
            SimpleNode< K, V > *leafn = static_cast<SimpleNode< K, V > *>(n);
            leafn->print();
        } else {
            SimpleNode< K, bnodeid_t > *intn = static_cast<SimpleNode< K, bnodeid_t > *>(n);
            intn->print();
        }
    }

#endif

    void get(int ind, BtreeValue *outval) const {
        // Need edge index
        if (ind == get_total_entries()) {
            assert(!is_leaf());

            assert(has_valid_edge());
            get_edge_value(outval);
        } else {
            get_nth_value(ind, outval, false /* no copy */);
        }
    }

    // Insert the key and value in provided index
    // Assumption: Node lock is already taken
    void insert(int ind, BtreeKey &key, BtreeValue &val) {
        //K& k = *(dynamic_cast<K *>(&key));
        //assert(get_total_entries() < getMaxEntries());
        uint32_t sz = (get_total_entries() - ind) * get_nth_obj_size(0);

        if (sz != 0) {
            memmove(get_nth_obj(ind + 1), get_nth_obj(ind), sz);
        }

        set_nth_obj(ind, key, val);
        inc_entries();
        inc_gen();

#ifndef NDEBUG
        //print();
#endif
    }

#ifndef NDEBUG

    void print() {
        cout << "###################" << endl;
        cout << "-------------------------------" << endl;
        cout << "id=" << get_node_id().m_x << " nEntries=" << get_total_entries()
             << " leaf?=" << is_leaf();

        if (!is_leaf()) {
            bnodeid_t edge_id;
            edge_id = get_edge_id();
            cout << " edge_id=" << edge_id.m_x;
        }
        cout << "\n";
        cout << "-------------------------------" << endl;
        for (uint32_t i = 0; i < get_total_entries(); i++) {
            cout << "Key=";
            K key;
            get_nth_key(i, &key, false);
            key.print();

            // TODO: Override the << in ostream for Value
            cout << " Val=";
            if (is_leaf()) {
                V val;
                get(i, &val);
                val.print();
            } else {
                BNodeptr p;
                get(i, &p);
                p.print();
            }
            cout << "\n";
        }
    }

#endif

    void remove(int ind) {
        uint32_t total_entries = get_total_entries();
        assert(total_entries >= ind);

        if (ind == total_entries) {
            assert(!is_leaf() && has_valid_edge());
            BNodeptr last_1_val;

            // Set the last key/value as edge entry and by decrementing entry count automatically removed the last entry.
            get_nth_value(total_entries - 1, &last_1_val, false);
            set_edge_value(last_1_val);
        } else {
            uint32_t sz = (total_entries - ind) * get_nth_obj_size(0);
            if (sz != 0) {
                memmove(get_nth_obj(ind), get_nth_obj(ind + 1), sz);
            }
        }
        inc_gen();
        dec_entries();
    }

    void update(int ind, BtreeValue &val) {
        if (ind == get_total_entries()) {
            assert(!is_leaf());
            set_edge_value(val);
        } else {
            set_nth_value(ind, val);
        }

        // TODO: Check if we need to upgrade the gen and impact of doing  so with performance. It is especially
        // needed for non similar key/value pairs
        inc_gen();
    }

    void update(int ind, BtreeKey &key, BtreeValue &val) {
        if (ind == get_total_entries()) {
            assert(!is_leaf());
            set_edge_value(val);
        } else {
            set_nth_obj(ind, key, val);
        }

        inc_gen();
    }

    void move_out_right(AbstractNode &othern, uint32_t nentries) {
        SimpleNode< K, V > *other_node = (SimpleNode< K, V > *) &othern;
        uint32_t sz = nentries * get_nth_obj_size(0);

        if (sz != 0) {
            uint32_t othersz = other_node->get_total_entries() * other_node->get_nth_obj_size(0);
            memmove(other_node->get_nth_obj(nentries), other_node->get_nth_obj(0), othersz);
            memmove(other_node->get_nth_obj(0), get_nth_obj(get_total_entries() - nentries), sz);
        }

        other_node->add_entries(nentries);
        sub_entries(nentries);

        // If there is an edgeEntry in this node, it needs to move to move out as well.
        if (!is_leaf() && has_valid_edge()) {
            bnodeid_t edge_value = get_edge_id();
            other_node->set_edge_id(edge_value);
            invalidate_edge();
        }

        other_node->inc_gen();
        inc_gen();
    }

    void move_in_right(AbstractNode &on, uint32_t nentries) {
        SimpleNode< K, V > *other_node = (SimpleNode< K, V > *) &on;
        uint32_t sz = nentries * get_nth_obj_size(0);

        if (sz != 0) {
            uint32_t othersz = (other_node->get_total_entries() - nentries) * other_node->get_nth_obj_size(0);
            memmove(get_nth_obj(get_total_entries()), other_node->get_nth_obj(0), sz);
            memmove(other_node->get_nth_obj(0), other_node->get_nth_obj(nentries), othersz);
        }

        other_node->sub_entries(nentries);
        this->add_entries(nentries);

        // If next node does not have any more entries, but only a edge entry
        // we need to move that to us, so that if need be next node could be freed.
        if ((other_node->get_total_entries() == 0) && other_node->has_valid_edge()) {
            assert(!has_valid_edge());

            set_edge_id(other_node->get_edge_id());
            other_node->invalidate_edge();
        }

        other_node->inc_gen();
        inc_gen();
    }

    bool is_split_needed(BtreeConfig &cfg, BtreeKey &key, BtreeValue &value, int *out_ind_hint) const {
        V curval;
        int size_needed;

        bool found = find(key, nullptr, &curval, out_ind_hint);
        if (found) {
            return false;
        }
        return (get_total_entries() == get_max_entries(cfg));
    }

    void get_adjacent_indicies(uint32_t cur_ind, vector< int > &indices_list, uint32_t max_indices) const {
        int i = 0;
        int start_ind;
        int end_ind;
        uint32_t nentries = get_total_entries();

        start_ind = cur_ind - ((max_indices / 2) - 1 + (max_indices % 2));
        end_ind = cur_ind + (max_indices / 2);
        if (start_ind < 0) {
            end_ind -= start_ind;
            start_ind = 0;
        }

        for (i = start_ind; (i <= end_ind) && (indices_list.size() < max_indices); i++) {
            if (i == nentries) {
                if (has_valid_edge()) {
                    indices_list.push_back(i);
                }
                break;
            } else {
                indices_list.push_back(i);
            }
        }
    }

private:
    ////////// Overridden private methods //////////////
    inline uint32_t get_nth_obj_size(int ind) const {
        return (get_obj_key_size(ind) + get_obj_value_size(ind));
    }

    void set_nth_obj(int ind, BtreeKey &k, BtreeValue &v) {
        assert(ind <= get_total_entries());

        uint8_t *entry = get_node_space() + (get_nth_obj_size(ind) * ind);
        uint32_t key_size;
        uint32_t val_size;
        void *blob = k.get_blob(&key_size);
        memcpy((void *) entry, blob, key_size);

        blob = v.get_blob(&val_size);
        memcpy((void *) (entry + key_size), blob, val_size);
    }

    void get_nth_key(int ind, BtreeKey *outkey, bool copykey) const {
        assert(ind < get_total_entries());

        const uint8_t *blob = get_node_space_const() + (get_nth_obj_size(ind) * ind);
        uint32_t key_size = get_obj_key_size(ind);
        if (copykey) {
            outkey->copy_blob(blob, key_size);
        } else {
            outkey->set_blob(blob, key_size);
        }
    }

    void get_nth_value(int ind, BtreeValue *outval, bool copy) const {
        assert(ind < get_total_entries());
        uint32_t keySize = get_obj_key_size(ind);
        uint32_t size = get_nth_obj_size(ind);

        const uint8_t *blob = get_node_space_const() + (size * ind) + keySize;
        if (copy) {
            outval->copy_blob(blob, outval->get_blob_size());
        } else {
            outval->set_blob(blob, outval->get_blob_size());
        }
    }

    int compare_nth_key(BtreeKey &cmp_key, int ind) const {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare(&cmp_key);
    }

    /////////////// Other Internal Methods /////////////
    inline uint32_t get_obj_key_size(int ind) const {
        return K::get_fixed_size();
    }

    inline uint32_t get_obj_value_size(int ind) const {
        if (is_leaf()) {
            return V::get_fixed_size();
        } else {
            return BNodeptr::get_fixed_size();
        }
    }

    uint8_t *get_nth_obj(int ind) {
        return (get_node_space() + (get_nth_obj_size(ind) * ind));
    }

    void set_nth_key(int ind, BtreeKey &k) {
        uint8_t *entry = get_node_space() + (get_nth_obj_size(ind) * ind);
        uint32_t keySize;

        uint8_t *blob = k.get_blob(&keySize);
        memcpy((void *) entry, (void *) blob, keySize);
    }

    void set_nth_value(int ind, BtreeValue &v) {
        assert(ind < get_total_entries());
        uint8_t *entry = get_node_space() + (get_nth_obj_size(ind) * ind) + get_obj_key_size(ind);
        uint32_t valSize;

        void *blob = v.get_blob(&valSize);
        memcpy((void *) entry, blob, valSize);
    }
};
} }
#endif
