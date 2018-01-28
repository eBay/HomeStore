/*
 * simple_node.hpp
 *
 *  Created on: 16-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include "abstract_node.hpp"
#include <iostream>
#include <cassert>
#include <pthread.h>
#include <boost/compressed_pair.hpp>

#include "btree_internal.h"

using namespace std;
using namespace boost;

namespace omds { namespace btree {

static bnodeid_t invalidEdgePtr = INVALID_BNODEID;

template< typename K, typename V, size_t NodeSize >
class SimpleNode : public AbstractNode<K, V, NodeSize> {
public:
    SimpleNode(bnodeid_t id, bool init_pers, bool init_trans) :
            AbstractNode<K, V, NodeSize>(id, init_pers, init_trans) {
        this->set_node_type(BTREE_NODETYPE_SIMPLE);
    }

    virtual ~SimpleNode() {}

public:
#ifndef NDEBUG

    static void cast_and_print(AbstractNode<K, V, NodeSize> *n) {
        // Not a great idea to downcast, but this is just for debugging
        if (n->is_leaf()) {
            SimpleNode< K, V, NodeSize > *leafn = static_cast<SimpleNode< K, V, NodeSize > *>(n);
            leafn->to_string();
        } else {
            SimpleNode< K, bnodeid_t, NodeSize > *intn = static_cast<SimpleNode< K, bnodeid_t, NodeSize > *>(n);
            intn->to_string();
        }
    }

#endif

    void get(int ind, BtreeValue *outval, bool copy) const override {
        // Need edge index
        if (ind == this->get_total_entries()) {
            assert(!this->is_leaf());

            assert(this->has_valid_edge());
            this->get_edge_value(outval);
        } else {
            this->get_nth_value(ind, outval, copy);
        }
    }

    // Insert the key and value in provided index
    // Assumption: Node lock is already taken
    void insert(int ind, const BtreeKey &key, const BtreeValue &val) override {
        //K& k = *(dynamic_cast<K *>(&key));
        //assert(get_total_entries() < getMaxEntries());
        uint32_t sz = (this->get_total_entries() - ind) * get_nth_obj_size(0);

        if (sz != 0) {
            memmove(get_nth_obj(ind + 1), get_nth_obj(ind), sz);
        }

        set_nth_obj(ind, key, val);
        this->inc_entries();
        this->inc_gen();

#ifndef NDEBUG
        //print();
#endif
    }

#ifndef NDEBUG

    std::string to_string() const override {
        std::stringstream ss;
        ss << "###################" << endl;
        ss << "-------------------------------" << endl;
        ss << "id=" << this->get_node_id().m_x << " nEntries=" << this->get_total_entries() << " leaf?=" << this->is_leaf();

        if (!this->is_leaf()) {
            bnodeid_t edge_id;
            edge_id = this->get_edge_id();
            ss << " edge_id=" << edge_id.m_x;
        }
        ss << "\n-------------------------------" << endl;
        for (uint32_t i = 0; i < this->get_total_entries(); i++) {
            ss << "Key=";
            K key;
            get_nth_key(i, &key, false);
            ss << key.to_string();

            // TODO: Override the << in ostream for Value
            ss << " Val=";
            if (this->is_leaf()) {
                V val;
                get(i, &val, false);
                ss << val.to_string();
            } else {
                BNodeptr p;
                get(i, &p, false);
                ss << p.to_string();
            }
            ss << "\n";
        }
        return ss.str();
    }

#endif

    void remove(int ind) override {
        uint32_t total_entries = this->get_total_entries();
        assert(total_entries >= ind);

        if (ind == total_entries) {
            assert(!this->is_leaf() && this->has_valid_edge());
            BNodeptr last_1_val;

            // Set the last key/value as edge entry and by decrementing entry count automatically removed the last entry.
            get_nth_value(total_entries - 1, &last_1_val, false);
            this->set_edge_value(last_1_val);
        } else {
            uint32_t sz = (total_entries - ind) * get_nth_obj_size(0);
            if (sz != 0) {
                memmove(get_nth_obj(ind), get_nth_obj(ind + 1), sz);
            }
        }
        this->inc_gen();
        this->dec_entries();
    }

    void update(int ind, const BtreeValue &val) override {
        if (ind == this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
        } else {
            set_nth_value(ind, val);
        }

        // TODO: Check if we need to upgrade the gen and impact of doing  so with performance. It is especially
        // needed for non similar key/value pairs
        this->inc_gen();
    }

    void update(int ind, const BtreeKey &key, const BtreeValue &val) override {
        if (ind == this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
        } else {
            set_nth_obj(ind, key, val);
        }

        this->inc_gen();
    }

    virtual uint32_t get_available_size(const BtreeConfig &cfg) const override {
        return (this->get_node_area_size(cfg) - (this->get_total_entries() * get_nth_obj_size(0)));
    }

    uint32_t move_out_to_right_by_entries(const BtreeConfig &cfg, AbstractNode<K, V, NodeSize> &othern,
                                          uint32_t nentries) override {
        auto other_node = (SimpleNode< K, V, NodeSize > *) &othern;

        // Minimum of whats to be moved out and how many slots available in other node
        nentries = std::min({nentries, this->get_total_entries(), other_node->get_available_entries(cfg)});

        uint32_t sz = nentries * get_nth_obj_size(0);

        if (sz != 0) {
            uint32_t othersz = other_node->get_total_entries() * other_node->get_nth_obj_size(0);
            memmove(other_node->get_nth_obj(nentries), other_node->get_nth_obj(0), othersz);
            memmove(other_node->get_nth_obj(0), get_nth_obj(this->get_total_entries() - nentries), sz);
        }

        other_node->add_entries(nentries);
        this->sub_entries(nentries);

        // If there is an edgeEntry in this node, it needs to move to move out as well.
        if (!this->is_leaf() && this->has_valid_edge()) {
            bnodeid_t edge_value = this->get_edge_id();
            other_node->set_edge_id(edge_value);
            this->invalidate_edge();
        }

        other_node->inc_gen();
        this->inc_gen();

        return nentries;
    }

    uint32_t move_out_to_right_by_size(const BtreeConfig &cfg, AbstractNode<K, V, NodeSize> &other_node, uint32_t size) override {
        return (get_nth_obj_size(0) * move_out_to_right_by_entries(cfg, other_node, size/get_nth_obj_size(0)));
    }

    uint32_t move_in_from_right_by_entries(const BtreeConfig &cfg, AbstractNode<K, V, NodeSize> &on, uint32_t nentries) override {
        auto other_node = (SimpleNode< K, V, NodeSize > *) &on;

        // Minimum of whats to be moved and how many slots available
        nentries = std::min({nentries, other_node->get_total_entries(), get_available_entries(cfg)});
        uint32_t sz = nentries * get_nth_obj_size(0);
        if (sz != 0) {
            uint32_t othersz = (other_node->get_total_entries() - nentries) * other_node->get_nth_obj_size(0);
            memmove(get_nth_obj(this->get_total_entries()), other_node->get_nth_obj(0), sz);
            memmove(other_node->get_nth_obj(0), other_node->get_nth_obj(nentries), othersz);
        }

        other_node->sub_entries(nentries);
        this->add_entries(nentries);

        // If next node does not have any more entries, but only a edge entry
        // we need to move that to us, so that if need be next node could be freed.
        if ((other_node->get_total_entries() == 0) && other_node->has_valid_edge()) {
            assert(!this->has_valid_edge());

            this->set_edge_id(other_node->get_edge_id());
            other_node->invalidate_edge();
        }

        other_node->inc_gen();
        this->inc_gen();

        return nentries;
    }

    uint32_t move_in_from_right_by_size(const BtreeConfig &cfg, AbstractNode<K, V, NodeSize> &other_node, uint32_t size) override {
        return (get_nth_obj_size(0) * move_in_from_right_by_entries(cfg, other_node, size/get_nth_obj_size(0)));
    }

    bool is_split_needed(const BtreeConfig &cfg, const BtreeKey &key, const BtreeValue &value,
                         int *out_ind_hint) const override {
        int size_needed;

        auto result = this->find(BtreeSearchRange(key), nullptr, nullptr);
        *out_ind_hint = result.end_of_search_index;
        if (result.found) {
            return false;
        }

        return (this->get_available_entries(cfg) == 0);
    }

private:
    ////////// Overridden private methods //////////////
    inline uint32_t get_nth_obj_size(int ind) const override {
        return (get_obj_key_size(ind) + get_obj_value_size(ind));
    }

    void get_nth_key(int ind, BtreeKey *outkey, bool copykey) const override {
        assert(ind < this->get_total_entries());

        omds::blob b;
        b.bytes = (uint8_t *)(this->get_node_area() + (get_nth_obj_size(ind) * ind));
        b.size  = get_obj_key_size(ind);

        (copykey) ? outkey->copy_blob(b) : outkey->set_blob(b);
    }

    void get_nth_value(int ind, BtreeValue *outval, bool copy) const override {
        assert(ind < this->get_total_entries());
        uint32_t size = get_nth_obj_size(ind);

        omds::blob b;
        b.bytes = (uint8_t *)(this->get_node_area() + (get_nth_obj_size(ind) * ind)) + get_obj_key_size(ind);
        b.size = outval->get_blob_size();

        (copy) ? outval->copy_blob(b) : outval->set_blob(b);
    }

    int compare_nth_key(const BtreeKey &cmp_key, int ind) const override {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare(&cmp_key);
    }

    /////////////// Other Internal Methods /////////////
    void set_nth_obj(int ind, const BtreeKey &k, const BtreeValue &v) {
        assert(ind <= this->get_total_entries());

        uint8_t *entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind);
        omds::blob key_blob = k.get_blob();
        memcpy((void *) entry, key_blob.bytes, key_blob.size);

        omds::blob val_blob = v.get_blob();
        memcpy((void *) (entry + key_blob.size), val_blob.bytes, val_blob.size);
    }

    uint32_t get_available_entries(const BtreeConfig &cfg) const {
        return get_available_size(cfg)/get_nth_obj_size(0);
    }

    inline uint32_t get_obj_key_size(int ind) const {
        return K::get_fixed_size();
    }

    inline uint32_t get_obj_value_size(int ind) const {
        if (this->is_leaf()) {
            return V::get_fixed_size();
        } else {
            return BNodeptr::get_fixed_size();
        }
    }

    uint8_t *get_nth_obj(int ind) {
        return (this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind));
    }

    void set_nth_key(int ind, const BtreeKey &k) {
        uint8_t *entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind);
        uint32_t keySize;

        omds::blob b = k.get_blob();
        memcpy((void *) entry, (void *) b.bytes, b.size);
    }

    void set_nth_value(int ind, const BtreeValue &v) {
        assert(ind < this->get_total_entries());
        uint8_t *entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind) + get_obj_key_size(ind);
        uint32_t valSize;

        omds::blob b = v.get_blob();
        memcpy((void *) entry, b.bytes, b.size);
    }
};
} }
