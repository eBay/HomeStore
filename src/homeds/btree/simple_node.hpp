/*
 * simple_node.hpp
 *
 *  Created on: 16-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include "physical_node.hpp"
#include <iostream>
#include <cassert>
#include <pthread.h>
#include <boost/compressed_pair.hpp>
#include "btree_internal.h"

using namespace std;
using namespace boost;

namespace homeds { namespace btree {

#define SimpleNode              VariantNode<btree_node_type::SIMPLE, K, V, NodeSize>

template< typename K, typename V, size_t NodeSize >
class SimpleNode : public PhysicalNode<SimpleNode, K, V, NodeSize> {
public:
    SimpleNode(bnodeid_t id, bool init,const BtreeConfig &cfg) :
            PhysicalNode<SimpleNode, K, V, NodeSize>(id, init) {
        this->set_node_type(btree_node_type::SIMPLE);
    }
    SimpleNode(bnodeid_t* id, bool init,const BtreeConfig &cfg) :
            PhysicalNode<SimpleNode, K, V, NodeSize>(id, init) {
        this->set_node_type(btree_node_type::SIMPLE);
    }
public:

#ifndef NDEBUG
    void validate_sanity() {
        int i = 1;
        std::map<int, bool> mapOfWords;
        //validate if keys are in ascending orde
        K prevKey;
        while (i < (int)this->get_total_entries()) {
            K key;
            get_nth_key(i,&key,false);
            uint64_t kp = *(uint64_t*)key.get_blob().bytes;
            if (i > 0 && prevKey.compare(&key) > 0) {
                LOGDEBUG("non sorted entry : {} -> {} ", kp, this->to_string());
                assert(0);
            }
            ++i;
            prevKey = key;
        }
    } 
#endif

    void get(uint32_t ind, BtreeValue *outval, bool copy) const {
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
    void insert(uint32_t ind, const BtreeKey &key, const BtreeValue &val) {
        //K& k = *(dynamic_cast<K *>(&key));
        //assert(get_total_entries() < getMaxEntries());
        uint32_t sz = (this->get_total_entries() - (ind + 1) + 1) * get_nth_obj_size(0);

        if (sz != 0) {
            memmove(get_nth_obj(ind + 1), get_nth_obj(ind), sz);
        }

        set_nth_obj(ind, key, val);
        this->inc_entries();
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
    }

    std::string to_string() const {
        std::stringstream ss;
        ss << "###################" << endl;
        ss << "-------------------------------" << endl;
        ss << "id=" << this->get_node_id().to_string() << " nEntries=" << this->get_total_entries() << " leaf?=" << this->is_leaf();

        if (!this->is_leaf()) {
            bnodeid_t edge_id;
            edge_id = this->get_edge_id();
            ss << " edge_id=" << static_cast<uint64_t>(edge_id.m_id);
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
                BtreeNodeInfo bni;
                get(i, &bni, false);
                ss << bni;
            }
            ss << "\n";
        }
        return ss.str();
    }

    void remove(int ind) {
        remove(ind,ind);
    }

    //ind_s and ind_e are inclusive
    void remove(int ind_s,int ind_e)  {
        int total_entries = this->get_total_entries();
        assert(total_entries >= ind_s);
        assert(total_entries >=ind_e);

        if (ind_e == total_entries) { //edge entry
            assert(!this->is_leaf() && this->has_valid_edge());
            BtreeNodeInfo last_1_val;

            // Set the last key/value as edge entry and by decrementing entry count automatically removed the last entry.
            get_nth_value(ind_s - 1, &last_1_val, false);
            this->set_edge_value(last_1_val);
            this->sub_entries(total_entries-ind_s+1);
        } else {
            uint32_t sz = (total_entries - ind_e -1) * get_nth_obj_size(0);

            if (sz != 0) {
                memmove(get_nth_obj(ind_s), get_nth_obj(ind_e + 1), sz);
            }
            this->sub_entries(ind_e-ind_s+1);
        }
        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
        
    }

    void update(uint32_t ind, const BtreeValue &val) {
        if (ind == this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
        } else {
            set_nth_value(ind, val);
        }

        // TODO: Check if we need to upgrade the gen and impact of doing  so with performance. It is especially
        // needed for non similar key/value pairs
        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
    }

    void update(uint32_t ind, const BtreeKey &key, const BtreeValue &val) {
        if (ind == this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
        } else {
            set_nth_obj(ind, key, val);
        }

        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
    }

    uint32_t get_available_size(const BtreeConfig &cfg) const {
        return (cfg.get_node_area_size() - (this->get_total_entries() * get_nth_obj_size(0)));
    }

    uint32_t move_out_to_right_by_entries(const BtreeConfig &cfg, SimpleNode *other_node,
                                          uint32_t nentries) {

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

#ifndef NDEBUG
        validate_sanity();
#endif
        return nentries;
    }

    uint32_t move_out_to_right_by_size(const BtreeConfig &cfg, SimpleNode *other_node, uint32_t size) {
        return (get_nth_obj_size(0) * move_out_to_right_by_entries(cfg, other_node, size/get_nth_obj_size(0)));
    }

    uint32_t move_in_from_right_by_entries(const BtreeConfig &cfg, SimpleNode *other_node, uint32_t nentries) {
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

#ifndef NDEBUG
        validate_sanity();
#endif
        return nentries;
    }

    uint32_t move_in_from_right_by_size(const BtreeConfig &cfg, SimpleNode *other_node, uint32_t size) {
        return (get_nth_obj_size(0) * move_in_from_right_by_entries(cfg, other_node, size/get_nth_obj_size(0)));
    }
    
    bool is_split_needed(const BtreeConfig &cfg, const BtreeKey &key, const BtreeValue &value,
                         int *out_ind_hint, btree_put_type &putType, BtreeUpdateRequest<K,V> *bur = nullptr) const {
        // TODO - add support for callback based internal/leaf nodes
        uint32_t alreadyFilledSize = cfg.get_node_area_size() - get_available_size(cfg);

        // TODO - we should have sperate ideal fill/merge size configurations for internal nodes and leaf node
        return alreadyFilledSize + key.get_blob_size() + value.get_blob_size() >= cfg.get_ideal_fill_size();
    }

    ////////// Overridden private methods //////////////
    inline uint32_t get_nth_obj_size(uint32_t ind) const {
        return (get_obj_key_size(ind) + get_obj_value_size(ind));
    }

    void get_nth_key(uint32_t ind, BtreeKey *outkey, bool copykey) const {
        assert(ind < this->get_total_entries());

        homeds::blob b;
        b.bytes = (uint8_t *)(this->get_node_area() + (get_nth_obj_size(ind) * ind));
        b.size  = get_obj_key_size(ind);

        (copykey) ? outkey->copy_blob(b) : outkey->set_blob(b);
    }

    void get_nth_value(uint32_t ind, BtreeValue *outval, bool copy) const {
        assert(ind < this->get_total_entries());

        homeds::blob b;
        b.bytes = (uint8_t *)(this->get_node_area() + (get_nth_obj_size(ind) * ind)) + get_obj_key_size(ind);
        b.size = outval->get_blob_size();

        (copy) ? outval->copy_blob(b) : outval->set_blob(b);
    }

    int compare_nth_key(const BtreeKey &cmp_key, int ind) const {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare(&cmp_key);
    }

    int compare_nth_key_range(const BtreeSearchRange &range, int ind) const {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare_range(range);
    }

    /////////////// Other Internal Methods /////////////
    void set_nth_obj(uint32_t ind, const BtreeKey &k, const BtreeValue &v) {
        assert(ind <= this->get_total_entries());

        uint8_t *entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind);
        homeds::blob key_blob = k.get_blob();
        memcpy((void *) entry, key_blob.bytes, key_blob.size);

        homeds::blob val_blob = v.get_blob();
        memcpy((void *) (entry + key_blob.size), val_blob.bytes, val_blob.size);
    }

    uint32_t get_available_entries(const BtreeConfig &cfg) const {
        return get_available_size(cfg)/get_nth_obj_size(0);
    }

    inline uint32_t get_obj_key_size(uint32_t ind) const {
        return K::get_fixed_size();
    }

    inline uint32_t get_obj_value_size(uint32_t ind) const {
        if (this->is_leaf()) {
            return V::get_fixed_size();
        } else {
            return BtreeNodeInfo::get_fixed_size();
        }
    }

    uint8_t *get_nth_obj(uint32_t ind) {
        return (this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind));
    }

    void set_nth_key(uint32_t ind, BtreeKey *key) {
        uint8_t *entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind);

        homeds::blob b = key->get_blob();
        memcpy((void *) entry, (void *) b.bytes, b.size);
    }

    void set_nth_value(uint32_t ind, const BtreeValue &v) {
        assert(ind < this->get_total_entries());
        uint8_t *entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind) + get_obj_key_size(ind);

        homeds::blob b = v.get_blob();
        memcpy((void *) entry, b.bytes, b.size);
    }
};
} }
