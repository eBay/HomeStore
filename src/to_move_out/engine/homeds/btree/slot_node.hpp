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

#include "physical_node.hpp"
#include <cassert>
#include "btree_internal.h"

using namespace std;
using namespace boost;

namespace homeds {
namespace btree {

#define SlotNode VariantNode< btree_node_type::SLOT, K, V >

#pragma pack(1)
struct slot_key_size_type {
    uint16_t m_key_len : 14;
    uint16_t reserved : 2;
};

struct slot_value_size_type {
    uint16_t m_value_len : 14;
    uint16_t reserved : 2;
};

template < typename K, std::enable_if_t< K::is_fixed_size() > >
struct record_slot_key_size_type {};

template < typename K, std::enable_if_t< !K::is_fixed_size() > >
struct record_slot_key_size_type : public slot_key_size_type {};

template < typename V, std::enable_if_t< V::is_fixed_size() > >
struct record_slot_value_size_type {};

template < typename V, std::enable_if_t< !V::is_fixed_size() > >
struct record_slot_value_size_type : public slot_value_size_type {};

template < typename K, typename V >
struct slot_record {
    uint8_t data_at_slot;
    record_slot_key_size_type m_key_size; // These are optional fields in case of non fixed size
    record_slot_value_size_type m_value_size;
};

typedef slot_t uint8_t;
typedef sisl::Bitword< unsafe_bits< uint64_t > > slot_bitword_t;

template < typename K, typename V >
struct slot_info_header {
    slot_t m_max_slots{0};
    slot_t m_filled_slots{0};
    uint16_t m_reserved1[2];
    slot_key_size_type m_fixed_key_size;
    slot_value_size_type m_fixed_value_size;

    // Followed by array of slot_locators equivalent to
    // std::array< slot_record, max_slots >
    //
    // Followed by bitmap area equivalent to
    // std::array< bitword, max_slots/8 >
    //
};
#pragma pack()

template < typename K, typename V >
class SlotNode : public PhysicalNode< SlotNode, K, V > {
public:
    SlotNode(bnodeid_t id, bool init, const BtreeConfig& cfg) : PhysicalNode< SlotNode, K, V >(id, init) {
        this->set_node_type(btree_node_type::SLOT);

        slot_info_header* shdr = reinterpret_cast< slot_info_header* >(this->get_node_area());
        shdr->m_max_slots = cfg.get_max_slots();
        if (K::is_fixed_size()) { shdr->m_fixed_key_size = K::get_fixed_size(); }
        if (V::is_fixed_size()) { shdr->m_fixed_value_size = V::get_fixed_size(); }
    }
    SlotNode(bnodeid_t* id, bool init, const BtreeConfig& cfg) : SlotNode(*id, init, cfg) {}

private:
    const slot_info_header* slot_header() const {
        return reinterpret_cast< const slot_info_header* >(this->get_node_area());
    }
    slot_t get_max_slots() const { return slot_header()->max_slots; }
    slot_bitword_t* slot_bitmap_area() {
        return reinterpret_cast< slot_bitword_t* >(this->get_node_area() + sizeof(slot_info_header) +
                                                   (sizeof(slot_record) * get_max_slots()));
    }
    slot_t num_bitmap_words() const { return ((get_max_slots() - 1) / sizeof(uint64_t) / 8) + 1; }

    uint8_t alloc_slots(const uint32_t size) {
        const slot_t needed_slots = (slot_t)((size - 1) / BtreeConfig::slot_size) + 1;
        const slot_t cur_slot{0};
        slot_t residue_bits{0};
        bool alloced{false};

        auto* bitword = slot_bitmap_area();
        for (auto i = 0; i < num_bitmap_words(); ++i) {
            const auto [bit_num, leading_0s, trailing_0s] = bitword->get_first_contiguous_reset_bits(needed_slots);
            if (bit_num < slot_bitword_t::bits()) {
                alloced = true;
                cur_slot += bit_num;
                break;
            } else if ((residue_bits + leading_0s) >= needed_slots) {
                alloced = true;
                break;
            } else if (trailing_0s) {
                cur_slot
            } else {
                cur_slot += slot_bitword_t::bits();
            }
            ++bitword;
        }

        if (alloced == false) { std::throw(); }
        return start_slot;
    }

public:
#ifndef NDEBUG
    void validate_sanity() {
        int i = 0;
        std::map< int, bool > mapOfWords;
        // validate if keys are in ascending orde
        K prevKey;
        while (i < (int)this->get_total_entries()) {
            K key;
            get_nth_key(i, &key, false);
            uint64_t kp = *(uint64_t*)key.get_blob().bytes;
            if (i > 0 && prevKey.compare(&key) > 0) {
                LOGDEBUG("non sorted entry : {} -> {} ", kp, this->to_string());
                assert(false);
            }
            ++i;
            prevKey = key;
        }
    }
#endif

    void get(uint32_t ind, BtreeValue* outval, bool copy) const {
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
    btree_status_t insert(uint32_t ind, const BtreeKey& key, const BtreeValue& val) {
        // K& k = *(dynamic_cast<K *>(&key));
        // assert(get_total_entries() < getMaxEntries());
        uint32_t sz = (this->get_total_entries() - (ind + 1) + 1) * get_nth_obj_size(0);

        if (sz != 0) { memmove(get_nth_obj(ind + 1), get_nth_obj(ind), sz); }

        set_nth_obj(ind, key, val);
        this->inc_entries();
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
        return btree_status_t::success;
    }

    std::string to_string(bool print_friendly = false) const {
        auto str = fmt::format(
            "{}id={} nEntries={} {} ",
            (print_friendly ? "---------------------------------------------------------------------\n" : ""),
            this->get_node_id(), this->get_total_entries(), (this->is_leaf() ? "LEAF" : "INTERIOR"));
        if (!this->is_leaf() && (this->has_valid_edge())) {
            fmt::format_to(std::back_inserter(str), "edge_id={} ", this->get_edge_id());
        }
        for (uint32_t i{0}; i < this->get_total_entries(); ++i) {
            K key;
            get_nth_key(i, &key, false);
            fmt::format_to(std::back_inserter(str), "{}Entry{} [Key={}", (print_friendly ? "\n\t" : " "), i + 1,
                           key.to_string());

            if (this->is_leaf()) {
                V val;
                get(i, &val, false);
                fmt::format_to(std::back_inserter(str), " Val={}]", val.to_string());
            } else {
                BtreeNodeInfo p;
                get(i, &p, false);
                fmt::format_to(std::back_inserter(str), " Val={}]", p.to_string());
            }
        }
        return str;
    }

    void remove(int ind) { remove(ind, ind); }

    // ind_s and ind_e are inclusive
    void remove(int ind_s, int ind_e) {
        int total_entries = this->get_total_entries();
        assert(total_entries >= ind_s);
        assert(total_entries >= ind_e);

        if (ind_e == total_entries) { // edge entry
            assert(!this->is_leaf() && this->has_valid_edge());
            BtreeNodeInfo last_1_val;

            // Set the last key/value as edge entry and by decrementing entry count automatically removed the last
            // entry.
            get_nth_value(ind_s - 1, &last_1_val, false);
            this->set_edge_value(last_1_val);
            this->sub_entries(total_entries - ind_s + 1);
        } else {
            uint32_t sz = (total_entries - ind_e - 1) * get_nth_obj_size(0);

            if (sz != 0) { memmove(get_nth_obj(ind_s), get_nth_obj(ind_e + 1), sz); }
            this->sub_entries(ind_e - ind_s + 1);
        }
        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
    }

    void update(uint32_t ind, const BtreeValue& val) {
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

    void update(uint32_t ind, const BtreeKey& key, const BtreeValue& val) {
        if (ind == this->get_total_entries()) {
            assert(!this->is_leaf());
            this->set_edge_value(val);
        } else {
            set_nth_obj(ind, key, val);
        }

        this->inc_gen();
    }

    uint32_t get_available_size(const BtreeConfig& cfg) const {
        return (cfg.get_node_area_size() - (this->get_total_entries() * get_nth_obj_size(0)));
    }

    uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, SimpleNode* other_node, uint32_t nentries) {

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

    uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, SimpleNode* other_node, uint32_t size) {
        return (get_nth_obj_size(0) * move_out_to_right_by_entries(cfg, other_node, size / get_nth_obj_size(0)));
    }

    uint32_t move_in_from_right_by_entries(const BtreeConfig& cfg, SimpleNode* other_node, uint32_t nentries) {
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

    uint32_t move_in_from_right_by_size(const BtreeConfig& cfg, SimpleNode* other_node, uint32_t size) {
        return (get_nth_obj_size(0) * move_in_from_right_by_entries(cfg, other_node, size / get_nth_obj_size(0)));
    }

    bool is_split_needed(const BtreeConfig& cfg, const BtreeKey& key, const BtreeValue& value, int* out_ind_hint,
                         btree_put_type& putType, BtreeUpdateRequest< K, V >* bur = nullptr) const {
        // TODO - add support for callback based internal/leaf nodes
        uint32_t alreadyFilledSize = cfg.get_node_area_size() - get_available_size(cfg);

        // TODO - we should have sperate ideal fill/merge size configurations for internal nodes and leaf node
        return alreadyFilledSize + key.get_blob_size() + value.get_blob_size() >= cfg.get_ideal_fill_size();
    }

    ////////// Overridden private methods //////////////
    inline uint32_t get_nth_obj_size(uint32_t ind) const { return (get_obj_key_size(ind) + get_obj_value_size(ind)); }

    void get_nth_key(uint32_t ind, BtreeKey* outkey, bool copykey) const {
        assert(ind < this->get_total_entries());

        sisl::blob b;
        b.bytes = (uint8_t*)(this->get_node_area() + (get_nth_obj_size(ind) * ind));
        b.size = get_obj_key_size(ind);

        (copykey) ? outkey->copy_blob(b) : outkey->set_blob(b);
    }

    void get_nth_value(uint32_t ind, BtreeValue* outval, bool copy) const {
        assert(ind < this->get_total_entries());

        sisl::blob b;
        b.bytes = (uint8_t*)(this->get_node_area() + (get_nth_obj_size(ind) * ind)) + get_obj_key_size(ind);
        b.size = outval->get_blob_size();

        (copy) ? outval->copy_blob(b) : outval->set_blob(b);
    }

    int compare_nth_key(const BtreeKey& cmp_key, int ind) const {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare(&cmp_key);
    }

    int compare_nth_key_range(const BtreeSearchRange& range, int ind) const {
        K nth_key;
        get_nth_key(ind, &nth_key, false /* copyKey */);
        return nth_key.compare_range(range);
    }

    void get_all_kvs(std::vector< pair< K, V > >* kvs) const {
        LOGERROR("Not implemented");
        return;
    }

    /////////////// Other Internal Methods /////////////
    void set_nth_obj(uint32_t ind, const BtreeKey& k, const BtreeValue& v) {
        assert(ind <= this->get_total_entries());

        uint8_t* entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind);
        sisl::blob key_blob = k.get_blob();
        memcpy((void*)entry, key_blob.bytes, key_blob.size);

        sisl::blob val_blob = v.get_blob();
        memcpy((void*)(entry + key_blob.size), val_blob.bytes, val_blob.size);
    }

    uint32_t get_available_entries(const BtreeConfig& cfg) const {
        return get_available_size(cfg) / get_nth_obj_size(0);
    }

    inline uint32_t get_obj_key_size(uint32_t ind) const { return K::get_fixed_size(); }

    inline uint32_t get_obj_value_size(uint32_t ind) const {
        if (this->is_leaf()) {
            return V::get_fixed_size();
        } else {
            return BtreeNodeInfo::get_fixed_size();
        }
    }

    uint8_t* get_nth_obj(uint32_t ind) { return (this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind)); }

    void set_nth_key(uint32_t ind, BtreeKey* key) {
        uint8_t* entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind);

        sisl::blob b = key->get_blob();
        memcpy((void*)entry, (void*)b.bytes, b.size);
    }

    void set_nth_value(uint32_t ind, const BtreeValue& v) {
        assert(ind < this->get_total_entries());
        uint8_t* entry = this->get_node_area_mutable() + (get_nth_obj_size(ind) * ind) + get_obj_key_size(ind);

        sisl::blob b = v.get_blob();
        memcpy((void*)entry, b.bytes, b.size);
    }
};
} // namespace btree
} // namespace homeds
