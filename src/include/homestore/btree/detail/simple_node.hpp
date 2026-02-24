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

#include <homestore/btree/btree_kv.hpp>
#include <homestore/btree/detail/variant_node.hpp>
#include <homestore/btree/detail/btree_internal.hpp>
#include "homestore/index/index_internal.hpp"

using namespace std;
using namespace boost;

SISL_LOGGING_DECL(btree)

namespace homestore {

template < typename K, typename V >
class SimpleNode : public VariantNode< K, V > {
public:
    SimpleNode(uint8_t* node_buf, bnodeid_t id, bool init, bool is_leaf, const BtreeConfig& cfg) :
            VariantNode< K, V >(node_buf, id, init, is_leaf, cfg) {
        this->set_node_type(btree_node_type::FIXED);
    }

    using BtreeNode::get_nth_key;
    using BtreeNode::get_nth_key_internal;
    using BtreeNode::get_nth_key_size;
    using BtreeNode::get_nth_obj_size;
    using BtreeNode::get_nth_value;
    using BtreeNode::get_nth_value_size;
    using BtreeNode::to_string;
    using VariantNode< K, V >::get_nth_value;
    using VariantNode< K, V >::max_keys_in_node;

    // Insert the key and value in provided index
    // Assumption: Node lock is already taken
    btree_status_t insert(uint32_t ind, const BtreeKey& key, const BtreeValue& val) override {
        uint32_t sz = (this->total_entries() - (ind + 1) + 1) * get_nth_obj_size(0);

        if (sz != 0) { std::memmove(get_nth_obj(ind + 1), get_nth_obj(ind), sz); }
        this->set_nth_obj(ind, key, val);
        this->inc_entries();
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
        return btree_status_t::success;
    }

    void update(uint32_t ind, const BtreeValue& val) override {
        set_nth_value(ind, val);

        // TODO: Check if we need to upgrade the gen and impact of doing  so with performance. It is especially
        // needed for non similar key/value pairs
        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
    }

    void update(uint32_t ind, const BtreeKey& key, const BtreeValue& val) override {
        if (ind == this->total_entries()) {
            DEBUG_ASSERT_EQ(this->is_leaf(), false);
            this->set_edge_value(val);
        } else {
            set_nth_obj(ind, key, val);
        }
        this->inc_gen();
    }

    // ind_s and ind_e are inclusive
    void remove(uint32_t ind_s, uint32_t ind_e) override {
        uint32_t total_entries = this->total_entries();
        DEBUG_ASSERT_GE(total_entries, ind_s, "node={}", to_string());
        DEBUG_ASSERT_GE(total_entries, ind_e, "node={}", to_string());

        if (ind_e == total_entries) { // edge entry
            DEBUG_ASSERT((!this->is_leaf() && this->has_valid_edge()), "node={}", to_string());
            // Set the last key/value as edge entry and by decrementing entry count automatically removed the last
            // entry.
            BtreeLinkInfo new_edge;
            this->get_nth_value(ind_s - 1, &new_edge, false);
            this->set_nth_value(total_entries, new_edge);
            this->sub_entries(total_entries - ind_s + 1);
        } else {
            uint32_t sz = (total_entries - ind_e - 1) * get_nth_obj_size(0);

            if (sz != 0) { std::memmove(get_nth_obj(ind_s), get_nth_obj(ind_e + 1), sz); }
            this->sub_entries(ind_e - ind_s + 1);
        }
        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
    }

    void remove_all(const BtreeConfig&) override {
        this->sub_entries(this->total_entries());
        this->invalidate_edge();
        this->inc_gen();
#ifndef NDEBUG
        validate_sanity();
#endif
    }

    uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, BtreeNode& o, uint32_t nentries) override {
        auto& other_node = s_cast< SimpleNode< K, V >& >(o);

        // Minimum of whats to be moved out and how many slots available in other node
        nentries = std::min({nentries, this->total_entries(), other_node.get_available_entries()});
        uint32_t sz = nentries * get_nth_obj_size(0);

        if (sz != 0) {
            uint32_t othersz = other_node.total_entries() * other_node.get_nth_obj_size(0);
            std::memmove(other_node.get_nth_obj(nentries), other_node.get_nth_obj(0), othersz);
            std::memmove(other_node.get_nth_obj(0), get_nth_obj(this->total_entries() - nentries), sz);
        }

        other_node.add_entries(nentries);
        this->sub_entries(nentries);

        // If there is an edgeEntry in this node, it needs to move to move out as well.
        if (!this->is_leaf() && this->has_valid_edge()) {
            other_node.set_edge_info(this->edge_info());
            this->invalidate_edge();
        }

        other_node.inc_gen();
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
        return nentries;
    }

    uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, BtreeNode& o, uint32_t size) override {
        return (get_nth_obj_size(0) * move_out_to_right_by_entries(cfg, o, size / get_nth_obj_size(0)));
    }

    uint32_t num_entries_by_size(uint32_t start_idx, uint32_t size) const override {
        return std::min(size / get_nth_obj_size(0), this->total_entries() - start_idx);
    }

    uint32_t copy_by_size(const BtreeConfig& cfg, const BtreeNode& o, uint32_t start_idx, uint32_t size) override {
        auto& other = s_cast< const SimpleNode< K, V >& >(o);
        return copy_by_entries(cfg, o, start_idx, other.num_entries_by_size(start_idx, size));
    }

    uint32_t copy_by_entries(const BtreeConfig& cfg, const BtreeNode& o, uint32_t start_idx,
                             uint32_t nentries) override {
        auto& other = s_cast< const SimpleNode< K, V >& >(o);

        nentries = std::min(nentries, other.total_entries() - start_idx);
        nentries = std::min(nentries, this->get_available_entries());
#ifdef _PRERELEASE
        const uint64_t max_keys = this->max_keys_in_node();
        if (max_keys) {
            if (this->total_entries() + nentries > max_keys) { nentries = max_keys - this->total_entries(); }
        }
#endif
        uint32_t sz = nentries * get_nth_obj_size(0);
        if (sz != 0) { std::memcpy(get_nth_obj(this->total_entries()), other.get_nth_obj_const(start_idx), sz); }
        this->add_entries(nentries);
        this->inc_gen();

        // If we copied everything from start_idx till end and if its an edge node, need to copy the edge id as well.
        if (other.has_valid_edge() && ((start_idx + nentries) == other.total_entries())) {
            this->set_edge_info(other.edge_info());
        }
        return nentries;
    }

    uint32_t available_size() const override {
        return (this->node_data_size() - (this->total_entries() * get_nth_obj_size(0)));
    }

    void get_nth_key_internal(uint32_t ind, BtreeKey& out_key, bool copy) const override {
        DEBUG_ASSERT_LT(ind, this->total_entries(), "node={}", to_string());
        sisl::blob b{this->node_data_area_const() + (get_nth_obj_size(ind) * ind), get_nth_key_size(ind)};
        out_key.deserialize(b, copy);
    }

    void get_nth_value(uint32_t ind, BtreeValue* out_val, bool copy) const override {
        if (ind == this->total_entries()) {
            DEBUG_ASSERT_EQ(this->is_leaf(), false, "setting value outside bounds on leaf node");
            DEBUG_ASSERT_EQ(this->has_valid_edge(), true, "node={}", to_string());
            *(BtreeLinkInfo*)out_val = this->get_edge_value();
        } else {
            sisl::blob b{const_cast< uint8_t* >(this->node_data_area_const() + (get_nth_obj_size(ind) * ind) +
                                                get_nth_key_size(ind)),
                         dummy_value< V >.serialized_size()};
            out_val->deserialize(b, copy);
        }
    }

    bool has_room_for_put(btree_put_type put_type, uint32_t key_size, uint32_t value_size) const override {
#ifdef _PRERELEASE
        auto max_keys = max_keys_in_node();
        if (max_keys) { return (this->total_entries() < max_keys); }
#endif
        return ((put_type == btree_put_type::UPSERT) || (put_type == btree_put_type::INSERT))
            ? (get_available_entries() > 0)
            : true;
    }

    std::string to_string(bool print_friendly = false) const override {
        auto snext = this->next_bnode() == empty_bnodeid ? "" : fmt::format("next_node={}", this->next_bnode());
        auto str =
            fmt::format("{}id={} level={} nEntries={} last_cp={} {} {} {}",
                        (print_friendly ? "------------------------------------------------------------\n" : ""),
                        this->node_id(), this->level(), this->total_entries(), this->get_persistent_header_const()->modified_cp_id ,(this->is_leaf() ? "LEAF" : "INTERIOR"),
                        snext, this->is_node_deleted() ? "  Deleted" : " LIVE");
        if (this->has_valid_edge()) {
            fmt::format_to(std::back_inserter(str), " edge={}.{}", this->edge_info().m_bnodeid,
                           this->edge_info().m_link_version);
        }

        for (uint32_t i{0}; i < this->total_entries(); ++i) {
            fmt::format_to(std::back_inserter(str), "{}Entry{} [Key={} Val={}]", (print_friendly ? "\n\t" : " "), i + 1,
                           BtreeNode::get_nth_key< K >(i, false).to_string(),
                           this->get_nth_value(i, false).to_string());
        }
        return str;
    }
    std::string to_dot_keys() const override {
        return to_dot_keys_impl(std::is_same< decltype(std::declval< K& >().key()), uint64_t >{});
    }

    std::string to_dot_keys_impl(std::false_type) const { return ""; }

    std::string to_dot_keys_impl(std::true_type) const {
        std::string str;
        std::string snext = this->next_bnode() == empty_bnodeid ? "" : fmt::format("next_node={}", this->next_bnode());
        str += fmt::format(R"("{}" [
                shape = none,
                labelloc="c",
                fontsize=25,
                label = <<table border="1" cellborder="0" cellspacing="0">
                <tr>)",
                           this->node_id());
        if (this->total_entries() == 0) {
            return str + fmt::format(R"(
                <td port="connector0"></td><td port="key0">E</td>
                <td port="connector1"></td></tr></table>>])");
        }

        if (!this->is_leaf()) {
            //            str += " <tr>";
            for (uint32_t i{0}; i < this->total_entries(); ++i) {
                uint32_t cur_key = BtreeNode::get_nth_key< K >(i, false).key();
                BtreeLinkInfo child_info;
                get_nth_value(i, &child_info, false /* copy */);
                str += fmt::format(R"(
                <td port="connector{}"></td><td port="key{}">{}.{}</td>)",
                                   i, i, cur_key, child_info.link_version());
            }
            std::string sedge = this->has_valid_edge() ? "edge:" + std::to_string(this->edge_info().m_bnodeid) + "." +
                    std::to_string(this->edge_info().m_link_version)
                                                       : "";
            str += fmt::format(R"(
                <td port="connector{}"></td>
                <td>{}.{}<br/> gen={}<br/>{} {} </td></tr></table>>];)",
                               this->total_entries(), this->node_id(), this->link_version(), this->node_gen(), snext,
                               sedge);

        } else {
            std::string keys_buf = "";
            uint32_t prev_key = BtreeNode::get_nth_key< K >(0, false).key();
            uint32_t cur_key = prev_key;
            uint32_t last_key = BtreeNode::get_nth_key< K >(this->total_entries() - 1, false).key();
            if (last_key - prev_key == this->total_entries() - 1) {
                if (this->total_entries() == 1) {
                    keys_buf += fmt::format(R"(
                       <td port="connector{}"></td><td port="key{}">{}</td>)",
                                            0, 0, cur_key);
                } else {
                    keys_buf += fmt::format(R"(
                        <td port="connector{}"></td><td port="key{}">{}-{}</td>)",
                                            0, 0, prev_key, last_key);
                }
                keys_buf += fmt::format(R"(
                        <td port="connector{}"></td>
                        <td>{}.{}<br/>gen={}<br/> {}</td>
                        </tr></table>>];)",
                                        1, this->node_id(), this->link_version(), this->node_gen(), snext);
                return str + keys_buf;
            }

            keys_buf += fmt::format(R"(
                        "<td port="connector{}"></td><td port="key{}">{})",
                                    0, 0, prev_key);
            uint32_t start_interval_key = prev_key;
            for (uint32_t i{1}; i < this->total_entries(); ++i) {
                cur_key = BtreeNode::get_nth_key< K >(i, false).key();
                if (cur_key != prev_key + 1) {
                    if (start_interval_key == prev_key) {
                        keys_buf += fmt::format(" {}", cur_key);
                    } else {
                        keys_buf += fmt::format("-{} {}", prev_key, cur_key);
                    }
                    start_interval_key = cur_key;
                }
                prev_key = cur_key;
            }

            if (start_interval_key == prev_key) {
                keys_buf += fmt::format("</td>");
            } else {
                keys_buf += fmt::format(" {}</td>", cur_key);
            }
            keys_buf += fmt::format(R"(
                        <td port="connector{}"></td>
                        <td>{}.{}<br/>gen={} <br/>{}</td></tr></table>>];)",
                                    1, this->node_id(), this->link_version(), this->node_gen(), snext);
            return str + keys_buf;
        }
        return str;
    }

#ifndef NDEBUG
    void validate_sanity() {
        if (this->total_entries() == 0) { return; }

        // validate if keys are in ascending order
        uint32_t i{1};
        K prevKey = BtreeNode::get_nth_key< K >(0, false);

        while (i < this->total_entries()) {
            K key = BtreeNode::get_nth_key< K >(i, false);
            if (i > 0 && prevKey.compare(key) > 0) {
                LOGINFO("non sorted entry : {} -> {} ", prevKey.to_string(), key.to_string());
                DEBUG_ASSERT(false, "node={}", to_string());
            }
            ++i;
            prevKey = key;
        }
    }
#endif

    inline uint32_t get_nth_obj_size(uint32_t ind) const override {
        return (get_nth_key_size(ind) + get_nth_value_size(ind));
    }

    /*int compare_nth_key_range(const BtreeKeyRange& range, uint32_t ind) const override {
        return get_nth_key(ind, false).compare_range(range);
    }*/

    /////////////// Other Internal Methods /////////////
    void set_nth_obj(uint32_t ind, const BtreeKey& k, const BtreeValue& v) {
        if (ind > this->total_entries()) {
            set_nth_value(ind, v);
        } else {
            uint8_t* entry = this->node_data_area() + (get_nth_obj_size(ind) * ind);
            sisl::blob const key_blob = k.serialize();
            memcpy((void*)entry, key_blob.cbytes(), key_blob.size());

            sisl::blob const val_blob = v.serialize();
            memcpy((void*)(entry + key_blob.size()), val_blob.cbytes(), val_blob.size());
        }
    }

    uint32_t get_available_entries() const { return available_size() / get_nth_obj_size(0); }

    uint32_t get_nth_key_size(uint32_t ind) const override { return dummy_key< K >.serialized_size(); }

    uint32_t get_nth_value_size(uint32_t ind) const override { return dummy_value< V >.serialized_size(); }

    uint8_t* get_nth_obj(uint32_t ind) { return (this->node_data_area() + (get_nth_obj_size(ind) * ind)); }
    const uint8_t* get_nth_obj_const(uint32_t ind) const {
        return (this->node_data_area_const() + (get_nth_obj_size(ind) * ind));
    }

    void set_nth_key(uint32_t ind, const BtreeKey& key) {
        uint8_t* entry = this->node_data_area() + (get_nth_obj_size(ind) * ind);
        sisl::blob const b = key.serialize();
        memcpy(entry, b.cbytes(), b.size());
    }

    void set_nth_value(uint32_t ind, const BtreeValue& v) {
        sisl::blob b = v.serialize();
        if (ind >= this->total_entries()) {
            RELEASE_ASSERT_EQ(this->is_leaf(), false, "setting value outside bounds on leaf node");
            DEBUG_ASSERT_EQ(b.size(), sizeof(BtreeLinkInfo::bnode_link_info),
                            "Invalid value size being set for non-leaf node");
            this->set_edge_info(*r_cast< BtreeLinkInfo::bnode_link_info const* >(b.cbytes()));
        } else {
            uint8_t* entry = this->node_data_area() + (get_nth_obj_size(ind) * ind) + get_nth_key_size(ind);
            std::memcpy(entry, b.cbytes(), b.size());
        }
    }
};
} // namespace homestore
