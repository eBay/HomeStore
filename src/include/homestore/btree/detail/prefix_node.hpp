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

#include <sisl/fds/compact_bitset.hpp>
#include <sisl/logging/logging.h>
#include "btree_node.hpp"
#include <homestore/btree/btree_kv.hpp>
#include <homestore/index/index_internal.hpp>

SISL_LOGGING_DECL(btree)

namespace homestore {

// Internal format of variable node:
// [Persistent Header][prefix_node_header][prefix_area_bitset][KV Suffix][KV Suffix].. ...  ... [KV Prefix][KV Prefix]
//
template < typename K, typename V >
class FixedPrefixNode : public VariantNode< K, V > {
    using BtreeNode::get_nth_key_internal;
    using BtreeNode::get_nth_key_size;
    using BtreeNode::get_nth_obj_size;
    using BtreeNode::get_nth_value;
    using BtreeNode::get_nth_value_size;
    using BtreeNode::to_string;
    using VariantNode< K, V >::get_nth_value;

private:
#pragma pack(1)
    struct prefix_node_header {
        uint16_t used_slots; // Number of slots actually used. TODO: We can deduce from set_bit_count of bitset
        uint16_t tail_slot;  // What is the tail slot number being used

        std::string to_string() const { return fmt::format("slots_used={} tail_slot={} ", used_slots, tail_slot); }

        static constexpr uint16_t min_holes_to_compact = 10;
        // Followed by bitset
    };

    struct prefix_entry {
        uint16_t ref_count{0};
        // Followed by common prefix key
        // Followed by common prefix value

        static constexpr uint32_t size() { return key_size() + value_size() + sizeof(prefix_entry); }

        static constexpr uint32_t key_size() {
            if constexpr (std::is_base_of_v< BtreeIntervalKey, K >) {
                return dummy_key< K >.serialized_prefix_size();
            } else {
                return 0u; // There is no prefix for non interval key
            }
        }

        static constexpr uint32_t value_size() {
            if constexpr (std::is_base_of_v< BtreeIntervalValue, V >) {
                return dummy_value< V >.serialized_prefix_size();
            } else {
                return 0u; // There is no prefix for non interval value
            }
        }

        void write_kv(BtreeKey const& key, BtreeValue const& val) {
            if constexpr (std::is_base_of_v< BtreeIntervalKey, K > && std::is_base_of_v< BtreeIntervalValue, V >) {
                sisl::blob const kblob = s_cast< K const& >(key).serialize_prefix();
                sisl::blob const vblob = s_cast< V const& >(val).serialize_prefix();

                DEBUG_ASSERT_EQ(kblob.size(), key_size(), "Prefix key size mismatch with serialized prefix size");
                DEBUG_ASSERT_EQ(vblob.size(), value_size(), "Prefix value size mismatch with serialized prefix size");

                uint8_t* cur_ptr = uintptr_cast(this) + sizeof(prefix_entry);
                std::memcpy(cur_ptr, kblob.cbytes(), kblob.size());
                cur_ptr += kblob.size();
                std::memcpy(cur_ptr, vblob.cbytes(), vblob.size());
            }
        }

        sisl::blob key_buf() const {
            return sisl::blob{r_cast< uint8_t const* >(this) + sizeof(prefix_entry), key_size()};
        }
        sisl::blob val_buf() const { return sisl::blob{key_buf().cbytes() + key_buf().size(), value_size()}; }
    };

    struct suffix_entry {
        uint16_t prefix_slot;
        // Followed by suffix key
        // Followed by suffix value

        static constexpr uint32_t size() { return key_size() + value_size() + sizeof(suffix_entry); }

        static constexpr uint32_t key_size() {
            if constexpr (std::is_base_of_v< BtreeIntervalKey, K >) {
                return dummy_key< K >.serialized_suffix_size();
            } else {
                return dummy_key< K >.serialized_size();
            }
        }

        static constexpr uint32_t value_size() {
            if constexpr (std::is_base_of_v< BtreeIntervalValue, V >) {
                return dummy_value< V >.serialized_suffix_size();
            } else {
                return dummy_value< V >.serialized_size();
            }
        }

        void write_kv(BtreeKey const& key, BtreeValue const& val) {
            sisl::blob kblob;
            sisl::blob vblob;

            uint8_t* cur_ptr = uintptr_cast(this) + sizeof(suffix_entry);
            if constexpr (std::is_base_of_v< BtreeIntervalKey, K > && std::is_base_of_v< BtreeIntervalValue, V >) {
                kblob = s_cast< K const& >(key).serialize_suffix();
                vblob = s_cast< V const& >(val).serialize_suffix();
            } else {
                kblob = key.serialize();
                vblob = val.serialize();
            }
            DEBUG_ASSERT_EQ(kblob.size(), key_size(), "Suffix key size mismatch with serialized suffix size");
            DEBUG_ASSERT_EQ(vblob.size(), value_size(), "Suffix value size mismatch with serialized suffix size");

            std::memcpy(cur_ptr, kblob.cbytes(), kblob.size());
            cur_ptr += kblob.size();
            std::memcpy(cur_ptr, vblob.cbytes(), vblob.size());
        }

        sisl::blob key_buf() const {
            return sisl::blob{const_cast< uint8_t* >(r_cast< uint8_t const* >(this) + sizeof(suffix_entry)),
                              key_size()};
        }
        sisl::blob val_buf() const { return sisl::blob{key_buf().bytes() + key_buf().size(), value_size()}; }
    };
#pragma pack()

    sisl::CompactBitSet prefix_bitset_;

public:
    FixedPrefixNode(uint8_t* node_buf, bnodeid_t id, bool init, bool is_leaf, const BtreeConfig& cfg) :
            VariantNode< K, V >(node_buf, id, init, is_leaf, cfg),
            prefix_bitset_{sisl::blob{bitset_area(), reqd_bitset_size(cfg)}, init} {
        if (init) {
            auto phdr = prefix_header();
            phdr->used_slots = 0;
            phdr->tail_slot = 0;
        }
    }

    virtual ~FixedPrefixNode() = default;

    ///////////////////////////// All overrides of BtreeIntervalNode ///////////////////////////////////
    /// @brief Upserts a batch of entries into a prefix node.
    ///
    /// This method upserts all entries in the node that have keys within the specified range.
    /// The method is supported only for leaf nodes.
    ///
    /// @param keys The range of keys to upsert.
    /// @param val The value to upsert.
    /// @param on_found_cb The callback function to be called for each entry found within the range.
    ///                    The function should take two arguments: a key and a value, and return a
    ///                    batch_upsert_decision_t value. If the function returns:
    ///                        batch_upsert_decision_t::replace, the entry is upserted with the new value.
    ///                        batch_upsert_decision_t::remove, the entry is removed from the node.
    ///                        batch_upsert_decision_t::keep, the entry is not modified and the method moves on to the
    ///                        next entry.
    /// @return An optional key that was not upserted due to lack of space in the node.
    ///         If all keys were upserted successfully, the method returns std::nullopt.
    ///         If the method ran out of space in the node, the method returns the key that was last upserted
    btree_status_t multi_put(BtreeKeyRange< K > const& keys, BtreeKey const& first_input_key, BtreeValue const& val,
                             btree_put_type put_type, K* last_failed_key,
                             put_filter_cb_t const& filter_cb = nullptr) override {
        DEBUG_ASSERT_EQ(this->is_leaf(), true, "Multi put entries on node are supported only for leaf nodes");
        if constexpr (std::is_base_of_v< BtreeIntervalKey, K > && std::is_base_of_v< BtreeIntervalValue, V >) {
            uint32_t modified{0};

            uint16_t prefix_slot{std::numeric_limits< uint16_t >::max()};
            K cur_key = keys.start_key();

            if (!keys.is_start_inclusive()) { cur_key.shift(1); }
            if (!has_room(1u)) { return btree_status_t::space_not_avail; }
            bool upserted_all{false};

            auto [found, idx] = this->find(cur_key, nullptr, false);
            do {
                auto x = cur_key.compare(keys.end_key());
                if ((x > 0) || ((x == 0) && !keys.is_end_inclusive())) {
                    upserted_all = true;
                    break;
                }

                put_filter_decision decision{put_filter_decision::replace};
                if (found) {
                    if (put_type == btree_put_type::INSERT) { // Insert operation should skip existing entries
                        decision = put_filter_decision::keep;
                    } else if (filter_cb) {
                        decision = filter_cb(cur_key, get_nth_value(idx, false), val);
                        if (decision == put_filter_decision::remove) {
                            ++modified;
                            remove(idx);
                        }
                    }

                    // We found the entry and it will be replaced in next step, for now, we need to deref the prefix
                    // corresponding to this suffix entry
                    if (decision == put_filter_decision::replace) {
                        deref_remove_prefix(get_suffix_entry_c(idx)->prefix_slot);
                    }
                } else {
                    if (put_type == btree_put_type::UPDATE) { // Update would need existing entries found
                        decision = put_filter_decision::keep;
                    } else {
                        std::memmove(get_suffix_entry(idx + 1), get_suffix_entry(idx),
                                     (this->total_entries() - idx) * suffix_entry::size());
                        this->inc_entries();
                    }
                }

                if (decision == put_filter_decision::replace) {
                    if (prefix_slot == std::numeric_limits< uint16_t >::max()) {
                        prefix_slot = add_prefix(cur_key, val);
                    }
                    V new_val{s_cast< V const& >(val)};
                    new_val.shift(s_cast< K const& >(cur_key).distance(first_input_key));
                    write_suffix(idx, prefix_slot, cur_key, new_val);
                }

                cur_key.shift(1);
                if (!has_room(1u)) { break; }

                if (decision != put_filter_decision::remove) { ++idx; }
                found =
                    (idx < this->total_entries() && (BtreeNode::get_nth_key< K >(idx, false).compare(cur_key) == 0));
            } while (true);

            if (modified) { this->inc_gen(); }
#ifndef NDEBUG
            validate_sanity();
#endif
            if (!upserted_all) {
                if (last_failed_key) { *last_failed_key = cur_key; }
                return btree_status_t::has_more;
            } else {
                return btree_status_t::success;
            }
        } else {
            return btree_status_t::not_supported;
        }
    }

    /**
     * @brief Removes a batch of entries from a prefix node.
     *
     * This method removes all entries in the node that have keys within the specified range.
     * The method is supported only for leaf nodes.
     *
     * @param keys The range of keys to remove.
     * @param on_found_cb The callback function to be called for each entry found within the range. The function should
     * take two arguments: a key and a value, and return a boolean value. If the function returns true or if there is
     * no callback function, the entry is removed from the node. If the function returns false, the entry is not
     * removed and the method moves on to the next entry.
     *
     * @return Returns number of objects removed
     */
    uint32_t multi_remove(BtreeKeyRange< K > const& keys, remove_filter_cb_t const& filter_cb = nullptr) override {
        DEBUG_ASSERT_EQ(this->is_leaf(), true, "remove_batch api is supported only for leaf node");
        if constexpr (std::is_base_of_v< BtreeIntervalKey, K > && std::is_base_of_v< BtreeIntervalValue, V >) {
            K cur_key = keys.start_key();
            if (!keys.is_start_inclusive()) { cur_key.shift(1); }
            uint32_t num_removed{0};

            auto [_, idx] = this->find(cur_key, nullptr, false);
            while (idx < this->total_entries()) {
                cur_key = BtreeNode::get_nth_key< K >(idx, false);
                auto x = cur_key.compare(keys.end_key());
                if ((x > 0) || ((x == 0) && !keys.is_end_inclusive())) { break; }

                bool remove{true};
                if (!filter_cb || filter_cb(cur_key, get_nth_value(idx, false))) {
                    suffix_entry* sentry = get_suffix_entry(idx);
                    deref_remove_prefix(sentry->prefix_slot);
                    std::memmove(uintptr_cast(sentry), uintptr_cast(get_suffix_entry(idx + 1)),
                                 (this->total_entries() - idx - 1) * suffix_entry::size());
                    this->dec_entries();
                    ++num_removed;
                } else {
                    ++idx;
                }
            }
            if (num_removed) { this->inc_gen(); }

#ifndef NDEBUG
            validate_sanity();
#endif
            return num_removed;
        } else {
            return 0;
        }
    }

    ///////////////////////////// All overrides of BtreeNode ///////////////////////////////////
    void get_nth_key_internal(uint32_t idx, BtreeKey& out_key, bool) const override {
        suffix_entry const* sentry = get_suffix_entry_c(idx);
        prefix_entry const* pentry = get_prefix_entry_c(sentry->prefix_slot);
        DEBUG_ASSERT(prefix_bitset_.is_bit_set(sentry->prefix_slot),
                     "Prefix slot number is in suffix entry, but corresponding bit is not set");
        s_cast< BtreeIntervalKey& >(out_key).deserialize(pentry->key_buf(), sentry->key_buf(), true);
    }

    void get_nth_value(uint32_t idx, BtreeValue* out_val, bool) const override {
        if (idx == this->total_entries()) {
            DEBUG_ASSERT_EQ(this->is_leaf(), false, "get_nth_value out-of-bound");
            DEBUG_ASSERT_EQ(this->has_valid_edge(), true, "get_nth_value out-of-bound");
            *(r_cast< BtreeLinkInfo* >(out_val)) = this->get_edge_value();
        } else {
            suffix_entry const* sentry = get_suffix_entry_c(idx);
            prefix_entry const* pentry = get_prefix_entry_c(sentry->prefix_slot);
            DEBUG_ASSERT(prefix_bitset_.is_bit_set(sentry->prefix_slot),
                         "Prefix slot number is in suffix entry, but corresponding bit is not set");
            s_cast< BtreeIntervalValue* >(out_val)->deserialize(pentry->val_buf(), sentry->val_buf(), true);
        }
    }

    uint32_t available_size() const override {
        auto num_holes = num_prefix_holes();
        if (num_holes > prefix_node_header::min_holes_to_compact) {
            return available_size_without_compaction() + (num_holes * prefix_entry::size());
        } else {
            return available_size_without_compaction();
        }
    }

    bool has_room_for_put(btree_put_type, uint32_t, uint32_t) const override { return has_room(1u); }

    uint32_t get_nth_key_size(uint32_t) const override { return dummy_key< K >.serialized_size(); }

    uint32_t get_nth_value_size(uint32_t) const override { return dummy_value< V >.serialized_size(); }

    uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, BtreeNode& on, uint32_t size_to_move) override {
        return move_out_to_right_internal(cfg, on, true /* by_size*/, size_to_move);
    }

    uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, BtreeNode& on, uint32_t num_entries) override {
        return move_out_to_right_internal(cfg, on, false /* by_size*/, num_entries);
    }

    uint32_t move_out_to_right_internal(const BtreeConfig& cfg, BtreeNode& on, bool by_size, uint32_t limit) {
        FixedPrefixNode& dst_node = s_cast< FixedPrefixNode& >(on);

        uint32_t dst_node_size = dst_node.occupied_size();
        uint32_t num_moved{0};

        // Nothing to move
        if (this->total_entries() == 0) { return by_size ? 0 : dst_node_size; }

        // Step 1: Walk through from last idx towards first and map the current node prefix slot to new prefix slot.
        // This map is used both to map the prefix slot as well as presence of if the prefix slot is used for multiple
        // suffixes. At the end of this step, all prefixes that needs to be moved are moved with correct bitset
        // settings on both source and destination
        std::map< uint16_t, uint16_t > this_to_dst_prefix;
        uint16_t idx = this->total_entries() - 1;
        do {
            if (by_size) {
                if (dst_node_size > limit) { break; }
            } else {
                if (num_moved == limit) { break; }
            }
            suffix_entry* this_sentry = get_suffix_entry(idx);

            auto const this_prefix_slot = this_sentry->prefix_slot;
            auto const it = this_to_dst_prefix.find(this_prefix_slot);

            if (it == this_to_dst_prefix.cend()) {
                // Have not seen the prefix before, new entry, allocate a prefix in dest node and copy the prefix to dst
                // node and update our suffix entry to point to that slot temporarily here. The suffix memory is all
                // moved will be moved to dst node all at once later.
                uint16_t dst_prefix_slot = dst_node.alloc_prefix();
                prefix_entry* dst_pentry = dst_node.get_prefix_entry(dst_prefix_slot);

                std::memcpy(voidptr_cast(dst_pentry), c_voidptr_cast(get_prefix_entry_c(this_prefix_slot)),
                            prefix_entry::size());

                dst_pentry->ref_count = 1;
                this_sentry->prefix_slot = dst_prefix_slot;

                this_to_dst_prefix.insert(std::pair(this_prefix_slot, dst_prefix_slot));
                dst_node_size += prefix_entry::size();
            } else {
                prefix_entry* new_pentry = dst_node.get_prefix_entry(it->second);
                ++new_pentry->ref_count;
                this_sentry->prefix_slot = it->second;
            }

            // Remove a reference to this prefix slot, since the suffix will be eventually moved to dst node
            deref_remove_prefix(this_prefix_slot);
            dst_node_size += suffix_entry::size();
            ++num_moved;
        } while (idx-- > 0);

        // Step 2: Move the suffixes and adjust the num_entries in source and destination. All tomove suffixes have
        // adjusted to their new prefix slot already as part of Step 1
        std::memmove(uintptr_cast(dst_node.get_suffix_entry(0)), uintptr_cast(get_suffix_entry(idx + 1)),
                     num_moved * suffix_entry::size());
        this->sub_entries(num_moved);
        dst_node.add_entries(num_moved);

        // Step 3: Adjust all the header parameters for old and new. For old we other header parameters are adjusted as
        // part of Step 1, except generation count
        this->inc_gen();
        dst_node.inc_gen();
        auto new_phdr = dst_node.prefix_header();

        if (!this->is_leaf() && (dst_node.total_entries() != 0)) {
            // Incase this node is an edge node, move the stick to the right hand side node
            dst_node.set_edge_info(this->edge_info());
            this->invalidate_edge();
        }

        // Step 4: Use this oppurtunity to compact the source node if it needs. Destination node is written in
        // compacted state anyways
        if (is_compaction_suggested()) { compact(); }

#ifndef NDEBUG
        validate_sanity();
        dst_node.validate_sanity();
#endif
        return by_size ? num_moved : dst_node_size;
    }

    btree_status_t insert(uint32_t idx, BtreeKey const& key, BtreeValue const& val) override {
        if (!has_room(1u)) { return btree_status_t::space_not_avail; }

        std::memmove(get_suffix_entry(idx + 1), get_suffix_entry(idx),
                     (this->total_entries() - idx) * suffix_entry::size());

        write_suffix(idx, add_prefix(key, val), key, val);
        this->inc_entries();
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
        return btree_status_t::success;
    }

    void update(uint32_t idx, BtreeValue const& val) override {
        update(idx, BtreeNode::get_nth_key< K >(idx, false), val);
    }

    void update(uint32_t idx, BtreeKey const& key, BtreeValue const& val) override {
        // If we are updating the edge value, none of the other logic matter. Just update edge value and move on
        if (idx == this->total_entries()) {
            DEBUG_ASSERT_EQ(this->is_leaf(), false);
            this->set_edge_value(val);
            this->inc_gen();
            return;
        }

        if (!has_room(1u)) {
            if (has_room_after_compaction(1u)) {
                compact();
            } else {
                LOGMSG_ASSERT(false, "Even after compaction there is no room for update");
                return;
            }
        }
        write_suffix(idx, add_prefix(key, val), key, val);
        this->inc_gen();

#ifndef NDEBUG
        validate_sanity();
#endif
    }

    void remove(uint32_t idx) override {
        if (idx == this->total_entries()) {
            DEBUG_ASSERT(!this->is_leaf() && this->has_valid_edge(),
                         "idx={} == num_entries={} for leaf or non-edge node", idx, this->total_entries());

            if (idx == 0) {
                this->invalidate_edge();
            } else {
                V last_1_val;
                get_nth_value(idx - 1, &last_1_val, false);
                this->set_edge_value(last_1_val);
            }
        } else {
            suffix_entry* sentry = get_suffix_entry(idx);
            deref_remove_prefix(sentry->prefix_slot);
            std::memmove(uintptr_cast(sentry), uintptr_cast(get_suffix_entry(idx + 1)),
                         (this->total_entries() - idx - 1) * suffix_entry::size());
            this->dec_entries();
        }
        this->inc_gen();
    }

    void remove(uint32_t idx_s, uint32_t idx_e) override {
        for (auto idx{idx_s}; idx < idx_e; ++idx) {
            remove(idx);
        }
    }

    void remove_all(BtreeConfig const& cfg) override {
        this->sub_entries(this->total_entries());
        this->invalidate_edge();
        this->inc_gen();
        prefix_bitset_ = sisl::CompactBitSet{sisl::blob{bitset_area(), reqd_bitset_size(cfg)}, true};

#ifndef NDEBUG
        validate_sanity();
#endif
    }

    uint32_t get_nth_obj_size(uint32_t) const override { return get_key_size() + get_value_size(); }

    uint32_t num_entries_by_size(uint32_t start_idx, uint32_t size) const {
        uint32_t num_entries{0};
        uint32_t cum_size{0};

        std::unordered_set< uint16_t > prefixes;
        for (auto idx{start_idx}; idx < this->total_entries(); ++idx) {
            suffix_entry const* sentry = get_suffix_entry_c(idx);
            if (prefixes.find(sentry->prefix_slot) == prefixes.cend()) {
                prefixes.insert(sentry->prefix_slot);
                cum_size += prefix_entry::size();
            }
            cum_size += suffix_entry::size();

            if (cum_size > size) { return num_entries; }
            ++num_entries;
        }
        return num_entries;
    }

    uint32_t copy_by_size(BtreeConfig const& cfg, BtreeNode const& o, uint32_t start_idx, uint32_t size) override {
        return copy_internal(cfg, o, start_idx, true /* by_size*/, size);
    }

    uint32_t copy_by_entries(BtreeConfig const& cfg, BtreeNode const& o, uint32_t start_idx,
                             uint32_t nentries) override {
        return copy_internal(cfg, o, start_idx, false /* by_size*/, nentries);
    }

    uint32_t copy_internal(BtreeConfig const& cfg, BtreeNode const& o, uint32_t start_idx, bool by_size,
                           uint32_t limit) {
        FixedPrefixNode const& src_node = s_cast< FixedPrefixNode const& >(o);

        // Adjust the size_to_move to cover the new node's reqd header space.
        uint32_t copied_size{0};

        // Step 1: Walk through from last idx towards first and map the current node prefix slot to new prefix slot.
        // This map is used both to map the prefix slot as well as presence of if the prefix slot is used for multiple
        // suffixes. At the end of this step, all prefixes that needs to be coped are copied with correct bitset
        // settings on both source and destination
        std::map< uint16_t, uint16_t > src_to_my_prefix;
        uint16_t src_idx{s_cast< uint16_t >(start_idx)};
        uint16_t my_prefix_slot{0};
        uint16_t my_idx = this->total_entries();
        uint32_t num_copied{0};

        while ((src_idx < src_node.total_entries()) && has_room(1u)) {
            if (!by_size && num_copied >= limit) { break; }

            suffix_entry const* src_sentry = src_node.get_suffix_entry_c(src_idx);
            auto const src_prefix_slot = src_sentry->prefix_slot;

            // Map the prefix slot from src node to my node. If we don't have a prefix slot yet, we need to allocate one
            // for the remote prefix slot and copy the prefix entry from src node to my node. If we have one, just
            // continue to use that by incrementing the ref_count.
            auto const it = src_to_my_prefix.find(src_prefix_slot);
            if (it == src_to_my_prefix.cend()) {
                copied_size += prefix_entry::size() + suffix_entry::size();
                if (by_size && (copied_size > limit)) { break; }

                my_prefix_slot = alloc_prefix();
                prefix_entry* my_pentry = get_prefix_entry(my_prefix_slot);
                std::memcpy(voidptr_cast(my_pentry), c_voidptr_cast(src_node.get_prefix_entry_c(src_prefix_slot)),
                            prefix_entry::size());
                my_pentry->ref_count = 1;

                src_to_my_prefix.insert(std::pair(src_prefix_slot, my_prefix_slot));
            } else {
                copied_size += suffix_entry::size();
                if (by_size && (copied_size > limit)) { break; }

                my_prefix_slot = it->second;
                prefix_entry* my_pentry = get_prefix_entry(it->second);
                ++my_pentry->ref_count;
            }

            suffix_entry* my_sentry = get_suffix_entry(my_idx++);
            std::memcpy(voidptr_cast(my_sentry), c_voidptr_cast(src_sentry), suffix_entry::size());
            my_sentry->prefix_slot = my_prefix_slot;

            ++src_idx;
            ++num_copied;
        }

        this->add_entries(num_copied);
        this->inc_gen();

        // If we copied everything from start_idx till end and if its an edge node, need to copy the edge id as
        // well.
        if (src_node.has_valid_edge() && ((start_idx + num_copied) == src_node.total_entries())) {
            this->set_edge_info(src_node.edge_info());
        }

#ifndef NDEBUG
        validate_sanity();
#endif
        return by_size ? num_copied : copied_size;
    }

    std::string to_string(bool print_friendly = false) const override {
        auto str = fmt::format("{}id={} level={} nEntries={} {} next_node={} ",
                               (print_friendly ? "------------------------------------------------------------\n" : ""),
                               this->node_id(), this->level(), this->total_entries(),
                               (this->is_leaf() ? "LEAF" : "INTERIOR"), this->next_bnode());
        if (!this->is_leaf() && (this->has_valid_edge())) {
            fmt::format_to(std::back_inserter(str), "edge_id={}.{}", this->edge_info().m_bnodeid,
                           this->edge_info().m_link_version);
        }

        fmt::format_to(std::back_inserter(str), "{}Prefix_Hdr={}, Prefix_Bitmap=[{}]\n",
                       (print_friendly ? "\n\t" : " "), cprefix_header()->to_string(), prefix_bitset_.to_string());

        for (uint32_t i{0}; i < this->total_entries(); ++i) {
            fmt::format_to(std::back_inserter(str), "{}Entry{} [Key={} Val={}]", (print_friendly ? "\n\t" : " "), i + 1,
                           BtreeNode::get_nth_key< K >(i, false).to_string(),
                           this->get_nth_value(i, false).to_string());
        }
        return str;
    }

    std::string to_string_keys(bool print_friendly = false) const override { return "NOT Supported"; }
    std::string to_dot_keys() const override { return "NOT Supported"; }

private:
    uint16_t add_prefix(BtreeKey const& key, BtreeValue const& val) {
        auto const slot_num = alloc_prefix();

        // Layout the prefix key/value into the prefix slot allocated
        prefix_entry* pentry = get_prefix_entry(slot_num);
        pentry->ref_count = 0; // Num suffix referencing this prefix
        pentry->write_kv(key, val);

        return slot_num;
    }

    uint16_t alloc_prefix() {
        auto const slot_num = prefix_bitset_.get_next_reset_bit(0);
        if (slot_num == std::numeric_limits< uint16_t >::max()) {
            DEBUG_ASSERT(false, "Unable to alloc slot, shouldn't be mutating in this node without splitting");
            return std::numeric_limits< uint16_t >::max();
        }
        prefix_bitset_.set_bit(slot_num);

        auto phdr = prefix_header();
        ++phdr->used_slots;
        if (slot_num > phdr->tail_slot) { phdr->tail_slot = slot_num; }
        return slot_num;
    }

    void ref_prefix(uint16_t slot_num) { ++(get_prefix_entry(slot_num)->ref_count); }

    void deref_remove_prefix(uint16_t slot_num) {
        auto phdr = prefix_header();
        auto pentry = get_prefix_entry(slot_num);
        DEBUG_ASSERT_GT(pentry->ref_count, 0, "Deref of prefix slot={} error: ref_count already 0", slot_num);
        DEBUG_ASSERT_GT(phdr->used_slots, 0, "Deref of prefix slot={} error: used slot count is already 0", slot_num);

        if (--pentry->ref_count == 0) {
            --phdr->used_slots;
            prefix_bitset_.reset_bit(slot_num);
            if ((slot_num != 0) && (slot_num == phdr->tail_slot)) {
                uint16_t prev_slot = prefix_bitset_.get_prev_set_bit(slot_num);
                if (prev_slot != std::numeric_limits< uint16_t >::max()) { phdr->tail_slot = prev_slot; }
            }
        }
    }

    void write_suffix(uint16_t idx, uint16_t prefix_slot, BtreeKey const& key, BtreeValue const& val) {
        suffix_entry* sentry = get_suffix_entry(idx);
        sentry->prefix_slot = prefix_slot;
        sentry->write_kv(key, val);
        ref_prefix(prefix_slot);
    }

    uint32_t available_size_without_compaction() const {
        uint8_t const* suffix = r_cast< uint8_t const* >(get_suffix_entry_c(this->total_entries()));
        uint8_t const* prefix = r_cast< uint8_t const* >(get_prefix_entry_c(cprefix_header()->tail_slot));

        if (suffix <= prefix) {
            return prefix - suffix;
        } else {
            DEBUG_ASSERT(false, "Node data is corrupted, suffix area is overlapping prefix area");
            return 0;
        }
    }

    uint32_t available_size_with_compaction() const {
        return available_size_without_compaction() + (num_prefix_holes() * prefix_entry::size());
    }

    bool has_room(uint16_t for_nentries) const {
        return (available_size_without_compaction() >= (prefix_entry::size() + (for_nentries * suffix_entry::size())));
    }

    bool has_room_after_compaction(uint16_t for_nentries) const {
        return (available_size_with_compaction() >= (prefix_entry::size() + (for_nentries * suffix_entry::size())));
    }

    uint32_t num_prefix_holes() const {
        auto phdr = cprefix_header();
        return (phdr->tail_slot + 1 - phdr->used_slots);
    }

    bool is_compaction_suggested() const { return (num_prefix_holes() > prefix_node_header::min_holes_to_compact); }

    void compact() {
        // Build reverse map from prefix to suffix
        std::multimap< uint16_t, uint16_t > prefix_to_suffix;
        for (uint16_t idx{0}; idx < this->total_entries(); ++idx) {
            suffix_entry const* sentry = get_suffix_entry_c(idx);
            prefix_to_suffix.insert(std::pair(sentry->prefix_slot, idx));
        }

        // Starting from a slot outside of actual used slots, keep finding all the slots which are out of slots used
        // count are moved to free area within the compactable area.
        uint16_t from_slot{prefix_header()->used_slots};
        uint16_t to_slot{0};
        while (true) {
            from_slot = prefix_bitset_.get_next_set_bit(from_slot);
            if (from_slot == std::numeric_limits< uint16_t >::max()) { break; }

            auto const to_slot = prefix_bitset_.get_next_reset_bit(0u);
            DEBUG_ASSERT_NE(to_slot, std::numeric_limits< uint16_t >::max(),
                            "Didn't find a free location on to compaction side, not expected");
            DEBUG_ASSERT_LT(to_slot, prefix_header()->used_slots,
                            "Couldn't find enough slots inside compactable area, not expected");

            std::memcpy(uintptr_cast(get_prefix_entry(to_slot)), (void*)get_prefix_entry(from_slot),
                        prefix_entry::size());
            prefix_bitset_.reset_bit(from_slot);
            prefix_bitset_.set_bit(to_slot);

            // Move all the suffixes that are referencing this prefix to the new location
            auto range = prefix_to_suffix.equal_range(from_slot);
            for (auto it = range.first; it != range.second; ++it) {
                suffix_entry* sentry = get_suffix_entry(it->second);
                sentry->prefix_slot = to_slot;
            }
        }

        // Finally adjust the tail offset to the compacted area.
        auto phdr = prefix_header();
        phdr->tail_slot = phdr->used_slots;
    }

#ifndef NDEBUG
    void validate_sanity() {
        uint32_t i{0};
        // validate if keys are in ascending order
        K prevKey;
        while (i < this->total_entries()) {
            K key = BtreeNode::get_nth_key< K >(i, false);
            uint64_t kp = *(uint64_t*)key.serialize().bytes();
            if (i > 0 && prevKey.compare(key) > 0) {
                DEBUG_ASSERT(false, "Found non sorted entry: {} -> {}", kp, to_string());
            }
            prevKey = key;
            ++i;
        }
    }
#endif

    //////////////////////// All Helper methods section ////////////////////////
    static uint32_t reqd_bitset_size(BtreeConfig const& cfg) {
        return sisl::round_up(cfg.node_data_size() / (prefix_entry::key_size() + prefix_entry::value_size()) / 8,
                              sisl::CompactBitSet::size_multiples());
    }

    prefix_node_header* prefix_header() { return r_cast< prefix_node_header* >(this->node_data_area()); }
    prefix_node_header const* cprefix_header() const {
        return r_cast< prefix_node_header const* >(this->node_data_area_const());
    }

    uint8_t* bitset_area() { return this->node_data_area() + sizeof(prefix_node_header); }
    uint8_t const* cbitset_area() const { return this->node_data_area_const() + sizeof(prefix_node_header); }

    uint8_t* suffix_kv_area() { return bitset_area() + (prefix_bitset_.size() / 8); }
    uint8_t const* csuffix_kv_area() const { return cbitset_area() + (prefix_bitset_.size() / 8); }

    prefix_entry* get_prefix_entry(uint16_t slot_num) {
        return r_cast< prefix_entry* >(this->node_data_area() +
                                       (this->node_data_size() - ((slot_num + 1) * prefix_entry::size())));
    }

    prefix_entry const* get_prefix_entry_c(uint16_t slot_num) const {
        return r_cast< prefix_entry const* >(this->node_data_area_const() +
                                             (this->node_data_size() - ((slot_num + 1) * prefix_entry::size())));
    }

    suffix_entry* get_suffix_entry(uint16_t idx) {
        return r_cast< suffix_entry* >(suffix_kv_area() + (idx * suffix_entry::size()));
    }
    suffix_entry const* get_suffix_entry_c(uint16_t idx) const {
        return r_cast< suffix_entry const* >(csuffix_kv_area() + (idx * suffix_entry::size()));
    }

    static constexpr uint32_t get_key_size() { return prefix_entry::key_size() + suffix_entry::key_size(); }
    static constexpr uint32_t get_value_size() { return prefix_entry::value_size() + suffix_entry::value_size(); }
};
} // namespace homestore
