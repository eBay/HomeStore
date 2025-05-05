/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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

#include <homestore/btree/detail/btree_node.hpp>
#include <homestore/btree/btree_req.hpp>

namespace homestore {
template < typename K >
static K dummy_key;

template < typename V >
static V dummy_value;

template < typename K, typename V >
class VariantNode : public StoreSpecificBtreeNode {
public:
    using BtreeNode::get_nth_key_size;
    using BtreeNode::get_nth_value;

    VariantNode(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf, BtreeConfig const& cfg) :
            StoreSpecificBtreeNode(node_buf, id, init_buf, is_leaf, cfg) {}

    ///////////////////////////////////////// Get related APIs of the node /////////////////////////////////////////

    /// @brief Gets all entries in the node that have keys within the specified range.
    ///
    /// This method returns all entries in the node that have keys within the specified range. The method searches the
    /// node using a binary search algorithm to find the first and last entries that have keys within the range. The
    /// method returns the indices of these entries in the node and optionally returns the key-value pairs of the
    /// entries.
    ///
    /// @tparam K The type of the keys in the node.
    /// @tparam V The type of the values in the node.
    /// @param range The range of keys to search for.
    /// @param max_count The maximum number of entries to return.
    /// @param start_idx [out] A reference to an integer to store the index of the first entry that has a key within the
    /// range.
    /// @param end_idx [out] A reference to an integer to store the index of the last entry that has a key within the
    /// range.
    /// @param out_values [optional] A pointer to a vector to store the key-value pairs of the entries if provided. Can
    /// be nullptr
    /// @param filter_cb [optional] A callback function to be called for each entry found in the node that has a key.
    /// The callback is expected to return true if the entry should be included in the result and false otherwise.
    /// @return The number of entries found in the node that have keys within the range and callback if any, allowed
    /// the method to include result to.
    virtual uint32_t multi_get(BtreeKeyRange< K > const& range, uint32_t max_count, uint32_t& start_idx,
                               uint32_t& end_idx, std::vector< std::pair< K, V > >* out_values = nullptr,
                               get_filter_cb_t const& filter_cb = nullptr) const {
        if (!match_range(range, start_idx, end_idx)) { return 0; }

        uint32_t count = std::min(end_idx - start_idx + 1, max_count);
        if (out_values || filter_cb) {
            /* get the keys and values */
            auto const upto_idx = start_idx + count;
            for (auto i{start_idx}; i < upto_idx; ++i) {
                K key = get_nth_key< K >(i, (out_values != nullptr) /* copy */);
                V val = get_nth_value(i, (out_values != nullptr) /* copy */);
                if (!filter_cb || filter_cb(key, val)) {
                    if (out_values) { out_values->emplace_back(std::move(key), std::move(val)); }
                } else {
                    --count;
                }
            }
        }
        return count;
    }

    /// @brief Gets any entry in the node that has a key within the specified range.
    ///
    /// This method returns any entry in the node that has a key within the specified range. The method does a  binary
    /// search to find the first entry that has a key within the range. It returns the index of the entry in the node
    /// and optionally returns the key and value of the entry.
    ///
    /// @param range The range of keys to search for.
    /// @param out_key [optional] A pointer to a key to store the key of the entry if desired.
    /// @param out_val [optional] A pointer to a value to store the value of the entry if desired.
    /// @param copy_key Whether to copy the key of the entry to the output key. If not copied, it uses its internal node
    /// pointer to construct the key. It is not advisable to set this to true in case the key is accessed after any
    /// mutation on nodes.
    /// @param copy_val Whether to copy the value of the entry to the output value. If not copied, it uses its internal
    /// node pointer to construct the value. It is not advisable to set this to true in case the value is accessed after
    /// any mutation on nodes.
    /// @param filter_cb [optional] A callback function to be called for each entry found in the node that has a key.
    /// The callback is expected to return true if the entry should be included in the result and false otherwise.
    /// @return A pair of a boolean and an integer.
    ///         The boolean indicates whether an entry was found within the range.
    ///         The integer is the index of the entry in the node.
    virtual std::pair< bool, uint32_t > get_any(BtreeKeyRange< K > const& range, BtreeKey* out_key, BtreeValue* out_val,
                                                bool copy_key, bool copy_val,
                                                get_filter_cb_t const& filter_cb = nullptr) const {
        LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "Magic mismatch on btree_node {}",
                         get_persistent_header_const()->to_string());
        uint32_t result_idx;
        const auto mm_opt = range.multi_option();
        bool efound;
        uint32_t end_idx;

        // Get the start index of the search range.
        auto [sfound, start_idx] = bsearch_node(range.start_key());
        if (sfound && !range.is_start_inclusive()) {
            ++start_idx;
            sfound = false;
        }

        if (sfound && ((mm_opt == MultiMatchOption::DO_NOT_CARE) || (mm_opt == MultiMatchOption::LEFT_MOST))) {
            result_idx = start_idx;
            goto found_result;
        } else if (start_idx == total_entries()) {
            DEBUG_ASSERT(is_leaf() || has_valid_edge(), "Invalid node");
            return std::make_pair(false, 0); // out_of_range
        }

        std::tie(efound, end_idx) = bsearch_node(range.end_key());
        if (efound && !range.is_end_inclusive()) {
            if (end_idx == 0) { return std::make_pair(false, 0); }
            --end_idx;
            efound = false;
        }

        if (end_idx > start_idx) {
            if (mm_opt == MultiMatchOption::RIGHT_MOST) {
                result_idx = end_idx;
            } else if (mm_opt == MultiMatchOption::MID) {
                result_idx = (end_idx - start_idx) / 2;
            } else {
                result_idx = start_idx;
            }
        } else if ((start_idx == end_idx) && ((sfound || efound))) {
            result_idx = start_idx;
        } else {
            return std::make_pair(false, 0);
        }

    found_result:
        K tmp_key;
        if (filter_cb && !out_key) {
            out_key = &tmp_key;
            copy_key = false;
        }

        V tmp_val;
        if (filter_cb && !out_val) {
            out_val = &tmp_val;
            copy_val = false;
        }

        if (out_key) { get_nth_key_internal(result_idx, *out_key, copy_key); }
        if (out_val) { get_nth_value(result_idx, out_val, copy_val); }

        return (!filter_cb || filter_cb(*out_key, *out_val)) ? std::make_pair(true, result_idx)
                                                             : std::make_pair(false, 0u);
    }

    V get_nth_value(uint32_t idx, bool copy) const {
        V out_val;
        get_nth_value(idx, &out_val, copy);
        return out_val;
    }

    int compare_nth_key(const BtreeKey& cmp_key, uint32_t ind) const override {
        return get_nth_key< K >(ind, false).compare(cmp_key);
    }

    ///////////////////////////////////////// Put related APIs of the node /////////////////////////////////////////
    /// @brief Inserts or updates an entry with the specified key and value in the node.
    ///
    /// This method inserts or updates an entry with the specified key and value in the node. It binary searches
    /// the node to find the index of the entry with the specified key. If an entry with the specified key is found, it
    /// updates the value for key according to the specified put type. If an entry with the specified key is not found,
    /// it inserts a new entry with the specified key and value. The method optionally returns the value of the existing
    /// entry if it was updated.
    ///
    /// NOTE: The operation fails if the put type is INSERT and an entry with the specified key already exists in the
    /// node.
    ///
    /// @param key The key of the entry to insert or update.
    /// @param val The value of the entry to insert or update.
    /// @param put_type The type of put operation to perform if an entry with the specified key is found. put_type
    /// translates into one of "Insert", "Update" or "Upsert".
    /// @param existing_val [optional] A pointer to a value to store the value of the existing entry if it was updated.
    /// @param filter_cb [optional] A callback function to be called for each entry found in the node that has a key. It
    /// is used as a filter to remove anything that needn't be updated.
    /// @return A status code indicating whether the operation was successful.
    ///
    virtual btree_status_t put(BtreeKey const& key, BtreeValue const& val, btree_put_type put_type,
                               BtreeValue* existing_val, put_filter_cb_t const& filter_cb = nullptr) {
        LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "Magic mismatch on btree_node {}",
                         get_persistent_header_const()->to_string());
        auto ret = btree_status_t::success;

        DEBUG_ASSERT_EQ(
            this->is_leaf(), true,
            "Put operation on node is supported only for leaf nodes, interiors do use insert/update on index APIs");

        const auto [found, idx] = find(key, nullptr, false);
        if (found) {
            if (existing_val) { get_nth_value(idx, existing_val, true); }
            if (filter_cb &&
                filter_cb(get_nth_key< K >(idx, false), get_nth_value(idx, false), val) !=
                    put_filter_decision::replace) {
                LOGINFO("Filter callback rejected the update for key {}", key.to_string());
                return btree_status_t::filtered_out;
            }
        }

        if (put_type == btree_put_type::INSERT) {
            if (found) {
                LOGINFO("Attempt to insert duplicate entry {}", key.to_string());
                return btree_status_t::already_exists;
            }
            ret = insert(idx, key, val);
        } else if (put_type == btree_put_type::UPDATE) {
            if (!found) {
                LOGINFO("Attempt to update non-existent entry {}", key.to_string());
                return btree_status_t::not_found;
            }
            update(idx, key, val);
        } else if (put_type == btree_put_type::UPSERT) {
            found ? update(idx, key, val) : (void)insert(idx, key, val);
        } else {
            DEBUG_ASSERT(false, "Wrong put_type {}", put_type);
        }
        return ret;
    }

    /// @brief Put a batch of key/values into this node
    ///
    /// This method updates all entries in the node that have keys within the specified range.
    /// NOTE: The method is supported only for leaf nodes.
    /// NOTE: This base class version only supports range updates.
    ///
    /// @param keys The range of keys to upsert.
    /// @param val The value to upsert.
    /// @param last_failed_key [optional] If non-null and if there an not enough room to put the objects, the key where
    /// it was not able to put.
    /// @param filter_cb The callback function to be called for each entry found within the range. The function should
    /// take two arguments: a key and a value, and return a batch_upsert_decision_t value. If the function returns:
    ///     put_filter_decision::replace, the entry is upserted with the new value.
    ///     put_filter_decision::remove, the entry is removed from the node.
    ///     put_filter_decision::keep, the entry is not modified and the method moves on to the next entry.
    /// @param app_ctx User supplied private context data.
    /// @return Btree status typically .
    ///         If all keys were upserted successfully, the method returns btree_status_t::success.
    ///         If the method ran out of space in the node, the method returns the key that was last put and the status
    ///         as btree_status_t::has_more
    virtual btree_status_t multi_put(BtreeKeyRange< K > const& keys, BtreeKey const&, BtreeValue const& val,
                                     btree_put_type put_type, K* last_failed_key,
                                     put_filter_cb_t const& filter_cb = nullptr, void* app_ctx = nullptr) {
        if (put_type != btree_put_type::UPDATE) {
            DEBUG_ASSERT(false, "For non-interval keys multi-put should be really update and cannot insert");
            return btree_status_t::not_supported;
        }
        DEBUG_ASSERT_EQ(this->is_leaf(), true, "Multi put entries on node are supported only for leaf nodes");

        // Match the key range to get start and end idx. If none of the ranges here matches, we have to return not_found
        uint32_t start_idx;
        uint32_t end_idx;
        if (!this->match_range(keys, start_idx, end_idx)) { return btree_status_t::not_found; }

        const auto new_val_size = val.serialized_size();
        for (auto idx{start_idx}; idx <= end_idx; ++idx) {
            if (!has_room_for_put(put_type, get_nth_key_size(idx), new_val_size)) {
                if (last_failed_key) { this->get_nth_key_internal(idx, *last_failed_key, true); }
                return btree_status_t::has_more;
            }
            if (filter_cb) {
                auto decision = filter_cb(get_nth_key< K >(idx, false), get_nth_value(idx, false), val);
                if (decision == put_filter_decision::replace) {
                    this->update(idx, val);
                } else if (decision == put_filter_decision::remove) {
                    this->remove(idx);
                    --idx;
                }
            } else {
                update(idx, val);
            }
        }
        return btree_status_t::success;
    }

    ///////////////////////////////////////// Remove related APIs of the node /////////////////////////////////////////
    virtual uint32_t multi_remove(BtreeKeyRange< K > const& keys, remove_filter_cb_t const& filter_cb = nullptr,
                                  void* usr_ctx = nullptr) {
        DEBUG_ASSERT_EQ(this->is_leaf(), true, "Multi put entries on node are supported only for leaf nodes");

        // Match the key range to get start and end idx. If none of the ranges here matches, we have to return not_found
        uint32_t start_idx{0};
        uint32_t end_idx{0};
        if (!this->match_range(keys, start_idx, end_idx)) { return 0u; }

        auto removed_count = end_idx - start_idx + 1;
        auto ret = removed_count;
        for (uint32_t count = 0; count < removed_count; ++count) {
            if (!filter_cb || filter_cb(get_nth_key< K >(start_idx, false), get_nth_value(start_idx, false))) {
                this->remove(start_idx);
            } else {
                ++start_idx; // Skipping the entry
                --ret;
            }
        }
        return ret;
    }
};
} // namespace homestore