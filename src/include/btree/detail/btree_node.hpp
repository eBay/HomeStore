/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam, Rishabh Mittal
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
#include <iostream>

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wattributes"
#endif
#include <folly/SharedMutex.h>
#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif

#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/utility/obj_life_counter.hpp>
#include "btree_internal.hpp"
#include "btree/btree_kv.hpp"

namespace homestore {
ENUM(locktype_t, uint8_t, NONE, READ, WRITE)

#pragma pack(1)
struct transient_hdr_t {
    mutable folly::SharedMutexReadPriority lock;
    sisl::atomic_counter< uint16_t > upgraders{0};

    /* these variables are accessed without taking lock and are not expected to change after init */
    uint8_t is_leaf_node{0};

    bool is_leaf() const { return (is_leaf_node != 0); }
};
#pragma pack()

static constexpr uint8_t BTREE_NODE_VERSION = 1;
static constexpr uint8_t BTREE_NODE_MAGIC = 0xab;

#pragma pack(1)
struct persistent_hdr_t {
    uint8_t magic{BTREE_NODE_MAGIC};
    uint8_t version{BTREE_NODE_VERSION};
    uint16_t checksum{0};

    bnodeid_t node_id{empty_bnodeid};
    bnodeid_t next_node{empty_bnodeid};

    uint32_t nentries : 27;
    uint32_t node_type : 3;
    uint32_t leaf : 1;
    uint32_t valid_node : 1;

    uint64_t node_gen{0};                     // Generation of this node, incremented on every update
    uint64_t link_version{0};                 // Version of the link between its parent, updated if structure changes
    BtreeLinkInfo::bnode_link_info edge_info; // Edge entry information

    persistent_hdr_t() : nentries{0}, leaf{0}, valid_node{1} {}
    std::string to_string() const {
        return fmt::format("magic={} version={} csum={} node_id={} next_node={} nentries={} node_type={} is_leaf={} "
                           "valid_node={} node_gen={} link_version={} edge_nodeid={}, edge_link_version={}",
                           magic, version, checksum, node_id, next_node, nentries, node_type, leaf, valid_node,
                           node_gen, link_version, edge_info.m_bnodeid, edge_info.m_link_version);
    }
};
#pragma pack()

template < typename K >
class BtreeNode : public sisl::ObjLifeCounter< BtreeNode< K > > {
    typedef std::pair< bool, uint32_t > node_find_result_t;

public:
    sisl::atomic_counter< int32_t > m_refcount{0};
    transient_hdr_t m_trans_hdr;
    uint8_t* m_phys_node_buf;

public:
    BtreeNode(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf) : m_phys_node_buf{node_buf} {
        if (init_buf) {
            new (node_buf) persistent_hdr_t{};
            set_leaf(is_leaf);
        } else {
            DEBUG_ASSERT_EQ(node_id(), id);
            DEBUG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC);
            DEBUG_ASSERT_EQ(version(), BTREE_NODE_VERSION);
        }
        m_trans_hdr.is_leaf_node = is_leaf;
    }
    virtual ~BtreeNode() { ((persistent_hdr_t*)m_phys_node_buf)->~persistent_hdr_t(); }

    // Identify if a node is a leaf node or not, from raw buffer, by just reading persistent_hdr_t
    static bool identify_leaf_node(uint8_t* buf) { return (r_cast< persistent_hdr_t* >(buf))->leaf; }

    node_find_result_t find(const BtreeKey& key, BtreeValue* outval, bool copy_val) const {
        LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "Magic mismatch on btree_node {}",
                         get_persistent_header_const()->to_string());

        auto [found, idx] = bsearch_node(key);
        if (idx == total_entries()) {
            if (!has_valid_edge() || is_leaf()) {
                DEBUG_ASSERT_EQ(found, false);
                return std::make_pair(found, idx);
            }
            if (outval) { *((BtreeLinkInfo*)outval) = get_edge_value(); }
        } else {
            if (outval) { get_nth_value(idx, outval, copy_val); }
        }
        return std::make_pair(found, idx);
    }

    template < typename V >
    uint32_t get_all(const BtreeKeyRange< K >& range, uint32_t max_count, uint32_t& start_idx, uint32_t& end_idx,
                     std::vector< std::pair< K, V > >* out_values = nullptr) const {
        LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "Magic mismatch on btree_node {}",
                         get_persistent_header_const()->to_string());
        auto count = 0U;
        bool sfound, efound;
        // Get the start index of the search range.
        std::tie(sfound, start_idx) = bsearch_node(range.start_key());
        if (sfound && !range.is_start_inclusive()) { ++start_idx; }
        if (start_idx == total_entries()) {
            end_idx = start_idx;
            if (is_leaf() || !has_valid_edge()) {
                return 0; // No result found
            } else {
                goto out;
            }
        }

        std::tie(efound, end_idx) = bsearch_node(range.end_key());
        if (efound && !range.is_end_inclusive()) {
            if (end_idx == 0) { return 0; }
            --end_idx;
        }
        if (end_idx == total_entries()) {
            DEBUG_ASSERT_GT(end_idx, 0); // At this point end_idx should never have been zero
            if (!has_valid_edge()) { --end_idx; }
        }

    out:
        count = std::min(end_idx - start_idx + 1, max_count);
        if (out_values) {
            /* get the keys and values */
            for (auto i{start_idx}; i < (start_idx + count); ++i) {
                add_nth_obj_to_list< V >(i, out_values, true);
            }
        }
        return count;
    }

    std::pair< bool, uint32_t > get_any(const BtreeKeyRange< K >& range, BtreeKey* out_key, BtreeValue* out_val,
                                        bool copy_key, bool copy_val) const {
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
        if (out_key) { *out_key = get_nth_key(result_idx, copy_key); }
        if (out_val) { get_nth_value(result_idx, out_val, copy_val); }
        return std::make_pair(true, result_idx);
    }

    bool put(const BtreeKey& key, const BtreeValue& val, btree_put_type put_type, BtreeValue* existing_val) {
        LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "Magic mismatch on btree_node {}",
                         get_persistent_header_const()->to_string());
        bool ret = true;

        const auto [found, idx] = find(key, nullptr, false);
        if (found && existing_val) { get_nth_value(idx, existing_val, true); }

        if (put_type == btree_put_type::INSERT_ONLY_IF_NOT_EXISTS) {
            if (found) {
                LOGDEBUG("Attempt to insert duplicate entry {}", key.to_string());
                return false;
            }
            ret = (insert(idx, key, val) == btree_status_t::success);
        } else if (put_type == btree_put_type::REPLACE_ONLY_IF_EXISTS) {
            if (!found) return false;
            update(idx, key, val);
        } else if (put_type == btree_put_type::REPLACE_IF_EXISTS_ELSE_INSERT) {
            (found) ? update(idx, key, val) : (void)insert(idx, key, val);
        } else if (put_type == btree_put_type::APPEND_ONLY_IF_EXISTS) {
            if (!found) return false;
            append(idx, key, val);
        } else if (put_type == btree_put_type::APPEND_IF_EXISTS_ELSE_INSERT) {
            (found) ? append(idx, key, val) : (void)insert(idx, key, val);
        } else {
            DEBUG_ASSERT(false, "Wrong put_type {}", put_type);
        }
        return ret;
    }

    virtual btree_status_t insert(const BtreeKey& key, const BtreeValue& val) {
        const auto [found, idx] = find(key, nullptr, false);
        DEBUG_ASSERT(!is_leaf() || (!found), "Invalid node"); // We do not support duplicate keys yet
        insert(idx, key, val);
        DEBUG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "{}", get_persistent_header_const()->to_string());
        return btree_status_t::success;
    }

    virtual bool remove_one(const BtreeKey& key, BtreeKey* outkey, BtreeValue* outval) {
        const auto [found, idx] = find(key, outval, true);
        if (found) {
            if (outkey) { *outkey = get_nth_key(idx, true); }
            remove(idx);
            LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "{}", get_persistent_header_const()->to_string());
        }
        return found;
    }

    virtual bool remove_any(const BtreeKeyRange< K >& range, BtreeKey* outkey, BtreeValue* outval) {
        const auto [found, idx] = get_any(range, outkey, outval, true, true);
        if (found) {
            remove(idx);
            LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "{}", get_persistent_header_const()->to_string());
        }
        return found;
    }

    /* Update the key and value pair and after update if outkey and outval are non-nullptr, it fills them with
     * the key and value it just updated respectively */
    virtual bool update_one(const BtreeKey& key, const BtreeValue& val, BtreeValue* outval) {
        const auto [found, idx] = find(key, outval, true);
        if (found) {
            update(idx, val);
            LOGMSG_ASSERT((magic() == BTREE_NODE_MAGIC), "{}", get_persistent_header_const()->to_string());
        }
        return found;
    }

    void get_adjacent_indicies(uint32_t cur_ind, std::vector< uint32_t >& indices_list, uint32_t max_indices) const {
        uint32_t i = 0;
        uint32_t start_ind;
        uint32_t end_ind;
        uint32_t nentries = total_entries();

        auto max_ind = ((max_indices / 2) - 1 + (max_indices % 2));
        end_ind = cur_ind + (max_indices / 2);
        if (cur_ind < max_ind) {
            end_ind += max_ind - cur_ind;
            start_ind = 0;
        } else {
            start_ind = cur_ind - max_ind;
        }

        for (i = start_ind; (i <= end_ind) && (indices_list.size() < max_indices); ++i) {
            if (i == nentries) {
                if (has_valid_edge()) { indices_list.push_back(i); }
                break;
            } else {
                indices_list.push_back(i);
            }
        }
    }

    K min_of(const K& cmp_key, uint32_t cmp_ind, bool& is_cmp_key_lesser) const {
        K min_key;
        int x{-1};
        is_cmp_key_lesser = false;

        if (cmp_ind < total_entries()) {
            min_key = get_nth_key(cmp_ind, false);
            x = cmp_key.compare(min_key);
        }

        if (x < 0) {
            min_key = cmp_key;
            is_cmp_key_lesser = true;
        }
        return min_key;
    }

    /*BtreeKeyRange get_subrange(const BtreeKeyRange< K >& inp_range, int upto_ind) const {
#ifndef NDEBUG
        if (upto_ind > 0) {
            // start of input range should always be more then the key in curr_ind - 1
            DEBUG_ASSERT_LE(get_nth_key(upto_ind - 1, false).compare(inp_range.start_key()), 0, "[node={}]",
                            to_string());
        }
#endif

        // find end of subrange
        bool end_inc = true;
        K end_key;

        if (upto_ind < int_cast(total_entries())) {
            end_key = get_nth_key(upto_ind, false);
            if (end_key.compare(inp_range.end_key()) >= 0) {
                // this is last index to process as end of range is smaller then key in this node
                end_key = inp_range.end_key();
                end_inc = inp_range.is_end_inclusive();
            } else {
                end_inc = true;
            }
        } else {
            // it is the edge node. end key is the end of input range
            LOGMSG_ASSERT_EQ(has_valid_edge(), true, "node={}", to_string());
            end_key = inp_range.end_key();
            end_inc = inp_range.is_end_inclusive();
        }

        BtreeKeyRangeSafe< K > subrange{inp_range.start_key(), inp_range.is_start_inclusive(), end_key, end_inc};
        RELEASE_ASSERT_LE(subrange.start_key().compare(subrange.end_key()), 0, "[node={}]", to_string());
        RELEASE_ASSERT_LE(subrange.start_key().compare(inp_range.end_key()), 0, "[node={}]", to_string());
        return subrange;
    } */

    K get_last_key() const {
        if (total_entries() == 0) { return K{}; }
        return get_nth_key(total_entries() - 1, true);
    }

    K get_first_key() const { return get_nth_key(0, true); }

    bool validate_key_order() const {
        for (auto i = 1u; i < total_entries(); ++i) {
            auto prevKey = get_nth_key(i - 1, false);
            auto curKey = get_nth_key(i, false);
            if (prevKey.compare(curKey) >= 0) {
                DEBUG_ASSERT(false, "Order check failed at entry={}", i);
                return false;
            }
        }
        return true;
    }

    virtual BtreeLinkInfo get_edge_value() const { return BtreeLinkInfo{edge_id(), link_version()}; }

    virtual void set_edge_value(const BtreeValue& v) {
        const auto b = v.serialize();
        auto l = r_cast< BtreeLinkInfo::bnode_link_info* >(b.bytes);
        ASSERT_EQ(b.size, sizeof(BtreeLinkInfo::bnode_link_info));
        set_edge_info(*l);
    }

    void invalidate_edge() { set_edge_id(empty_bnodeid); }

    uint32_t total_entries() const { return get_persistent_header_const()->nentries; }
    // uint32_t total_entries() const { return (has_valid_edge() ? total_entries() + 1 : total_entries()); }

    void lock(locktype_t l) const {
        if (l == locktype_t::READ) {
            m_trans_hdr.lock.lock_shared();
        } else if (l == locktype_t::WRITE) {
            m_trans_hdr.lock.lock();
        }
    }

    void unlock(locktype_t l) const {
        if (l == locktype_t::READ) {
            m_trans_hdr.lock.unlock_shared();
        } else if (l == locktype_t::WRITE) {
            m_trans_hdr.lock.unlock();
        }
    }

    void lock_upgrade() {
        m_trans_hdr.upgraders.increment(1);
        this->unlock(locktype_t::READ);
        this->lock(locktype_t::WRITE);
        m_trans_hdr.upgraders.decrement(1);
    }

    void lock_acknowledge() { m_trans_hdr.upgraders.decrement(1); }
    bool any_upgrade_waiters() const { return (!m_trans_hdr.upgraders.testz()); }

    bool can_accomodate(const BtreeConfig& cfg, uint32_t key_size, uint32_t value_size) const {
        return ((key_size + value_size + get_record_size()) <= available_size(cfg));
    }

    template < typename V >
    void add_nth_obj_to_list(uint32_t ind, std::vector< std::pair< K, V > >* vec, bool copy) const {
        std::pair< K, V > kv;
        vec->emplace_back(kv);

        auto* pkv = &vec->back();
        if (ind == total_entries() && !is_leaf()) {
            pkv->second = edge_value_internal< V >();
        } else {
            pkv->first = get_nth_key(ind, copy);
            get_nth_value(ind, &pkv->second, copy);
        }
    }

public:
    // Public method which needs to be implemented by variants
    virtual uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, BtreeNode& other_node, uint32_t nentries) = 0;
    virtual uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, BtreeNode& other_node, uint32_t size) = 0;
    virtual uint32_t num_entries_by_size(uint32_t start_idx, uint32_t size) const = 0;
    virtual uint32_t copy_by_size(const BtreeConfig& cfg, const BtreeNode& other_node, uint32_t start_idx,
                                  uint32_t size) = 0;
    virtual uint32_t copy_by_entries(const BtreeConfig& cfg, const BtreeNode& other_node, uint32_t start_idx,
                                     uint32_t nentries) = 0;
    /*virtual uint32_t move_in_from_right_by_entries(const BtreeConfig& cfg, BtreeNode& other_node,
                                                   uint32_t nentries) = 0;
    virtual uint32_t move_in_from_right_by_size(const BtreeConfig& cfg, BtreeNode& other_node, uint32_t size) = 0;*/
    virtual uint32_t available_size(const BtreeConfig& cfg) const = 0;
    virtual std::string to_string(bool print_friendly = false) const = 0;
    virtual void get_nth_value(uint32_t ind, BtreeValue* out_val, bool copy) const = 0;
    virtual K get_nth_key(uint32_t ind, bool copykey) const = 0;

    virtual btree_status_t insert(uint32_t ind, const BtreeKey& key, const BtreeValue& val) = 0;
    virtual void remove(uint32_t ind) { remove(ind, ind); }
    virtual void remove(uint32_t ind_s, uint32_t ind_e) = 0;
    virtual void remove_all(const BtreeConfig& cfg) = 0;
    virtual void update(uint32_t ind, const BtreeValue& val) = 0;
    virtual void update(uint32_t ind, const BtreeKey& key, const BtreeValue& val) = 0;
    virtual void append(uint32_t ind, const BtreeKey& key, const BtreeValue& val) = 0;

    virtual uint32_t get_nth_obj_size(uint32_t ind) const = 0;
    virtual uint16_t get_record_size() const = 0;
    virtual int compare_nth_key(const BtreeKey& cmp_key, uint32_t ind) const = 0;

    // Method just to please compiler
    template < typename V >
    V edge_value_internal() const {
        return V{edge_id()};
    }

private:
    node_find_result_t bsearch_node(const BtreeKey& key) const {
        DEBUG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC);
        auto [found, idx] = bsearch(-1, total_entries(), key);
        if (found) { DEBUG_ASSERT_LT(idx, total_entries()); }

        return std::make_pair(found, idx);
    }

    node_find_result_t bsearch(int start, int end, const BtreeKey& key) const {
        int mid = 0;
        bool found{false};
        uint32_t end_of_search_index{0};

        if ((end - start) <= 1) { return std::make_pair(found, end_of_search_index); }
        while ((end - start) > 1) {
            mid = start + (end - start) / 2;
            DEBUG_ASSERT(mid >= 0 && mid < int_cast(total_entries()), "Invalid mid={}", mid);
            int x = compare_nth_key(key, mid);
            if (x == 0) {
                found = true;
                end = mid;
                break;
            } else if (x > 0) {
                end = mid;
            } else {
                start = mid;
            }
        }

        return std::make_pair(found, end);
    }

public:
    persistent_hdr_t* get_persistent_header() { return r_cast< persistent_hdr_t* >(m_phys_node_buf); }
    const persistent_hdr_t* get_persistent_header_const() const {
        return r_cast< const persistent_hdr_t* >(m_phys_node_buf);
    }
    uint8_t* node_data_area() { return (m_phys_node_buf + sizeof(persistent_hdr_t)); }
    const uint8_t* node_data_area_const() const { return (m_phys_node_buf + sizeof(persistent_hdr_t)); }

    uint8_t magic() const { return get_persistent_header_const()->magic; }
    void set_magic() { get_persistent_header()->magic = BTREE_NODE_MAGIC; }

    uint8_t version() const { return get_persistent_header_const()->version; }
    uint16_t checksum() const { return get_persistent_header_const()->checksum; }
    void init_checksum() { get_persistent_header()->checksum = 0; }

    void set_node_id(bnodeid_t id) { get_persistent_header()->node_id = id; }
    bnodeid_t node_id() const { return get_persistent_header_const()->node_id; }

#ifndef NO_CHECKSUM
    void set_checksum(const BtreeConfig& cfg) {
        get_persistent_header()->checksum = crc16_t10dif(init_crc_16, node_data_area_const(), cfg.node_data_size());
    }

    bool verify_node(const BtreeConfig& cfg) const {
        HS_DEBUG_ASSERT_EQ(is_valid_node(), true, "verifying invalide node {}!",
                           get_persistent_header_const()->to_string());
        auto exp_checksum = crc16_t10dif(init_crc_16, node_data_area_const(), cfg.node_data_size());
        return ((magic() == BTREE_NODE_MAGIC) && (checksum() == exp_checksum));
    }
#endif

    bool is_leaf() const { return get_persistent_header_const()->leaf; }
    btree_node_type get_node_type() const {
        return s_cast< btree_node_type >(get_persistent_header_const()->node_type);
    }

    void set_total_entries(uint32_t n) { get_persistent_header()->nentries = n; }
    void inc_entries() { ++get_persistent_header()->nentries; }
    void dec_entries() { --get_persistent_header()->nentries; }

    void add_entries(uint32_t addn) { get_persistent_header()->nentries += addn; }
    void sub_entries(uint32_t subn) { get_persistent_header()->nentries -= subn; }

    void set_leaf(bool leaf) { get_persistent_header()->leaf = leaf; }
    void set_node_type(btree_node_type t) { get_persistent_header()->node_type = uint32_cast(t); }
    uint64_t node_gen() const { return get_persistent_header_const()->node_gen; }
    void inc_gen() { get_persistent_header()->node_gen++; }
    void set_gen(uint64_t g) { get_persistent_header()->node_gen = g; }
    uint64_t link_version() const { return get_persistent_header_const()->link_version; }
    void set_link_version(uint64_t version) { return get_persistent_header()->link_version = version; }
    void inc_link_version() { ++(get_persistent_header()->link_version); }

    void set_valid_node(bool valid) { get_persistent_header()->valid_node = (valid ? 1 : 0); }
    bool is_valid_node() const { return get_persistent_header_const()->valid_node; }

    BtreeLinkInfo link_info() const { return BtreeLinkInfo{node_id(), link_version()}; }

    uint32_t occupied_size(const BtreeConfig& cfg) const { return (cfg.node_data_size() - available_size(cfg)); }
    bool is_merge_needed(const BtreeConfig& cfg) const {
#if 0
#ifdef _PRERELEASE
        if (homestore_flip->test_flip("btree_merge_node") && occupied_size(cfg) < node_area_size(cfg)) {
            return true;
        }

        auto ret = homestore_flip->get_test_flip< uint64_t >("btree_merge_node_pct");
        if (ret && occupied_size(cfg) < (ret.get() * node_area_size(cfg) / 100)) { return true; }
#endif
#endif
        return (occupied_size(cfg) < cfg.suggested_min_size());
    }

    bnodeid_t next_bnode() const { return get_persistent_header_const()->next_node; }
    void set_next_bnode(bnodeid_t b) { get_persistent_header()->next_node = b; }

    bnodeid_t edge_id() const { return get_persistent_header_const()->edge_info.m_bnodeid; }
    void set_edge_id(bnodeid_t edge) { get_persistent_header()->edge_info.m_bnodeid = edge; }

    BtreeLinkInfo::bnode_link_info edge_info() const { return get_persistent_header_const()->edge_info; }
    void set_edge_info(const BtreeLinkInfo::bnode_link_info& info) { get_persistent_header()->edge_info = info; }

    bool has_valid_edge() const {
        if (is_leaf()) { return false; }
        return (edge_id() != empty_bnodeid);
    }
};

template < typename K, typename V >
struct btree_locked_node_info {
    BtreeNode< K >* node;
    Clock::time_point start_time;
    const char* fname;
    int line;

    void dump() const { LOGINFO("node locked by file: {}, line: {}", fname, line); }
};

} // namespace homestore
