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
#include <iostream>
#include <queue>
#include <iomgr/fiber_lib.hpp>

#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/utility/obj_life_counter.hpp>
#include "btree_internal.hpp"
#include <homestore/btree/btree_kv.hpp>
#include <homestore/crc.h>

namespace homestore {
ENUM(locktype_t, uint8_t, NONE, READ, WRITE)

#pragma pack(1)
struct transient_hdr_t {
    mutable iomgr::FiberManagerLib::shared_mutex lock;
    sisl::atomic_counter< uint16_t > upgraders{0};

    /* these variables are accessed without taking lock and are not expected to change after init */
    uint8_t leaf_node{0};
    uint64_t max_keys_in_node{0};
    uint64_t min_keys_in_node{0}; // to specify the threshold for triggering merge

    bool is_leaf() const { return (leaf_node != 0); }
};
#pragma pack()

static constexpr uint8_t BTREE_NODE_VERSION = 1;
static constexpr uint8_t BTREE_NODE_MAGIC = 0xab;

#pragma pack(1)
struct persistent_hdr_t {
    uint8_t magic{BTREE_NODE_MAGIC};     // offset=0
    uint8_t version{BTREE_NODE_VERSION}; // offset=1
    uint16_t checksum{0};                // offset=2

    uint32_t nentries : 30; // offset 4
    uint32_t leaf : 1;
    uint32_t node_deleted : 1;

    bnodeid_t node_id{empty_bnodeid};   // offset=8
    bnodeid_t next_node{empty_bnodeid}; // offset=16

    uint64_t node_gen{0};     // offset=24: Generation of this node, incremented on every update
    uint64_t link_version{0}; // offset=32: Version of the link between its parent, updated if structure changes
    BtreeLinkInfo::bnode_link_info edge_info; // offset=40: Edge entry information

    int64_t modified_cp_id{-1};   // offset=56: Checkpoint ID of the last modification of this node
    uint16_t level;               // offset=64: Level of the node within the tree
    uint16_t node_size;           // offset=66: Size of node, max 64K
    uint8_t node_type;            // offset=68: Type of the node (simple vs varlen etc..)
    uint8_t reserved[3]{0, 0, 0}; // offset=69-72: Reserved

    persistent_hdr_t() : nentries{0}, leaf{0}, node_deleted{0} {}
    std::string to_string() const {
        auto snext = (next_node == empty_bnodeid) ? "" : " next=" + std::to_string(next_node);
        auto sedge = (edge_info.m_bnodeid == empty_bnodeid)
            ? ""
            : fmt::format(" edge={}.{}", edge_info.m_bnodeid, edge_info.m_link_version);
        return fmt::format("magic={} version={} csum={} node_id={}{} nentries={} node_type={} is_leaf={} "
                           "node_deleted={} node_gen={} modified_cp_id={} link_version={}{} level={} ",
                           magic, version, checksum, node_id, snext, nentries, node_type, leaf, node_deleted, node_gen,
                           modified_cp_id, link_version, sedge, level);
    }

    std::string to_compact_string() const {
        auto snext = (next_node == empty_bnodeid) ? "" : " next=" + std::to_string(next_node);
        auto sedge = (edge_info.m_bnodeid == empty_bnodeid)
            ? ""
            : fmt::format(" edge={}.{}", edge_info.m_bnodeid, edge_info.m_link_version);
        return fmt::format("id={}{}{} {} level={} nentries={} mod_cp={}{}", node_id, snext, sedge,
                           leaf ? "LEAF" : "INTERIOR", level, nentries, modified_cp_id,
                           node_deleted == 0x1 ? "  Deleted" : " LIVE");
    }
};
#pragma pack()

class BtreeNode : public sisl::ObjLifeCounter< BtreeNode > {
    using node_find_result_t = std::pair< bool, uint32_t >;

public:
    sisl::atomic_counter< int32_t > m_refcount{0};
    transient_hdr_t m_trans_hdr;
    uint8_t* m_phys_node_buf;

public:
    BtreeNode(uint8_t* node_buf, bnodeid_t id, bool init_buf, bool is_leaf, BtreeConfig const& cfg) :
            m_phys_node_buf{node_buf} {
        if (init_buf) {
            new (node_buf) persistent_hdr_t{};
            set_node_id(id);
            set_leaf(is_leaf);
            set_node_size(cfg.node_size());
        } else {
            DEBUG_ASSERT_EQ(node_id(), id);
            DEBUG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC);
            DEBUG_ASSERT_EQ(version(), BTREE_NODE_VERSION);
        }
        m_trans_hdr.leaf_node = is_leaf;
#ifdef _PRERELEASE
        m_trans_hdr.max_keys_in_node = cfg.m_max_keys_in_node;
        m_trans_hdr.min_keys_in_node = cfg.m_min_keys_in_node;
#endif
    }
    virtual ~BtreeNode() = default;

    // Identify if a node is a leaf node or not, from raw buffer, by just reading persistent_hdr_t
    static bool identify_leaf_node(uint8_t* buf) { return (r_cast< persistent_hdr_t* >(buf))->leaf; }
    static std::string to_string_buf(uint8_t* buf) { return (r_cast< persistent_hdr_t* >(buf))->to_compact_string(); }
    static BtreeLinkInfo::bnode_link_info identify_edge_info(uint8_t* buf) {
        return (r_cast< persistent_hdr_t* >(buf))->edge_info;
    }

    static bool is_valid_node(sisl::blob const& buf) {
        auto phdr = r_cast< persistent_hdr_t const* >(buf.cbytes());
        if ((phdr->magic != BTREE_NODE_MAGIC) || (phdr->version != BTREE_NODE_VERSION)) { return false; }
        if ((uint32_cast(phdr->node_size) + 1) != buf.size()) { return false; }
        if (phdr->node_id == empty_bnodeid) { return false; }

        auto const exp_checksum = crc16_t10dif(bt_init_crc_16, (buf.cbytes() + sizeof(persistent_hdr_t)),
                                               buf.size() - sizeof(persistent_hdr_t));
        if (phdr->checksum != exp_checksum) { return false; }

        return true;
    }

    static void revert_node_delete(uint8_t* buf) {
        auto phdr = r_cast< persistent_hdr_t* >(buf);
        phdr->node_deleted = 0x0;
    }

    static int64_t get_modified_cp_id(uint8_t* buf) {
        auto phdr = r_cast< persistent_hdr_t const* >(buf);
        return phdr->modified_cp_id;
    }

    /// @brief Finds the index of the entry with the specified key in the node.
    ///
    /// This method performs a binary search on the node to find the index of the entry with the specified key.
    /// If the key is not found in the node, the method returns the index of the first entry greater than the key.
    ///
    /// @param key The key to search for.
    /// @param outval [optional] A pointer to a BtreeValue object to store the value associated with the key.
    /// @param copy_val If outval is non-null, is the value deserialized from node needs to be copy of the btree
    /// internal buffer. Safest option is to set this true, it is ok to set it false, if find() is called and value is
    /// accessed and used before subsequent node modification.
    /// @return A pair of values representing the result of the search.
    ///         The first value is a boolean indicating whether the key was found in the node.
    ///         The second value is an integer representing the index of the entry with the specified key or the index
    ///         of the first entry greater than the key.
    node_find_result_t find(BtreeKey const& key, BtreeValue* outval, bool copy_val) const {
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

    template < typename K >
    bool match_range(BtreeKeyRange< K > const& range, uint32_t& start_idx, uint32_t& end_idx) const {
        LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "Magic mismatch on btree_node {}",
                         get_persistent_header_const()->to_string());

        bool sfound, efound;
        // Get the start index of the search range.
        std::tie(sfound, start_idx) = this->bsearch_node(range.start_key());
        if (sfound && !range.is_start_inclusive()) {
            ++start_idx;
            sfound = false;
        }

        if (start_idx == this->total_entries()) {
            // We are already at the end of search, we should return this as the only entry
            end_idx = start_idx;
            return (!is_leaf() && this->has_valid_edge()); // No result found unless its a edge node
        }

        // Get the end index of the search range.
        std::tie(efound, end_idx) = this->bsearch_node(range.end_key());
        if (is_leaf() || ((end_idx == this->total_entries()) && !has_valid_edge())) {
            // Binary search will always return the index as the first key that is >= given key (end_key in this
            // case). Our goal here in leaf node is to find the last key that is less than in case of non_inclusive
            // search or less than or equal in case of inclusive search.
            if (!efound || !range.is_end_inclusive()) {
                // If we are already on the first key, then obviously nothing has been matched.
                if (end_idx == 0) { return false; }
                --end_idx;
            }

            // If we point to same start and end without any match, it is hitting unavailable range
            if (start_idx > end_idx) { return false; }
        }

        return true;
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
            if (outkey) { get_nth_key_internal(idx, *outkey, true); }
            remove(idx);
            LOGMSG_ASSERT_EQ(magic(), BTREE_NODE_MAGIC, "{}", get_persistent_header_const()->to_string());
        }
        return found;
    }

    template < typename K >
    bool remove_any(const BtreeKeyRange< K >& range, BtreeKey* outkey, BtreeValue* outval) {
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

    template < typename K >
    K get_nth_key(uint32_t idx, bool copy) const {
        K k;
        get_nth_key_internal(idx, k, copy);
        return k;
    }

    template < typename K >
    K get_last_key() const {
        if (total_entries() == 0) { return K{}; }
        return get_nth_key< K >(total_entries() - 1, true);
    }

    template < typename K >
    K get_first_key() const {
        if (total_entries() == 0) { return K{}; }
        return get_nth_key< K >(0, true);
    }

    template < typename K >
    bool validate_key_order() const {
        for (auto i = 1u; i < total_entries(); ++i) {
            auto prevKey = get_nth_key< K >(i - 1, false);
            auto curKey = get_nth_key< K >(i, false);
            if (prevKey.compare(curKey) >= 0) {
                DEBUG_ASSERT(false, "Order check failed at entry={}", i);
                return false;
            }
        }
        return true;
    }

    virtual BtreeLinkInfo get_edge_value() const { return BtreeLinkInfo{edge_id(), edge_link_version()}; }

    virtual void set_edge_value(const BtreeValue& v) {
        auto const b = v.serialize();
        auto const l = r_cast< BtreeLinkInfo::bnode_link_info const* >(b.cbytes());
        DEBUG_ASSERT_EQ(b.size(), sizeof(BtreeLinkInfo::bnode_link_info));
        set_edge_info(*l);
    }

    void invalidate_edge() { set_edge_id(empty_bnodeid); }

    uint32_t total_entries() const { return get_persistent_header_const()->nentries; }

    void set_level(uint16_t l) { get_persistent_header()->level = l; }
    uint16_t level() const { return get_persistent_header_const()->level; }

    // uint32_t total_entries() const { return (has_valid_edge() ? total_entries() + 1 : total_entries()); }
    uint64_t max_keys_in_node() const { return m_trans_hdr.max_keys_in_node; }
    uint64_t min_keys_in_node() const { return m_trans_hdr.min_keys_in_node; }

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

    template < typename K, typename V >
    std::string to_custom_string(to_string_cb_t< K, V > const& cb) const {
        std::string snext =
            (this->next_bnode() == empty_bnodeid) ? "" : fmt::format(" next_node={}", this->next_bnode());
        auto str =
            fmt::format("id={}.{} level={} nEntries={} {}{} node_gen={} {} ", this->node_id(), this->link_version(),
                        this->level(), this->total_entries(), (this->is_leaf() ? "LEAF" : "INTERIOR"), snext,
                        this->node_gen(), this->is_node_deleted() ? " **DELETED**" : "");
        if (this->has_valid_edge()) {
            fmt::format_to(std::back_inserter(str), " edge={}.{}", this->edge_info().m_bnodeid,
                           this->edge_info().m_link_version);
        }

        if (this->total_entries() == 0) {
            fmt::format_to(std::back_inserter(str), " [EMPTY] ");
            return str;
        } else if (this->is_leaf()) {
            std::vector< std::pair< K, V > > entries;
            for (uint32_t i{0}; i < this->total_entries(); ++i) {
                V v;
                get_nth_value(i, &v, false);
                entries.emplace_back(std::make_pair(get_nth_key< K >(i, false), v));
            }
            fmt::format_to(std::back_inserter(str), " Keys=[{}]", cb(entries));
            return str;
        } else {
            fmt::format_to(std::back_inserter(str), " Keys=[");
            for (uint32_t i{0}; i < this->total_entries(); ++i) {
                fmt::format_to(std::back_inserter(str), "{}{}", get_nth_key< K >(i, false).to_string(),
                               (i == this->total_entries() - 1) ? "" : ", ");
            }
            fmt::format_to(std::back_inserter(str), "]");
        }
        return str;
    }

public:
    // Public method which needs to be implemented by variants
    virtual btree_status_t insert(uint32_t ind, const BtreeKey& key, const BtreeValue& val) = 0;
    virtual void remove(uint32_t ind) { remove(ind, ind); }
    virtual void remove(uint32_t ind_s, uint32_t ind_e) = 0;
    virtual void remove_all(const BtreeConfig& cfg) = 0;
    virtual void update(uint32_t ind, const BtreeValue& val) = 0;
    virtual void update(uint32_t ind, const BtreeKey& key, const BtreeValue& val) = 0;

    virtual uint32_t move_out_to_right_by_entries(const BtreeConfig& cfg, BtreeNode& other_node, uint32_t nentries) = 0;
    virtual uint32_t move_out_to_right_by_size(const BtreeConfig& cfg, BtreeNode& other_node, uint32_t size) = 0;
    virtual uint32_t copy_by_size(const BtreeConfig& cfg, const BtreeNode& other_node, uint32_t start_idx,
                                  uint32_t size) = 0;
    virtual uint32_t copy_by_entries(const BtreeConfig& cfg, const BtreeNode& other_node, uint32_t start_idx,
                                     uint32_t nentries) = 0;
    /*virtual uint32_t move_in_from_right_by_entries(const BtreeConfig& cfg, BtreeNode& other_node,
                                                   uint32_t nentries) = 0;
    virtual uint32_t move_in_from_right_by_size(const BtreeConfig& cfg, BtreeNode& other_node, uint32_t size) = 0;*/

    virtual uint32_t available_size() const = 0;
    virtual bool has_room_for_put(btree_put_type put_type, uint32_t key_size, uint32_t value_size) const = 0;
    virtual uint32_t num_entries_by_size(uint32_t start_idx, uint32_t size) const = 0;

    virtual int compare_nth_key(const BtreeKey& cmp_key, uint32_t ind) const = 0;
    virtual void get_nth_key_internal(uint32_t ind, BtreeKey& out_key, bool copykey) const = 0;
    virtual uint32_t get_nth_key_size(uint32_t ind) const = 0;
    virtual void get_nth_value(uint32_t ind, BtreeValue* out_val, bool copy) const = 0;
    virtual uint32_t get_nth_value_size(uint32_t ind) const = 0;
    virtual uint32_t get_nth_obj_size(uint32_t ind) const { return get_nth_key_size(ind) + get_nth_value_size(ind); }

    // Method just to please compiler
    template < typename V >
    V edge_value_internal() const {
        return V{edge_id()};
    }

    virtual std::string to_string(bool print_friendly = false) const = 0;
    virtual std::string to_dot_keys() const = 0;

protected:
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
    void update_phys_buf(uint8_t* buf) { m_phys_node_buf = buf; }
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

    void set_checksum() {
        get_persistent_header()->checksum = crc16_t10dif(bt_init_crc_16, node_data_area_const(), node_data_size());
    }

    bool verify_node() const {
        auto exp_checksum = crc16_t10dif(bt_init_crc_16, node_data_area_const(), node_data_size());
        return ((magic() == BTREE_NODE_MAGIC) && (checksum() == exp_checksum));
    }

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
    void set_node_size(uint32_t size) { get_persistent_header()->node_size = s_cast< uint16_t >(size - 1); }
    uint64_t node_gen() const { return get_persistent_header_const()->node_gen; }
    uint32_t node_size() const { return s_cast< uint32_t >(get_persistent_header_const()->node_size) + 1; }
    uint32_t node_data_size() const { return node_size() - sizeof(persistent_hdr_t); }

    void inc_gen() { get_persistent_header()->node_gen++; }
    void set_gen(uint64_t g) { get_persistent_header()->node_gen = g; }
    uint64_t link_version() const { return get_persistent_header_const()->link_version; }
    void set_link_version(uint64_t version) { get_persistent_header()->link_version = version; }
    void inc_link_version() { ++(get_persistent_header()->link_version); }

    void set_node_deleted() { get_persistent_header()->node_deleted = 0x1; }
    bool is_node_deleted() const { return (get_persistent_header_const()->node_deleted == 0x1); }

    BtreeLinkInfo link_info() const { return BtreeLinkInfo{node_id(), link_version()}; }

    virtual uint32_t occupied_size() const { return (node_data_size() - available_size()); }
    bool is_merge_needed(const BtreeConfig& cfg) const {
        if (level() > cfg.m_max_merge_level) { return false; }
#ifdef _PRERELEASE
        if (min_keys_in_node()) { return total_entries() < min_keys_in_node(); }
#endif
        return (occupied_size() < cfg.suggested_min_size());
    }

    bnodeid_t next_bnode() const { return get_persistent_header_const()->next_node; }
    void set_next_bnode(bnodeid_t b) { get_persistent_header()->next_node = b; }

    bnodeid_t edge_id() const { return get_persistent_header_const()->edge_info.m_bnodeid; }
    void set_edge_id(bnodeid_t edge) { get_persistent_header()->edge_info.m_bnodeid = edge; }
    uint64_t edge_link_version() const { return get_persistent_header_const()->edge_info.m_link_version; }
    void set_edge_link_version(uint64_t link_version) {
        get_persistent_header()->edge_info.m_link_version = link_version;
    }

    BtreeLinkInfo::bnode_link_info edge_info() const { return get_persistent_header_const()->edge_info; }
    void set_edge_info(const BtreeLinkInfo::bnode_link_info& info) { get_persistent_header()->edge_info = info; }

    bool has_valid_edge() const {
        if (is_leaf()) { return false; }
        return (edge_id() != empty_bnodeid);
    }

    void set_modified_cp_id(int64_t id) { get_persistent_header()->modified_cp_id = id; }
    friend void intrusive_ptr_add_ref(BtreeNode* node) { node->m_refcount.increment(1); }

    friend void intrusive_ptr_release(BtreeNode* node) {
        if (node->m_refcount.decrement_testz(1)) { delete node; }
    }
};

struct btree_locked_node_info {
    BtreeNode* node;
    Clock::time_point start_time;
    const char* fname;
    int line;

    void dump() const { LOGINFO("node locked by file: {}, line: {}", fname, line); }
};

} // namespace homestore
