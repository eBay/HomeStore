/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
/*
 * btree_internal.h
 *
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once

#include <atomic>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/control/if.hpp>
#include <boost/preprocessor/facilities/empty.hpp>
#include <boost/preprocessor/facilities/identity.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <boost/vmd/is_empty.hpp>

#include <sisl/fds/obj_allocator.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/fds/freelist_allocator.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/utility/obj_life_counter.hpp>

#include "engine/blkalloc/blk.h"
#include "engine/common/error.h"
#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/homestore_base.hpp"
#include "engine/blkalloc/blkalloc_cp.hpp"

ENUM(btree_status_t, uint32_t, success, not_found, item_found, closest_found, closest_removed, retry, has_more,
     read_failed, write_failed, stale_buf, refresh_failed, put_failed, space_not_avail, split_failed, insert_failed,
     cp_mismatch, merge_not_required, merge_failed, replay_not_needed, fast_path_not_possible, resource_full,
     update_debug_bm_failed, crc_mismatch);

typedef enum {
    READ_NONE = 0,
    READ_FIRST = 1,
    READ_SECOND = 2,
    READ_BOTH = 3,
} diff_read_next_t;

namespace homestore {
struct blkalloc_cp_id;
}

/* We should always find the child smaller or equal then  search key in the interior nodes. */
#ifndef NDEBUG
#define ASSERT_IS_VALID_INTERIOR_CHILD_INDX(ret, node)                                                                 \
    DEBUG_ASSERT(((ret.end_of_search_index < (int)node->get_total_entries()) || node->has_valid_edge()),               \
                 "Is_valid_interior_child_check_failed: end_of_search_index={} total_entries={}, edge_valid={}",       \
                 ret.end_of_search_index, node->get_total_entries(), node->has_valid_edge())
#else
#define ASSERT_IS_VALID_INTERIOR_CHILD_INDX(ret, node)
#endif

#define THIS_BT_LOG(level, mod, node, msg, ...)                                                                        \
    HS_DETAILED_LOG(level, mod, , "btree", m_btree_cfg.get_name(),                                                     \
                    BOOST_PP_IF(BOOST_VMD_IS_EMPTY(node), BOOST_PP_EMPTY, BOOST_PP_IDENTITY("node"))(),                \
                    node->to_string(), msg, ##__VA_ARGS__)

#define THIS_BT_CP_LOG(level, cp_id, msg, ...)                                                                         \
    HS_PERIODIC_DETAILED_LOG(level, cp, "cp", cp_id, "btree", m_btree_cfg.get_name(), msg, ##__VA_ARGS__)

#define BT_ASSERT(assert_type, cond, node, ...)                                                                        \
    HS_DETAILED_ASSERT(assert_type, cond, , "btree", m_btree_cfg.get_name(),                                           \
                       BOOST_PP_IF(BOOST_VMD_IS_EMPTY(node), BOOST_PP_EMPTY, BOOST_PP_IDENTITY("node"))(),             \
                       node->to_string(), ##__VA_ARGS__)
#define BT_ASSERT_CMP(assert_type, val1, cmp, val2, node, ...)                                                         \
    HS_DETAILED_ASSERT_CMP(assert_type, val1, cmp, val2, , "btree", m_btree_cfg.get_name(),                            \
                           BOOST_PP_IF(BOOST_VMD_IS_EMPTY(node), BOOST_PP_EMPTY, BOOST_PP_IDENTITY("node"))(),         \
                           node->to_string(), ##__VA_ARGS__)

#define BT_DBG_ASSERT(...) BT_ASSERT(DEBUG_ASSERT_FMT, __VA_ARGS__)
#define BT_REL_ASSERT(...) BT_ASSERT(RELEASE_ASSERT_FMT, __VA_ARGS__)
#define BT_LOG_ASSERT(...) BT_ASSERT(LOGMSG_ASSERT_FMT, __VA_ARGS__)

#define BT_DBG_ASSERT_CMP(...) BT_ASSERT_CMP(DEBUG_ASSERT_CMP, ##__VA_ARGS__)
#define BT_REL_ASSERT_CMP(...) BT_ASSERT_CMP(RELEASE_ASSERT_CMP, ##__VA_ARGS__)
#define BT_LOG_ASSERT_CMP(...) BT_ASSERT_CMP(RELEASE_ASSERT_CMP, ##__VA_ARGS__)
//#define BT_LOG_ASSERT_CMP(...) BT_ASSERT_CMP(LOGMSG, ##__VA_ARGS__)

#define MAX_ADJANCENT_INDEX 3

// clang-format off
/* Journal entry of a btree
 *---------------------------------------------------------------------------------------------------------------------------------------------
 * |  Journal_entry_hdr | list of old node IDs | list of stale node IDs | list of new node IDs | list of new node gen | list of modified keys |
 *---------------------------------------------------------------------------------------------------------------------------------------------
 */
// clang-format on
VENUM(journal_op, uint8_t, BTREE_SPLIT = 1, BTREE_MERGE = 2, BTREE_CREATE = 3);

#define INVALID_SEQ_ID -1
struct btree_cp;
using btree_cp_ptr = boost::intrusive_ptr< btree_cp >;
using cp_comp_callback = std::function< void(const btree_cp_ptr& bcp) >;
using bnodeid_t = uint64_t;
static constexpr bnodeid_t empty_bnodeid = std::numeric_limits< bnodeid_t >::max();

using namespace homestore;
struct btree_cp_sb {
    seq_id_t active_seqid = -1;
    int64_t cp_id = -1;
    int64_t blkalloc_cp_id = -1;
    int64_t btree_size = 0;

    seq_id_t get_active_seqid() const { return active_seqid; }

    /* we can add more statistics as well like number of interior nodes etc. */
    std::string to_string() const {
        return fmt::format("active_seqid={} cp_id={} blkalloc_cp_id={} btree_size={}", active_seqid, cp_id,
                           blkalloc_cp_id, btree_size);
    }
} __attribute__((__packed__));

struct btree_cp : public boost::intrusive_ref_counter< btree_cp > {
    int64_t cp_id = -1;
    std::atomic< int > ref_cnt;
    std::atomic< int64_t > btree_size;
    seq_id_t start_seqid = -1; // not inclusive
    seq_id_t end_seqid = -1;   // inclusive
    cp_comp_callback cb;
    homestore::blkid_list_ptr free_blkid_list;
    btree_cp() : ref_cnt(1), btree_size(0){};
    ~btree_cp() {}

    std::string to_string() const {
        return fmt::format("cp_id={} start_seqid={} end_seqid={} free_blkid_list_size={}", cp_id, start_seqid,
                           end_seqid, free_blkid_list->size());
    }
};

/********************* Journal Specific Section **********************/
struct bt_node_gen_pair {
    bnodeid_t node_id = empty_bnodeid;
    uint64_t node_gen = 0;

    bnodeid_t get_id() const { return node_id; }
    uint64_t get_gen() const { return node_gen; }
};

VENUM(bt_journal_node_op, uint8_t, inplace_write = 1, removal = 2, creation = 3);
struct bt_journal_node_info {
    bt_node_gen_pair node_info;
    bt_journal_node_op type = bt_journal_node_op::inplace_write;
    uint16_t key_size = 0;
    uint8_t* key_area() { return ((uint8_t*)this + sizeof(bt_journal_node_info)); }
    bnodeid_t node_id() const { return node_info.node_id; }
    uint64_t node_gen() const { return node_info.node_gen; }
};

struct btree_journal_entry {
    btree_journal_entry(journal_op p, bool root, bt_node_gen_pair ninfo, int64_t cp_id) :
            op(p), is_root(root), cp_id(cp_id), parent_node(ninfo) {}

    void append_node(bt_journal_node_op node_op, bnodeid_t node_id, uint64_t gen, sisl::blob key = {nullptr, 0}) {
        ++node_count;
        bt_journal_node_info* info = _append_area();
        info->node_info = {node_id, gen};
        info->type = node_op;
        info->key_size = key.size;
        if (key.size) memcpy(info->key_area(), key.bytes, key.size);
        actual_size += sizeof(bt_journal_node_info) + key.size;
    }

    void foreach_node(bt_journal_node_op node_op, const std::function< void(bt_node_gen_pair, sisl::blob) >& cb) const {
        bt_journal_node_info* info = (bt_journal_node_info*)((uint8_t*)this + sizeof(btree_journal_entry));
        for (auto i = 0u; i < node_count; ++i) {
            if (info->type == node_op) { cb(info->node_info, sisl::blob(info->key_area(), info->key_size)); }
            info = (bt_journal_node_info*)((uint8_t*)info + sizeof(bt_journal_node_info) + info->key_size);
        }
    }

    std::vector< bt_journal_node_info* > get_nodes(const std::optional< bt_journal_node_op >& node_op = {}) const {
        std::vector< bt_journal_node_info* > result;
        bt_journal_node_info* info = (bt_journal_node_info*)((uint8_t*)this + sizeof(btree_journal_entry));
        for (auto i = 0u; i < node_count; ++i) {
            if (!node_op || (info->type == *node_op)) { result.push_back(info); }
            info = (bt_journal_node_info*)((uint8_t*)info + sizeof(bt_journal_node_info) + info->key_size);
        }
        return result;
    }

    bt_journal_node_info* leftmost_node() const {
        return get_nodes(is_root ? bt_journal_node_op::creation : bt_journal_node_op::inplace_write)[0];
    }

    std::string to_string() const {
        auto str = fmt::format("op={} is_root={} cp_id={} size={} num_nodes={} ", enum_name(op), is_root, cp_id,
                               actual_size, node_count);
        str += fmt::format("[parent: id={}, gen={}] ", parent_node.node_id, parent_node.node_gen);

        bt_journal_node_info* info = (bt_journal_node_info*)((uint8_t*)this + sizeof(btree_journal_entry));
        for (auto i = 0u; i < node_count; ++i) {
            str += fmt::format("[node{}: id={} gen={} node_op={} key_size={}] ", i, info->node_info.node_id,
                               info->node_info.node_gen, enum_name(info->type), info->key_size);
            info = (bt_journal_node_info*)((uint8_t*)info + sizeof(bt_journal_node_info) + info->key_size);
        }
        return str;
    }

    /************** Actual header starts here **********/
    journal_op op;
    bool is_root = false;
    int64_t cp_id = 0;
    uint16_t actual_size = sizeof(btree_journal_entry);
    uint16_t node_count = 0;
    bt_node_gen_pair parent_node; // Info about the parent node
    // Additional node info follows this

private:
    bt_journal_node_info* _append_area() { return (bt_journal_node_info*)((uint8_t*)this + actual_size); }
} __attribute__((__packed__));

#if 0
struct btree_journal_entry_hdr {
    journal_op op;
    bool is_root = false;
    uint64_t parent_node_id;
    uint64_t parent_node_gen;
    uint32_t parent_indx;
    uint64_t left_child_id;
    uint64_t left_child_gen;
    uint8_t num_old_nodes;
    uint8_t num_new_nodes;
    uint8_t new_key_size;
    int64_t cp_id;
} __attribute__((__packed__));
#endif

#if 0
struct btree_journal_data {
    static btree_journal_entry* make(journal_op op) {
        size_t size = std::max(
            alloc_increment,
            (sizeof(btree_journal_entry_hdr) +
             (HS_DYNAMIC_CONFIG(btree->max_nodes_to_rebalance) * btree_journal_entry_hdr::estimated_info_size)));

        btree_journal_data* entry = (btree_journal_data*)malloc(size);
        entry->op = op;
        entry->is_root = false;
        entry->actual_size = sizeof(btree_journal_entry_hdr);
        return entry;
    }

    btree_journal_entry_hdr btree_journal_entry_hdr* header() const { return &hdr; }

    uint64_t* reserve_old_nodes_list(uint8_t size) {
        hdr.old_nodes_size = size;
        return old_node_area();
    }

    std::pair< uint64_t*, uint32_t > old_nodes_list() const {
        return std::make_pair((uint64_t*)old_node_area(), hdr.old_nodes_size);
    }

    std::pair< uint64_t*, uint32_t > new_nodes_list() const {
        return std::make_pair((uint64_t*)new_node_area(), hdr.new_nodes_size);
    }

    std::pair< uint64_t*, uint32_t > new_node_gen() const {
        return std::make_pair((uint64_t*)new_node_area(), hdr.new_nodes_size);
    }

    std::pair< uint8_t*, uint32_t > new_keys() const { return std::make_pair(new_key_area(), hdr.new_key_size); }

private:
    btree_journal_entry() {}
    uint8_t* data_area() const { return ((uint8_t*)this + sizeof(btree_journal_entry_hdr)); }
    uint8_t* old_node_area() const { return data_area(); }
    uint8_t* new_node_area() const { return old_node_area() + (sizeof(uint64_t) * hdr.old_nodes_size); }
    uint8_t* new_node_gen_area() const { return new_node_area() + (sizeof(uint64_t) * hdr.new_nodes_size); }
    uint8_t* new_key_area() const { return new_node_gen_area() + (sizeof(uint64_t) * hdr.new_nodes_size); }
} __attribute__((__packed__));

struct btree_journal_entry {
    static btree_journal_entry_hdr* get_entry_hdr(uint8_t* mem) { return ((btree_journal_entry_hdr*)mem); }

    static std::pair< uint64_t*, uint32_t > get_old_nodes_list(uint8_t* mem) {
        auto hdr = get_entry_hdr(mem);
        uint64_t* old_node_id = (uint64_t*)((uint64_t)mem + sizeof(btree_journal_entry_hdr));
        return (std::make_pair(old_node_id, hdr->old_nodes_size));
    }

    static std::pair< uint64_t*, uint32_t > get_new_nodes_list(uint8_t* mem) {
        auto hdr = get_entry_hdr(mem);
        auto old_node_id = get_old_nodes_list(mem);
        uint64_t* new_node_id = (uint64_t*)(&(old_node_id.first[old_node_id.second]));
        return (std::make_pair(new_node_id, hdr->new_nodes_size));
    }

    static std::pair< uint64_t*, uint32_t > get_new_node_gen(uint8_t* mem) {
        auto hdr = get_entry_hdr(mem);
        auto new_node_id = get_new_nodes_list(mem);
        uint64_t* new_node_gen = (uint64_t*)(&(new_node_id.first[new_node_id.second]));
        return (std::make_pair(new_node_gen, hdr->new_nodes_size));
    }

    static std::pair< uint8_t*, uint32_t > get_key(uint8_t* mem) {
        auto hdr = get_entry_hdr(mem);
        auto new_node_gen = get_new_node_gen(mem);
        uint8_t* key = (uint8_t*)(&(new_node_gen.first[new_node_gen.second]));
        return (std::make_pair(key, hdr->new_key_size));
    }
} __attribute__((__packed__));
#endif

namespace homeds {
namespace btree {

#define BTREE_VMODULE_SET (VMODULE_ADD(bt_insert), VMODULE_ADD(bt_delete), )

template < uint8_t NBits >
constexpr uint64_t set_bits() {
    return (NBits == 64) ? -1ULL : ((static_cast< uint64_t >(1) << NBits) - 1);
}

#if 0
struct bnodeid {
    uint64_t m_id : 63; // TODO: We can reduce this if needbe later.
    uint64_t m_pc_gen_flag : 1;

    bnodeid() : bnodeid(set_bits< 63 >(), 0) {}
    bnodeid(uint64_t id, uint8_t gen_flag = 0) : m_id(id), m_pc_gen_flag(gen_flag) {}
    bnodeid(const bnodeid& other) = default;

    bool operator==(const bnodeid& bid) const { return (m_id == bid.m_id) && (m_pc_gen_flag == bid.m_pc_gen_flag); }
    std::string to_string() {
        std::stringstream ss;
        ss << " Id:" << m_id << ",pcgen:" << m_pc_gen_flag;
        return ss.str();
    }

    friend std::ostream& operator<<(std::ostream& os, const bnodeid& id) {
        os << " Id:" << id.m_id << ",pcgen:" << id.m_pc_gen_flag;
        return os;
    }

    bool is_valid() const { return (m_id != set_bits< 63 >()); }
    static bnodeid empty_bnodeid() { return bnodeid(); }
    uint64_t get_int() { return (m_id << 63 | 1); };
} __attribute__((packed));
#endif

#pragma pack(1)
struct btree_super_block {
    bnodeid_t root_node = 0;
    uint32_t journal_id = 0;

    uint32_t get_journal_id() const { return journal_id; }
};
#pragma pack()

ENUM(btree_store_type, uint32_t, MEM_BTREE, SSD_BTREE);

ENUM(btree_node_type, uint32_t, SIMPLE, VAR_VALUE, VAR_KEY, VAR_OBJECT, PREFIX, COMPACT);

#if 0
enum MatchType { NO_MATCH = 0, FULL_MATCH, SUBSET_MATCH, SUPERSET_MATCH, PARTIAL_MATCH_LEFT, PARTIAL_MATCH_RIGHT };
#endif

ENUM(btree_put_type, uint16_t,
     INSERT_ONLY_IF_NOT_EXISTS, // Insert
     REPLACE_ONLY_IF_EXISTS,    // Upsert
     REPLACE_IF_EXISTS_ELSE_INSERT,
     APPEND_ONLY_IF_EXISTS, // Update
     APPEND_IF_EXISTS_ELSE_INSERT);

class BtreeSearchRange;

class BtreeKey {
public:
    BtreeKey() = default;
    // BtreeKey(const BtreeKey& other) = delete; // Deleting copy constructor forces the
    // derived class to define its own copy constructor
    virtual ~BtreeKey() = default;

    // virtual BtreeKey& operator=(const BtreeKey& other) = delete; // Deleting = overload forces the derived to
    // define its = overload
    virtual int compare(const BtreeKey* other) const = 0;

    /* Applicable only for extent keys. It compare start key of (*other) with end key of (*this) */
    virtual int compare_start(const BtreeKey* other) const { return compare(other); };
    virtual int compare_range(const BtreeSearchRange& range) const = 0;
    virtual sisl::blob get_blob() const = 0;
    virtual void set_blob(const sisl::blob& b) = 0;
    virtual void copy_blob(const sisl::blob& b) = 0;

    /* Applicable to extent keys. It doesn't copy the entire blob. Copy only the end key of the blob */
    virtual void copy_end_key_blob(const sisl::blob& b) { copy_blob(b); };

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;

    virtual std::string to_string() const = 0;
    virtual bool is_extent_key() { return false; }
};

ENUM(_MultiMatchSelector, uint16_t, DO_NOT_CARE, LEFT_MOST, RIGHT_MOST,
     BEST_FIT_TO_CLOSEST,           // Return the entry either same or more then the search key. If
                                    // nothing is available then return the entry just smaller then the
                                    // search key.
     BEST_FIT_TO_CLOSEST_FOR_REMOVE // It is similar as BEST_FIT_TO_CLOSEST but have special
                                    // handling for remove This code will be removed once
                                    // range query is supported in remove
)

struct BtreeLockTracker;

struct BtreeQueryCursor {
    std::unique_ptr< BtreeKey > m_last_key;
    std::unique_ptr< BtreeLockTracker > m_locked_nodes;
    const sisl::blob serialize() {
        sisl::blob b(nullptr, 0);
        if (m_last_key) { return (m_last_key->get_blob()); }
        return b;
    };

    BtreeQueryCursor(){};
    std::string to_string() const {
        if (m_last_key) {
            return (m_last_key->to_string());
        } else {
            return "null";
        }
    };
};

using create_key_func = std::function< std::unique_ptr< BtreeKey >(BtreeKey* start_key) >;
class BtreeSearchRange {
    friend struct BtreeQueryCursor;
    // friend class  BtreeQueryRequest;

private:
    const BtreeKey* const m_start_key = nullptr;
    const BtreeKey* const m_end_key = nullptr;

    bool m_start_incl = false;
    bool m_end_incl = false;
    _MultiMatchSelector m_multi_selector;
    BtreeQueryCursor* m_cur = nullptr;

public:
    /* Note :- we don't allow default constructor. User should always create a range with start_key and end_key */
    /* TODO : reduce number of constructors */
    BtreeSearchRange(const BtreeKey& start_key, BtreeQueryCursor* cur = nullptr) :
            BtreeSearchRange(start_key, true, start_key, true, cur) {}

    BtreeSearchRange(const BtreeKey& start_key, const BtreeKey& end_key, BtreeQueryCursor* cur = nullptr) :
            BtreeSearchRange(start_key, true, end_key, true, cur) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, _MultiMatchSelector option,
                     BtreeQueryCursor* cur = nullptr) :
            BtreeSearchRange(start_key, start_incl, start_key, start_incl, option, cur) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl,
                     BtreeQueryCursor* cur = nullptr) :
            BtreeSearchRange(start_key, start_incl, end_key, end_incl, _MultiMatchSelector::DO_NOT_CARE, cur) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl,
                     _MultiMatchSelector option, BtreeQueryCursor* cur = nullptr) :
            m_start_key(&start_key),
            m_end_key(&end_key),
            m_start_incl(start_incl),
            m_end_incl(end_incl),
            m_multi_selector(option),
            m_cur(cur) {}

    void set_selection_option(_MultiMatchSelector o) { m_multi_selector = o; }
    void set_cursor(BtreeQueryCursor* cur) { m_cur = cur; }
    void reset_cursor() { m_cur = nullptr; }

    /******************* all functions are constant *************/
    BtreeQueryCursor* get_cur() const { return m_cur; }
    bool is_cursor_valid() const {
        if (m_cur) {
            return true;
        } else {
            return false;
        }
    }

    void copy_start_end_blob(BtreeKey& start_key, bool& start_incl, BtreeKey& end_key, bool& end_incl) const {
        start_key.copy_blob(get_start_key()->get_blob());
        end_key.copy_blob(get_end_key()->get_blob());
        start_incl = is_start_inclusive();
        end_incl = is_end_inclusive();
    }

    void set_cursor_key(BtreeKey* end_key, const create_key_func& func) {
        if (!m_cur) {
            /* no need to set cursor as user doesn't want to keep track of it */
            return;
        }
        if (m_cur->m_last_key) {
            m_cur->m_last_key->copy_end_key_blob(end_key->get_blob());
        } else {
            m_cur->m_last_key = std::move(func(end_key));
        }
    }

    const BtreeKey* get_start_key() const {
        if (m_cur && m_cur->m_last_key) {
            return m_cur->m_last_key.get();
        } else {
            return m_start_key;
        }
    }
    const BtreeKey* get_end_key() const { return m_end_key; }

    BtreeSearchRange get_start_of_range() const {
        return BtreeSearchRange(*get_start_key(), is_start_inclusive(), m_multi_selector);
    }

    BtreeSearchRange get_end_of_range() const {
        return BtreeSearchRange(*get_end_key(), is_end_inclusive(), m_multi_selector);
    }

    bool is_start_inclusive() const {
        if (m_cur && m_cur->m_last_key) {
            // cursor always have the last key not included
            return false;
        } else {
            return m_start_incl;
        }
    }

    bool is_end_inclusive() const { return m_end_incl; }

    bool is_simple_search() const { return ((get_start_key() == get_end_key()) && (m_start_incl == m_end_incl)); }

    _MultiMatchSelector selection_option() const { return m_multi_selector; }
};

/* This type is for keys which is range in itself i.e each key is having its own
 * start() and end().
 */
class ExtentBtreeKey : public BtreeKey {
public:
    ExtentBtreeKey() = default;
    virtual ~ExtentBtreeKey() = default;
    virtual bool is_extent_key() { return true; }
    virtual int compare_end(const BtreeKey* other) const = 0;
    virtual int compare_start(const BtreeKey* other) const override = 0;

    virtual bool preceeds(const BtreeKey* other) const = 0;
    virtual bool succeeds(const BtreeKey* other) const = 0;

    virtual void copy_end_key_blob(const sisl::blob& b) override = 0;

    /* we always compare the end key in case of extent */
    virtual int compare(const BtreeKey* other) const override { return (compare_end(other)); }

    /* we always compare the end key in case of extent */
    virtual int compare_range(const BtreeSearchRange& range) const override {
        return (compare_end(range.get_end_key()));
    }
};

class BtreeValue {
public:
    BtreeValue() {}
    virtual ~BtreeValue() {}

    // BtreeValue(const BtreeValue& other) = delete; // Deleting copy constructor forces the derived class to define
    // its own copy constructor

    virtual sisl::blob get_blob() const = 0;
    virtual void set_blob(const sisl::blob& b) = 0;
    virtual void copy_blob(const sisl::blob& b) = 0;
    virtual void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;
    virtual uint32_t estimate_size_after_append(const BtreeValue& new_val) = 0;

    virtual void get_overlap_diff_kvs(BtreeKey* k1, BtreeValue* v1, BtreeKey* k2, BtreeValue* v2, uint32_t param,
                                      diff_read_next_t& to_read,
                                      std::vector< std::pair< BtreeKey, BtreeValue > >& overlap_kvs) {
        LOGINFO("Not Implemented");
    }

    virtual std::string to_string() const { return ""; }
};

/* This class is a top level class to keep track of the locks that are held currently. It is
 * used for serializabke query to unlock all nodes in right order at the end of the lock */
class BtreeLockTracker {
public:
    virtual ~BtreeLockTracker() = default;
};

ENUM(BtreeQueryType, uint8_t,
     // This is default query which walks to first element in range, and then sweeps/walks
     // across the leaf nodes. However, if upon pagination, it again walks down the query from
     // the key it left off.
     SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,

     // Similar to sweep query, except that it retains the node and its lock during
     // pagination. This is more of intrusive query and if the caller is not careful, the read
     // lock will never be unlocked and could cause deadlocks. Use this option carefully.
     SWEEP_INTRUSIVE_PAGINATION_QUERY,

     // This is relatively inefficient query where every leaf node goes from its parent node
     // instead of walking the leaf node across. This is useful only if we want to check and
     // recover if parent and leaf node are in different generations or crash recovery cases.
     TREE_TRAVERSAL_QUERY,

     // This is both inefficient and quiet intrusive/unsafe query, where it locks the range
     // that is being queried for and do not allow any insert or update within that range. It
     // essentially create a serializable level of isolation.
     SERIALIZABLE_QUERY)

// Base class for range callback params
class BRangeCBParam {
protected:
    uint8_t node_version;
};

template < typename K, typename V >
using match_item_cb_t = std::function< btree_status_t(
    std::vector< std::pair< K, V > >&, std::vector< std::pair< K, V > >&, BRangeCBParam*, BtreeSearchRange& subrange) >;
template < typename K, typename V >
using get_size_needed_cb_t = std::function< uint32_t(std::vector< std::pair< K, V > >&, BRangeCBParam*) >;

// Base class for range requests
class BRangeRequest {
public:
    BtreeSearchRange& get_input_range() { return *m_input_range; }
    uint32_t get_batch_size() const { return m_batch_size; }
    void set_batch_size(uint32_t count) { m_batch_size = count; }

    bool is_empty_cursor() const {
        return ((m_input_range->get_cur()->m_last_key == nullptr) &&
                (m_input_range->get_cur()->m_locked_nodes == nullptr));
    }

protected:
    BRangeRequest(BRangeCBParam* cb_param, BtreeSearchRange& search_range, uint32_t batch_size = UINT32_MAX) :
            m_cb_param(cb_param), m_input_range(&search_range), m_batch_size(UINT32_MAX) {}

protected:
    BRangeCBParam* m_cb_param; // additional parameters that is passed to callback

private:
    BtreeSearchRange* m_input_range; // Btree range filter originally provided
    uint32_t m_batch_size;
};

template < typename K, typename V >
class BtreeQueryRequest : public BRangeRequest {
public:
    /* TODO :- uint32_max to c++. pass reference */
    BtreeQueryRequest(BtreeSearchRange& search_range,
                      BtreeQueryType query_type = BtreeQueryType::SWEEP_NON_INTRUSIVE_PAGINATION_QUERY,
                      uint32_t batch_size = UINT32_MAX, match_item_cb_t< K, V > cb = nullptr,
                      BRangeCBParam* cb_param = nullptr) :
            BRangeRequest(cb_param, search_range, batch_size), m_query_type(query_type), m_cb(cb) {}

    ~BtreeQueryRequest() = default;

    // virtual bool is_serializable() const = 0;
    BtreeQueryType query_type() const { return m_query_type; }

    match_item_cb_t< K, V > callback() const { return m_cb; }
    BRangeCBParam* get_cb_param() const { return (BRangeCBParam*)m_cb_param; }

protected:
    BtreeQueryType m_query_type; // Type of the query
    const match_item_cb_t< K, V > m_cb;
};

template < typename K, typename V >
class BtreeUpdateRequest : public BRangeRequest {
public:
    BtreeUpdateRequest(BtreeSearchRange& search_range, match_item_cb_t< K, V > cb = nullptr,
                       get_size_needed_cb_t< K, V > size_cb = nullptr, BRangeCBParam* cb_param = nullptr,
                       uint32_t batch_size = UINT32_MAX) :
            BRangeRequest(cb_param, search_range, batch_size), m_cb(cb), m_size_cb(size_cb) {}

    match_item_cb_t< K, V > callback() const { return m_cb; }
    BRangeCBParam* get_cb_param() const { return (BRangeCBParam*)m_cb_param; }
    get_size_needed_cb_t< K, V > get_size_needed_callback() { return m_size_cb; }

protected:
    const match_item_cb_t< K, V > m_cb;
    const get_size_needed_cb_t< K, V > m_size_cb;
};

#if 0
class BtreeSweepQueryRequest : public BtreeQueryRequest {
public:
    BtreeSweepQueryRequest(const BtreeSearchRange& criteria, uint32_t iter_count = 1000,
            const match_item_cb_t& match_item_cb = nullptr) :
            BtreeQueryRequest(criteria, iter_count, match_item_cb) {}

    BtreeSweepQueryRequest(const BtreeSearchRange &criteria, const match_item_cb_t& match_item_cb) :
            BtreeQueryRequest(criteria, 1000, match_item_cb) {}

    bool is_serializable() const { return false; }
};

class BtreeSerializableQueryRequest : public BtreeQueryRequest {
public:
    BtreeSerializableQueryRequest(const BtreeSearchRange &range, uint32_t iter_count = 1000,
                             const match_item_cb_t& match_item_cb = nullptr) :
            BtreeQueryRequest(range, iter_count, match_item_cb) {}

    BtreeSerializableQueryRequest(const BtreeSearchRange &criteria, const match_item_cb_t& match_item_cb) :
            BtreeSerializableQueryRequest(criteria, 1000, match_item_cb) {}

    bool is_serializable() const { return true; }
};
#endif

class BtreeNodeInfo : public BtreeValue {
private:
    bnodeid_t m_bnodeid;

public:
    BtreeNodeInfo() : BtreeNodeInfo(empty_bnodeid) {}
    explicit BtreeNodeInfo(const bnodeid_t& id) : m_bnodeid(id) {}
    BtreeNodeInfo& operator=(const BtreeNodeInfo& other) = default;

    bnodeid_t bnode_id() const { return m_bnodeid; }
    void set_bnode_id(bnodeid_t bid) { m_bnodeid = bid; }
    bool has_valid_bnode_id() const { return (m_bnodeid != empty_bnodeid); }

    sisl::blob get_blob() const override {
        sisl::blob b;
        b.size = sizeof(bnodeid_t);
        b.bytes = (uint8_t*)&m_bnodeid;
        return b;
    }

    void set_blob(const sisl::blob& b) override {
        DEBUG_ASSERT_EQ(b.size, sizeof(bnodeid_t));
        m_bnodeid = *(bnodeid_t*)b.bytes;
    }

    void copy_blob(const sisl::blob& b) override { set_blob(b); }

    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override { set_blob(new_val.get_blob()); }

    void get_overlap_diff_kvs(BtreeKey* k1, BtreeValue* v1, BtreeKey* k2, BtreeValue* v2, uint32_t param,
                              diff_read_next_t& to_read,
                              std::vector< std::pair< BtreeKey, BtreeValue > >& overlap_kvs) override {}

    uint32_t get_blob_size() const override { return sizeof(bnodeid_t); }
    static uint32_t get_fixed_size() { return sizeof(bnodeid_t); }
    void set_blob_size(uint32_t size) override {}
    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return sizeof(bnodeid_t); }

    std::string to_string() const override { return fmt::format("{}", m_bnodeid); }

    friend std::ostream& operator<<(std::ostream& os, const BtreeNodeInfo& b) {
        os << b.m_bnodeid;
        return os;
    }
};

class EmptyClass : public BtreeValue {
public:
    EmptyClass() {}

    sisl::blob get_blob() const override {
        sisl::blob b;
        b.size = 0;
        b.bytes = (uint8_t*)this;
        return b;
    }

    void set_blob(const sisl::blob& b) override {}

    void copy_blob(const sisl::blob& b) override {}

    void append_blob(const BtreeValue& new_val, BtreeValue& existing_val) override {}

    static uint32_t get_fixed_size() { return 0; }

    uint32_t get_blob_size() const override { return 0; }

    void set_blob_size(uint32_t size) override {}

    void get_overlap_diff_kvs(BtreeKey* k1, BtreeValue* v1, BtreeKey* k2, BtreeValue* v2, uint32_t param,
                              diff_read_next_t& to_read,
                              std::vector< std::pair< BtreeKey, BtreeValue > >& overlap_kvs) override {}

    EmptyClass& operator=(const EmptyClass& other) { return (*this); }

    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return 0; }

    std::string to_string() const override { return "<Empty>"; }
};

typedef std::function< void() > trigger_cp_callback;
struct BtreeConfig {
    uint64_t m_max_objs;
    uint32_t m_max_key_size;
    uint32_t m_max_value_size;

    uint32_t m_node_area_size;
    uint32_t m_node_size;

    uint8_t m_ideal_fill_pct;
    uint8_t m_split_pct;

    std::string m_btree_name; // Unique name for the btree
    uint64_t align_size;
    trigger_cp_callback trigger_cp_cb;
    void* blkstore;

    BtreeConfig(uint32_t node_size, const char* btree_name = nullptr) {
        m_max_objs = 0;
        m_max_key_size = m_max_value_size = 0;
        m_ideal_fill_pct = 90;
        m_split_pct = 50;
        m_btree_name = btree_name ? btree_name : std::string("btree");
        m_node_size = node_size;
    }

    uint32_t get_node_size() { return m_node_size; };
    uint32_t get_max_key_size() const { return m_max_key_size; }
    void set_max_key_size(uint32_t max_key_size) { m_max_key_size = max_key_size; }

    uint64_t get_max_objs() const { return m_max_objs; }
    void set_max_objs(uint64_t max_objs) { m_max_objs = max_objs; }

    uint32_t get_max_value_size() const { return m_max_value_size; }
    uint32_t get_node_area_size() const { return m_node_area_size; }

    void set_node_area_size(uint32_t size) { m_node_area_size = size; }
    void set_max_value_size(uint32_t max_value_size) { m_max_value_size = max_value_size; }

    uint32_t get_ideal_fill_size() const { return (uint32_t)(get_node_area_size() * m_ideal_fill_pct) / 100; }
    uint32_t get_merge_suggested_size() const { return get_node_area_size() - get_ideal_fill_size(); }
    uint32_t get_split_size(uint32_t filled_size) const { return (uint32_t)(filled_size * m_split_pct) / 100; }
    const std::string& get_name() const { return m_btree_name; }
};

#define DEFAULT_FREELIST_CACHE_COUNT 10000
template < size_t NodeSize, size_t CacheCount = DEFAULT_FREELIST_CACHE_COUNT >
class BtreeNodeAllocator {
public:
    static BtreeNodeAllocator< NodeSize, CacheCount >* create() {
        bool initialized = bt_node_allocator_initialized.load(std::memory_order_acquire);
        if (!initialized) {
            auto allocator = std::make_unique< BtreeNodeAllocator< NodeSize, CacheCount > >();
            if (bt_node_allocator_initialized.compare_exchange_strong(initialized, true, std::memory_order_acq_rel)) {
                bt_node_allocator = std::move(allocator);
            }
        }
        return bt_node_allocator.get();
    }

    static uint8_t* allocate() {
        DEBUG_ASSERT_EQ(bt_node_allocator_initialized, true);
        return bt_node_allocator->get_allocator()->allocate(NodeSize);
    }

    static void deallocate(uint8_t* mem) {
        // LOG(INFO) << "Deallocating memory " << (void *)mem;
        bt_node_allocator->get_allocator()->deallocate(mem, NodeSize);
    }

    static std::atomic< bool > bt_node_allocator_initialized;
    static std::unique_ptr< BtreeNodeAllocator< NodeSize, CacheCount > > bt_node_allocator;

    auto get_allocator() { return &m_allocator; }

private:
    sisl::FreeListAllocator< CacheCount, NodeSize > m_allocator;
};

class BtreeMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit BtreeMetrics(btree_store_type store_type, const char* inst_name) :
            sisl::MetricsGroupWrapper(enum_name(store_type), inst_name) {
        REGISTER_COUNTER(btree_obj_count, "Btree object count", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(btree_leaf_node_count, "Btree Leaf node count", "btree_node_count", {"node_type", "leaf"},
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(btree_int_node_count, "Btree Interior node count", "btree_node_count",
                         {"node_type", "interior"}, sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(btree_split_count, "Total number of btree node splits");
        REGISTER_COUNTER(insert_failed_count, "Total number of inserts failed");
        REGISTER_COUNTER(btree_merge_count, "Total number of btree node merges");
        REGISTER_COUNTER(btree_depth, "Depth of btree", sisl::_publish_as::publish_as_gauge);

        REGISTER_COUNTER(btree_int_node_writes, "Total number of btree interior node writes", "btree_node_writes",
                         {"node_type", "interior"});
        REGISTER_COUNTER(btree_leaf_node_writes, "Total number of btree leaf node writes", "btree_node_writes",
                         {"node_type", "leaf"});
        REGISTER_COUNTER(btree_num_pc_gen_mismatch, "Number of gen mismatches to recover");

        REGISTER_HISTOGRAM(btree_int_node_occupancy, "Interior node occupancy", "btree_node_occupancy",
                           {"node_type", "interior"}, HistogramBucketsType(LinearUpto128Buckets));
        REGISTER_HISTOGRAM(btree_leaf_node_occupancy, "Leaf node occupancy", "btree_node_occupancy",
                           {"node_type", "leaf"}, HistogramBucketsType(LinearUpto128Buckets));
        REGISTER_COUNTER(btree_retry_count, "number of retries");
        REGISTER_COUNTER(write_err_cnt, "number of errors in write");
        REGISTER_COUNTER(split_failed, "split failed");
        REGISTER_COUNTER(query_err_cnt, "number of errors in query");
        REGISTER_COUNTER(read_node_count_in_write_ops, "number of nodes read in write_op");
        REGISTER_COUNTER(read_node_count_in_query_ops, "number of nodes read in query_op");
        REGISTER_COUNTER(btree_write_ops_count, "number of btree operations");
        REGISTER_COUNTER(btree_query_ops_count, "number of btree operations");
        REGISTER_COUNTER(btree_remove_ops_count, "number of btree operations");
        REGISTER_HISTOGRAM(btree_exclusive_time_in_int_node,
                           "Exclusive time spent (Write locked) on interior node (ns)", "btree_exclusive_time_in_node",
                           {"node_type", "interior"});
        REGISTER_HISTOGRAM(btree_exclusive_time_in_leaf_node, "Exclusive time spent (Write locked) on leaf node (ns)",
                           "btree_exclusive_time_in_node", {"node_type", "leaf"});
        REGISTER_HISTOGRAM(btree_inclusive_time_in_int_node, "Inclusive time spent (Read locked) on interior node (ns)",
                           "btree_inclusive_time_in_node", {"node_type", "interior"});
        REGISTER_HISTOGRAM(btree_inclusive_time_in_leaf_node, "Inclusive time spent (Read locked) on leaf node (ns)",
                           "btree_inclusive_time_in_node", {"node_type", "leaf"});
        REGISTER_HISTOGRAM(btree_write_time, "time spent in write (ns)", "btree_write_time");
        REGISTER_HISTOGRAM(btree_read_query_time, "time spent in read (ns)", "btree_read_query_time");
        REGISTER_HISTOGRAM(btree_read_lock_time_in_leaf_node, "time spent in read lock contention on leaf node",
                           "btree_read_lock_time_in_leaf_node");
        REGISTER_HISTOGRAM(btree_read_lock_time_in_int_node, "time spent in read lock contention on interior node",
                           "btree_read_lock_time_in_int_node");
        REGISTER_HISTOGRAM(btree_write_lock_time_in_leaf_node, "time spent in write lock contention on leaf node",
                           "btree_write_lock_time_in_leaf_node");
        REGISTER_HISTOGRAM(btree_write_lock_time_in_int_node, "time spent in write lock contention on interior node",
                           "btree_write_lock_time_in_int_node");

        register_me_to_farm();
    }

    ~BtreeMetrics() { deregister_me_from_farm(); }
};

template < size_t NodeSize, size_t CacheCount >
std::atomic< bool > BtreeNodeAllocator< NodeSize, CacheCount >::bt_node_allocator_initialized(false);

template < size_t NodeSize, size_t CacheCount >
std::unique_ptr< BtreeNodeAllocator< NodeSize, CacheCount > >
    BtreeNodeAllocator< NodeSize, CacheCount >::bt_node_allocator = nullptr;

} // namespace btree
} // namespace homeds
