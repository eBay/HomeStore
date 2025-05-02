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

#include <string>
#include <vector>
#include <fmt/format.h>
#include <sisl/fds/buffer.hpp>
#include <homestore/btree/detail/btree_internal.hpp>

namespace homestore {

ENUM(MultiMatchOption, uint16_t,
     DO_NOT_CARE, // Select anything that matches
     LEFT_MOST,   // Select the left most one
     RIGHT_MOST,  // Select the right most one
     MID          // Select the middle one
)

ENUM(btree_put_type, uint16_t,
     INSERT, // Insert only if it doesn't exist
     UPDATE, // Update only if it exists
     UPSERT  // Update if exists, insert otherwise
)

// The base class, btree library expects its key to be derived from
class BtreeKey {
public:
    BtreeKey() = default;

    // Deleting copy constructor forces the derived class to define its own copy constructor
    // BtreeKey(const BtreeKey& other) = delete;
    // BtreeKey(const sisl::blob& b) = delete;
    BtreeKey(BtreeKey const& other) = default;
    virtual ~BtreeKey() = default;

    virtual int compare(BtreeKey const& other) const = 0;

    virtual sisl::blob serialize() const = 0;
    virtual uint32_t serialized_size() const = 0;
    virtual void deserialize(sisl::blob const& b, bool copy) = 0;

    virtual std::string to_string() const = 0;
    virtual bool is_interval_key() const { return false; }
};

// An extension of BtreeKey where each key is part of an interval range. Keys are not neccessarily only needs to be
// integers, but it needs to be able to get next or prev key from a given key in the key range
class BtreeIntervalKey : public BtreeKey {
public:
    virtual void shift(int n, void* app_ctx) = 0;
    virtual int distance(BtreeKey const& from) const = 0;
    bool is_interval_key() const override { return true; }

    virtual sisl::blob serialize_prefix() const = 0;
    virtual sisl::blob serialize_suffix() const = 0;

    virtual uint32_t serialized_prefix_size() const = 0;
    virtual uint32_t serialized_suffix_size() const = 0;
    virtual void deserialize(sisl::blob const& prefix, sisl::blob const& suffix, bool copy) = 0;
};

template < typename K >
class BtreeTraversalState;

template < typename K >
class BtreeKeyRange {
public:
    K m_start_key;
    K m_end_key;
    bool m_start_incl{true};
    bool m_end_incl{true};
    MultiMatchOption m_multi_selector{MultiMatchOption::DO_NOT_CARE};

    friend class BtreeTraversalState< K >;

public:
    BtreeKeyRange() = default;

    BtreeKeyRange(const K& start_key, bool start_incl, const K& end_key, bool end_incl = true,
                  MultiMatchOption option = MultiMatchOption::DO_NOT_CARE) :
            m_start_key{start_key},
            m_end_key{end_key},
            m_start_incl{start_incl},
            m_end_incl{end_incl},
            m_multi_selector{option} {}

    BtreeKeyRange(const K& start_key, const K& end_key) : BtreeKeyRange(start_key, true, end_key, true) {}

    BtreeKeyRange(const BtreeKeyRange& other) = default;
    BtreeKeyRange(BtreeKeyRange&& other) = default;
    BtreeKeyRange& operator=(const BtreeKeyRange< K >& other) = default;
    BtreeKeyRange& operator=(BtreeKeyRange< K >&& other) = default;

    void set_multi_option(MultiMatchOption o) { m_multi_selector = o; }
    const K& start_key() const { return m_start_key; }
    const K& end_key() const { return m_end_key; }
    bool is_start_inclusive() const { return m_start_incl; }
    bool is_end_inclusive() const { return m_end_incl; }
    MultiMatchOption multi_option() const { return m_multi_selector; }

    void set_start_key(K&& key, bool incl) {
        m_start_key = std::move(key);
        m_start_incl = incl;
    }

    void set_end_key(K&& key, bool incl) {
        m_end_key = std::move(key);
        m_end_incl = incl;
    }

    std::string to_string() const {
        return fmt::format("{}{}-{}{}", is_start_inclusive() ? '[' : '(', start_key().to_string(),
                           end_key().to_string(), is_end_inclusive() ? ']' : ')');
    }
};

class BtreeValue {
public:
    BtreeValue() = default;
    virtual ~BtreeValue() = default;

    virtual sisl::blob serialize() const = 0;
    virtual uint32_t serialized_size() const = 0;
    virtual void deserialize(const sisl::blob& b, bool copy) = 0;

    virtual std::string to_string() const { return ""; }
};

class BtreeIntervalValue : public BtreeValue {
public:
    virtual void shift(int n, void* app_ctx) = 0;

    virtual sisl::blob serialize_prefix() const = 0;
    virtual sisl::blob serialize_suffix() const = 0;

    virtual uint32_t serialized_prefix_size() const = 0;
    virtual uint32_t serialized_suffix_size() const = 0;
    virtual void deserialize(sisl::blob const& prefix, sisl::blob const& suffix, bool copy) = 0;
};

struct BtreeLockTracker;
template < typename K >
struct BtreeQueryCursor {
    std::unique_ptr< K > m_last_key;
    std::unique_ptr< BtreeLockTracker > m_locked_nodes;
    BtreeQueryCursor() = default;

    const sisl::blob serialize() const { return m_last_key ? m_last_key->serialize() : sisl::blob{}; };
    virtual std::string to_string() const { return (m_last_key) ? m_last_key->to_string() : "null"; }
};

// This class holds the current state of the search. This is where intermediate search state are stored
// and it is mutated by the do_put and do_query methods. Expect the current_sub_range and cursor to keep
// getting updated on calls.
template < typename K >
class BtreeTraversalState {
protected:
    const BtreeKeyRange< K > m_input_range;
    BtreeKeyRange< K > m_working_range;
    bool m_trimmed{false};   // Keep track of trimmed, so that a shift doesn't do unwanted copy of input_range
    bool m_exhausted{false}; // The entire working range is exhausted

public:
    BtreeTraversalState(BtreeKeyRange< K >&& inp_range) :
            m_input_range{std::move(inp_range)}, m_working_range{m_input_range} {}
    BtreeTraversalState(const BtreeTraversalState& other) = default;
    BtreeTraversalState(BtreeTraversalState&& other) = default;

    const BtreeKeyRange< K >& input_range() const { return m_input_range; }
    const BtreeKeyRange< K >& working_range() const {
        DEBUG_ASSERT_EQ(m_exhausted, false, "requested for working range on an exhausted traversal state");
        return m_working_range;
    }

    // Returns the mutable reference to the end key, which caller can update it to trim down the end key
    void trim_working_range(K&& end_key, bool end_incl) {
        m_working_range.set_end_key(std::move(end_key), end_incl);
        m_trimmed = true;
    }

    // Shift the working range start to previous working range end_key
    void shift_working_range() {
        if (m_trimmed) {
            m_working_range.set_start_key(std::move(m_working_range.m_end_key), false);
            m_working_range.m_end_key = m_input_range.end_key();
            m_working_range.m_end_incl = m_input_range.is_end_inclusive();
            m_trimmed = false;
        } else {
            m_exhausted = true;
        }
    }

    // Shift the working range start to specific end key
    void shift_working_range(K&& start_key, bool start_incl) {
        m_working_range.set_start_key(std::move(start_key), start_incl);
        if (m_trimmed) {
            m_working_range.m_end_key = m_input_range.end_key();
            m_working_range.m_end_incl = m_input_range.is_end_inclusive();
            m_trimmed = false;
        }
    }

    const K& first_key() const { return m_working_range.start_key(); }

    uint32_t first_key_size() const {
        if (is_start_inclusive() || K::is_fixed_size()) {
            return m_working_range.start_key().serialized_size();
        } else {
            return K::get_max_size();
        }
    }

private:
    bool is_start_inclusive() const { return m_input_range.is_start_inclusive(); }
    bool is_end_inclusive() const { return m_input_range.is_end_inclusive(); }
};

class BtreeLinkInfo : public BtreeValue {
public:
    struct bnode_link_info {
        bnodeid_t m_bnodeid{empty_bnodeid};
        uint64_t m_link_version{0}; // Link version between parent and a child
    };

private:
    bnode_link_info info;

public:
    BtreeLinkInfo() = default;
    explicit BtreeLinkInfo(bnodeid_t id, uint64_t v) {
        info.m_bnodeid = id;
        info.m_link_version = v;
    }
    BtreeLinkInfo(bnode_link_info l) : info{l} {}
    BtreeLinkInfo& operator=(const BtreeLinkInfo& other) = default;

    bnodeid_t bnode_id() const { return info.m_bnodeid; }
    uint64_t link_version() const { return info.m_link_version; }
    void set_bnode_id(bnodeid_t bid) { info.m_bnodeid = bid; }
    void set_link_version(uint64_t v) { info.m_link_version = v; }
    bool has_valid_bnode_id() const { return (info.m_bnodeid != empty_bnodeid); }

    sisl::blob serialize() const override {
        sisl::blob b;
        b.set_size(sizeof(bnode_link_info));
        b.set_bytes(r_cast< const uint8_t* >(&info));
        return b;
    }
    uint32_t serialized_size() const override { return sizeof(bnode_link_info); }
    static uint32_t get_fixed_size() { return sizeof(bnode_link_info); }
    std::string to_string() const override { return fmt::format("{}.{}", info.m_bnodeid, info.m_link_version); }

    void deserialize(const sisl::blob& b, bool copy) override {
        DEBUG_ASSERT_EQ(b.size(), sizeof(bnode_link_info), "BtreeLinkInfo deserialize received invalid blob");
        auto other = r_cast< bnode_link_info const* >(b.cbytes());
        set_bnode_id(other->m_bnodeid);
        set_link_version(other->m_link_version);
    }

    friend std::ostream& operator<<(std::ostream& os, const BtreeLinkInfo& b) {
        os << b.to_string();
        return os;
    }
};

} // namespace homestore
