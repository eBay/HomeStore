/*
 * btree_internal.h
 *
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#ifndef BTREE_KVSTORE_H_
#define BTREE_KVSTORE_H_
#include <vector>
#include <iostream>
#include "omds/utility/useful_defs.hpp"

using namespace std;

struct uint48_t {
    uint64_t m_x:48;

    uint48_t() {
        m_x = 0;
    }

    uint48_t(const int &x) {
        m_x = x;
    }

    uint48_t(uint8_t *mem) {
        m_x = (uint64_t)mem;
    }

    uint48_t(const uint48_t &other) {
        m_x = other.m_x;
    }

    uint48_t& operator=(const uint48_t &other) {
        m_x = other.m_x;
        return *this;
    }

    uint48_t& operator=(const uint64_t &x) {
        m_x = x;
        return *this;
    }

    uint48_t& operator=(const int &x) {
        m_x = (uint64_t)x;
        return *this;
    }

    bool operator==(const uint48_t &other) const {
        return (m_x == other.m_x);
    }

    bool operator!=(const uint48_t &other) const {
        return (m_x != other.m_x);
    }
} __attribute__((packed));

namespace omds { namespace btree {

typedef uint48_t bnodeid_t;

typedef enum {
    BTREE_SUCCESS = 0,
    BTREE_NOT_FOUND,
    BTREE_ITEM_FOUND,
    BTREE_CLOSEST_FOUND,
    BTREE_CLOSEST_REMOVED,
    BTREE_RETRY
} btree_status_t;

typedef enum {
    BTREE_NODETYPE_SIMPLE = 0,
    BTREE_NODETYPE_VAR_VALUE,
    BTREE_NODETYPE_VAR_KEY,
    BTREE_NODETYPE_VAR_OBJECT,
    BTREE_NODETYPE_PREFIX,
    BTREE_NODETYPE_COMPACT
} btree_nodetype_t;

enum MatchType {
    NO_MATCH=0,
    FULL_MATCH,
    SUBSET_MATCH,
    SUPERSET_MATCH,
    PARTIAL_MATCH_LEFT,
    PARTIAL_MATCH_RIGHT
};

enum PutType {
    INSERT_ONLY_IF_NOT_EXISTS,     // Insert

    REPLACE_ONLY_IF_EXISTS,        // Upsert
    REPLACE_IF_EXISTS_ELSE_INSERT,

    APPEND_ONLY_IF_EXISTS,         // Update
    APPEND_IF_EXISTS_ELSE_INSERT
};

class BtreeKey
{
public:
    BtreeKey() = default;
    virtual ~BtreeKey() = default;

    virtual int compare(const BtreeKey *other) const = 0;
    virtual omds::blob get_blob() const = 0;
    virtual void set_blob(const omds::blob &b) = 0;
    virtual void copy_blob(const omds::blob &b) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;

#ifdef DEBUG
    virtual void print() = 0;
#endif
};

#if 0
class BtreeRangeKey {
private:
    BtreeKey *m_start_key;
    BtreeKey *m_end_key;

public:
    BtreeRangeKey(BtreeKey& start_key) :
            BtreeRangeKey(start_key, start_key) {}

    BtreeRangeKey(BtreeKey& start_key, BtreeKey& end_key) :
            m_start_key(&start_key),
            m_end_key(&end_key) {}

    virtual const BtreeKey* get_start_key() const {
        return m_start_key;
    }

    virtual const BtreeKey* get_end_key() const {
        return m_end_key;
    }
};
#endif

class BtreeSearchRange
{
private:
    const BtreeKey *m_start_key;
    const BtreeKey *m_end_key;

    bool m_start_incl;
    bool m_end_incl;
    bool m_left_leaning;

public:
    BtreeSearchRange(const BtreeKey& start_key) :
            BtreeSearchRange(start_key, true, start_key, true) {}

    BtreeSearchRange(const BtreeKey& start_key, const BtreeKey& end_key) :
            BtreeSearchRange(start_key, true, end_key, true) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl) :
            BtreeSearchRange(start_key, start_incl, end_key, end_incl, true) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl,
                  bool left_leaning) :
            m_start_key(&start_key),
            m_end_key(&end_key),
            m_start_incl(start_incl),
            m_end_incl(end_incl),
            m_left_leaning(left_leaning) {
    }

    const BtreeKey* get_start_key() const {
        return m_start_key;
    }

    const BtreeKey* get_end_key() const {
        return m_end_key;
    }

    // Is the key provided and current key completely matches.
    // i.e If say a range = [8 to 12] and rkey is [9 - 11], then compare will return 0,
    // but this method will return false. It will return true only if range exactly matches.
    //virtual bool is_full_match(BtreeRangeKey *rkey) const = 0;

    virtual bool is_start_inclusive() const {
        return m_start_incl;
    }
    virtual bool is_end_inclusive() const {
        return m_end_incl;
    }

    bool is_simple_search() const {
        return ((get_start_key() == get_end_key()) && (m_start_incl == m_end_incl));
    }

    virtual bool is_left_leaning() const {
        return m_left_leaning;
    }
};

class BtreeValue
{
public:
    BtreeValue() {}

    virtual omds::blob get_blob() const = 0;
    virtual void set_blob(const omds::blob &b) = 0;
    virtual void copy_blob(const omds::blob &b) = 0;
    virtual void append_blob(const BtreeValue &new_val) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;

#ifndef NDEBUG
    virtual void print() const = 0;
#endif
};

#define INVALID_BNODEID    -1

class BNodeptr: public BtreeValue
{
private:
    bnodeid_t m_id;

public:
    BNodeptr() {
        m_id = INVALID_BNODEID;
    }

    BNodeptr(bnodeid_t ptr) {
        m_id = ptr;
    }

    bnodeid_t get_node_id() const {
        return m_id;
    }
    void set_node_id(bnodeid_t id) {
        m_id = id;
    }
    bool is_valid_ptr() const {
        return (m_id != INVALID_BNODEID);
    }

    omds::blob get_blob() const override {
        omds::blob b;
        b.size = sizeof(bnodeid_t);
        b.bytes = (uint8_t *)&m_id;
        return b;
    }

    void set_blob(const omds::blob &b) override {
        assert(b.size == sizeof(bnodeid_t));
        m_id = *(bnodeid_t *)b.bytes;
    }

    void copy_blob(const omds::blob &b) override {
        set_blob(b);
    }

    void append_blob(const BtreeValue &new_val) override {
        set_blob(new_val.get_blob());
    }

    uint32_t get_blob_size() const override {
        return sizeof(bnodeid_t);
    }

    static uint32_t get_fixed_size() {
        return sizeof(bnodeid_t);
    }

    void set_blob_size(uint32_t size) override {
    }

    BtreeValue& operator=(const BtreeValue& other) {
        BNodeptr *otherp = (BNodeptr *) &other;
        m_id = otherp->m_id;
        return (*this);
    }

    void print() const override {
        cout << m_id.m_x;
    }
};

class EmptyClass: public BtreeValue
{
public:
    EmptyClass() {}

    omds::blob get_blob() const override {
        omds::blob b;
        b.size = 0;
        b.bytes = (uint8_t *)this;
        return b;
    }

    void set_blob(const omds::blob &b) override {
    }

    void copy_blob(const omds::blob &b) override {
    }

    void append_blob(const BtreeValue &new_val) override {
    }

    static uint32_t get_fixed_size() {
        return 0;
    }

    uint32_t get_blob_size() const override {
        return 0;
    }

    void set_blob_size(uint32_t size) override {
    }

    EmptyClass& operator=(const EmptyClass& other) {
        return (*this);
    }

    void print() const override {
        cout << "<Empty>";
    }
};

class BtreeConfig
{
private:
    uint64_t m_max_objs;
    uint32_t m_nodesize;

    btree_nodetype_t m_int_node_type;
    btree_nodetype_t m_leaf_node_type;

    uint32_t m_max_key_size;
    uint32_t m_max_value_size;

    uint32_t m_max_leaf_entries_per_node;
    uint32_t m_max_int_entries_per_node;

    uint8_t m_ideal_fill_pct;
    uint8_t m_split_pct;

public:
    BtreeConfig() {
        m_max_leaf_entries_per_node = m_max_int_entries_per_node = m_max_objs = 0;
        m_nodesize = 8192;
        m_max_key_size = m_max_value_size = 0;
        m_int_node_type = m_leaf_node_type = BTREE_NODETYPE_SIMPLE;
        m_ideal_fill_pct = 90;
        m_split_pct = 50;
    }

    btree_nodetype_t get_interior_node_type() const {
        return m_int_node_type;
    }

    void set_interior_node_type(btree_nodetype_t intNodeType) {
        m_int_node_type = intNodeType;
    }

    btree_nodetype_t get_leaf_node_type() const {
        return m_leaf_node_type;
    }

    void set_leaf_node_type(btree_nodetype_t leaf_node_type) {
        m_leaf_node_type = leaf_node_type;
    }

    uint32_t get_max_key_size() const {
        return m_max_key_size;
    }
    void set_max_key_size(uint32_t max_key_size) {
        m_max_key_size = max_key_size;
    }

    uint64_t get_max_objs() const {
        return m_max_objs;
    }

    void set_max_objs(uint64_t max_objs) {
        m_max_objs = max_objs;
    }

    uint32_t get_max_value_size() const {
        return m_max_value_size;
    }

    void set_max_value_size(uint32_t max_value_size) {
        m_max_value_size = max_value_size;
    }

    uint32_t get_node_size() const {
        return m_nodesize;
    }

    void set_node_size(uint32_t node_size) {
        m_nodesize = node_size;
    }

    uint32_t get_max_leaf_entries_per_node() const {
        return m_max_leaf_entries_per_node;
    }

    uint32_t get_max_interior_entries_per_node() const {
        return m_max_int_entries_per_node;
    }

    void calculate_max_leaf_entries_per_node() {
        switch (m_leaf_node_type) {
        case BTREE_NODETYPE_SIMPLE:
            m_max_leaf_entries_per_node = m_nodesize / (m_max_key_size + m_max_value_size);
            break;
        default:
            assert(0);
            break;
        }
    }

    void calculate_max_interior_entries_per_node() {
        switch (m_int_node_type) {
        case BTREE_NODETYPE_SIMPLE:
            m_max_int_entries_per_node = m_nodesize / (m_max_key_size + sizeof(BNodeptr));
            break;
        default:
            assert(0);
            break;
        }
    }

    uint32_t get_ideal_fill_size() const {
        return (uint32_t) (get_node_size() * m_ideal_fill_pct)/100;
    }

    uint32_t get_merge_suggested_size() const {
        return get_node_size() - get_ideal_fill_size();
    }

    uint32_t get_split_size() const {
        return (uint32_t) (get_node_size() * m_split_pct)/100;
    }
};

}}
#endif
