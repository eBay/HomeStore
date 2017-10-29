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
#define INVALID_BNODEID    -1

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
    BTREE_NODETYPE_PREFIX,
    BTREE_NODETYPE_COMPACT
} btree_nodetype_t;

class BtreeKey
{
public:
    BtreeKey() {}
    virtual ~BtreeKey() {}

    virtual bool is_regex_key() const {
        return false;
    }

    // Result Key is the same as our key, so lets return nullptr
    virtual BtreeKey *get_result_key() {
        return nullptr;
    }

    virtual int compare(BtreeKey *other) const = 0;
    virtual uint8_t *get_blob(uint32_t *psize) const = 0;
    virtual void set_blob(const uint8_t *blob, uint32_t size) = 0;
    virtual void copy_blob(const uint8_t *blob, uint32_t size) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;

#ifdef DEBUG
    virtual void print() = 0;
#endif
};

class BtreeRangeKey : public BtreeKey {
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

class BtreeRegExKey : public BtreeRangeKey
{
private:
    bool m_start_incl;
    bool m_end_incl;
    BtreeKey *m_result_key;
    bool m_left_leaning;

public:
    BtreeRegExKey(BtreeKey& start_key) :
            BtreeRegExKey(start_key, true, start_key, true) {}

    BtreeRegExKey(BtreeKey& start_key, BtreeKey& end_key) :
            BtreeRegExKey(start_key, true, end_key, true) {}

    BtreeRegExKey(BtreeKey& start_key, bool start_incl, BtreeKey& end_key, bool end_incl) :
            BtreeRegExKey(start_key, start_incl, end_key, end_incl, true, nullptr) {}

    BtreeRegExKey(BtreeKey& start_key, bool start_incl, BtreeKey& end_key, bool end_incl,
                  bool left_leaning, BtreeKey *out_key) :
            BtreeRangeKey(start_key, end_key),
            m_start_incl(start_incl),
            m_end_incl(end_incl),
            m_result_key(out_key),
            m_left_leaning(left_leaning) {}

    // Is the key provided and current key completely matches.
    // i.e If say a range = [8 to 12] and rkey is [9 - 11], then compare will return 0,
    // but this method will return false. It will return true only if range exactly matches.
    virtual bool is_full_match(BtreeRangeKey *rkey) const = 0;

    virtual bool is_start_inclusive() const {
        return m_start_incl;
    }
    virtual bool is_end_inclusive() const {
        return m_end_incl;
    }

    bool is_regex_key() const override {
        return true;
    }

    virtual bool is_left_leaning() const {
        return m_left_leaning;
    }
    BtreeKey *get_result_key() override {
        return m_result_key;
    }
};

class BtreeValue
{
public:
    BtreeValue() {}

    virtual uint8_t *get_blob(uint32_t *pSize) const = 0;
    virtual void set_blob(const uint8_t *blob, uint32_t size) = 0;
    virtual void copy_blob(const uint8_t *blob, uint32_t size) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;

#ifdef DEBUG
    virtual void print() = 0;
#endif
};

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

    uint8_t *get_blob(uint32_t *pSize) const {
        *pSize = sizeof(bnodeid_t);
        return (uint8_t *) &m_id;
    }

    void set_blob(const uint8_t *blob, uint32_t size) {
        assert(size == sizeof(bnodeid_t));
        m_id = *(bnodeid_t *) blob;
    }

    void copy_blob(const uint8_t *blob, uint32_t size) {
        set_blob(blob, size);
    }

    uint32_t get_blob_size() const {
        return sizeof(bnodeid_t);
    }

    static uint32_t get_fixed_size() {
        return sizeof(bnodeid_t);
    }

    void set_blob_size(uint32_t size) {
    }

    BtreeValue& operator=(const BtreeValue& other) {
        BNodeptr *otherp = (BNodeptr *) &other;
        m_id = otherp->m_id;
        return (*this);
    }

    void print() const {
        cout << m_id.m_x;
    }
};

class EmptyClass: public BtreeValue
{
public:
    EmptyClass() {}

    uint8_t *get_blob(uint32_t *pSize) const {
        *pSize = 0;
        return (uint8_t *) this;
    }

    void set_blob(const uint8_t *blob, uint32_t size) {
    }

    virtual void copy_blob(const uint8_t *blob, uint32_t size) {
    }

    static uint32_t get_fixed_size() {
        return 0;
    }

    uint32_t get_blob_size() const {
        return 0;
    }

    void set_blob_size(uint32_t size) {
    }

    EmptyClass& operator=(const EmptyClass& other) {
        return (*this);
    }

    void print() const {
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
public:
    BtreeConfig() {
        m_max_leaf_entries_per_node = m_max_int_entries_per_node = m_max_objs = 0;
        m_nodesize = 8192;
        m_max_key_size = m_max_value_size = 0;
        m_int_node_type = m_leaf_node_type = BTREE_NODETYPE_SIMPLE;
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
};

}}
#endif
