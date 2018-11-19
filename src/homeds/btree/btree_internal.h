/*
 * btree_internal.h
 *
 *  Created on: 14-May-2016
 *      Author: Hari Kadayam
 *
 *  Copyright © 2016 Kadayam, Hari. All rights reserved.
 */
#pragma once
#include <vector>
#include <iostream>
#include <cmath>
#include "homeds/utility/useful_defs.hpp"
#include "homeds/memory/freelist_allocator.hpp"
#include "error/error.h"

struct empty_writeback_req {
    /* shouldn't contain anything */
    std::atomic<int> m_refcount;
    friend void intrusive_ptr_add_ref(empty_writeback_req* req) {
        req->m_refcount.fetch_add(1, std::memory_order_acquire);
    }
    friend void intrusive_ptr_release(empty_writeback_req* req) {
        if (req->m_refcount.fetch_sub(1, std::memory_order_acquire) == 1) {
            free(req);
        }
    }
};
struct uint48_t {
    uint64_t m_x : 48;

    uint48_t() { m_x = 0; }
    uint48_t(uint64_t x) { m_x = x; }
    uint48_t(const int& x) { m_x = x; }
    uint48_t(uint8_t* mem) { m_x = (uint64_t)mem; }
    uint48_t(const uint48_t& other) { m_x = other.m_x; }

    uint48_t& operator=(const uint48_t& other) {
        m_x = other.m_x;
        return *this;
    }

    uint48_t& operator=(const uint64_t& x) {
        m_x = x;
        return *this;
    }

    uint48_t& operator=(const int& x) {
        m_x = (uint64_t)x;
        return *this;
    }

    bool operator==(const uint48_t& other) const { return (m_x == other.m_x); }
    bool operator!=(const uint48_t& other) const { return (m_x != other.m_x); }
    uint64_t to_integer() { return m_x; }
} __attribute__((packed));

namespace homeds {
namespace btree {

#define BTREE_VMODULE_SET (VMODULE_ADD(bt_insert), VMODULE_ADD(bt_delete), )

typedef uint48_t bnodeid_t;

typedef enum {
    BTREE_SUCCESS = 0,
    BTREE_NOT_FOUND,
    BTREE_ITEM_FOUND,
    BTREE_CLOSEST_FOUND,
    BTREE_CLOSEST_REMOVED,
    BTREE_RETRY
} btree_status_t;

typedef enum { MEM_BTREE = 0, SSD_BTREE = 1 } btree_store_type;

typedef enum {
    BTREE_NODETYPE_SIMPLE = 0,
    BTREE_NODETYPE_VAR_VALUE,
    BTREE_NODETYPE_VAR_KEY,
    BTREE_NODETYPE_VAR_OBJECT,
    BTREE_NODETYPE_PREFIX,
    BTREE_NODETYPE_COMPACT
} btree_node_type;

enum MatchType { NO_MATCH = 0, FULL_MATCH, SUBSET_MATCH, SUPERSET_MATCH, PARTIAL_MATCH_LEFT, PARTIAL_MATCH_RIGHT };

enum PutType {
    INSERT_ONLY_IF_NOT_EXISTS, // Insert

    REPLACE_ONLY_IF_EXISTS, // Upsert
    REPLACE_IF_EXISTS_ELSE_INSERT,

    APPEND_ONLY_IF_EXISTS, // Update
    APPEND_IF_EXISTS_ELSE_INSERT
};

class BtreeSearchRange;
class BtreeKey {
  public:
    BtreeKey() = default;
    //BtreeKey(const BtreeKey& other) = delete; // Deleting copy constructor forces the derived class to define its own copy constructor
    virtual ~BtreeKey() = default;

    //virtual BtreeKey& operator=(const BtreeKey& other) = delete; // Deleting = overload forces the derived to define its = overload
    virtual int compare(const BtreeKey* other) const = 0;
    virtual int compare_range(const BtreeSearchRange& range) const = 0;
    virtual homeds::blob get_blob() const = 0;
    virtual void set_blob(const homeds::blob& b) = 0;
    virtual void copy_blob(const homeds::blob& b) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;

    virtual std::string to_string() const = 0;
};

enum _MultiMatchSelector {
    DO_NOT_CARE,
    LEFT_MOST,
    SECOND_TO_THE_LEFT,
    RIGHT_MOST,
};

class BtreeSearchRange {
    friend struct BtreeQueryCursor;
    friend class  BtreeQueryRequest;

private:
    const BtreeKey* m_start_key;
    const BtreeKey* m_end_key;

    bool m_start_incl;
    bool m_end_incl;
    _MultiMatchSelector m_multi_selector;

public:
    BtreeSearchRange(const BtreeKey& start_key) : BtreeSearchRange(start_key, true, start_key, true) {}

    BtreeSearchRange(const BtreeKey& start_key, const BtreeKey& end_key) :
            BtreeSearchRange(start_key, true, end_key, true) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, _MultiMatchSelector option) :
            BtreeSearchRange(start_key, start_incl, start_key, start_incl, option) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl) :
            BtreeSearchRange(start_key, start_incl, end_key, end_incl, DO_NOT_CARE) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl,
                     _MultiMatchSelector option) :
            m_start_key(&start_key),
            m_end_key(&end_key),
            m_start_incl(start_incl),
            m_end_incl(end_incl),
            m_multi_selector(option) {}

    const BtreeKey* get_start_key() const { return m_start_key; }
    const BtreeKey* get_end_key() const { return m_end_key; }

    BtreeSearchRange extract_start_of_range() const { return BtreeSearchRange(*m_start_key, m_start_incl, m_multi_selector); }
    BtreeSearchRange extract_end_of_range() const { return BtreeSearchRange(*m_end_key, m_end_incl, m_multi_selector); }

    // Is the key provided and current key completely matches.
    // i.e If say a range = [8 to 12] and rkey is [9 - 11], then compare will return 0,
    // but this method will return false. It will return true only if range exactly matches.
    // virtual bool is_full_match(BtreeRangeKey *rkey) const = 0;

    bool is_start_inclusive() const { return m_start_incl; }
    bool is_end_inclusive() const { return m_end_incl; }

    bool is_simple_search() const { return ((get_start_key() == get_end_key()) && (m_start_incl == m_end_incl)); }

    _MultiMatchSelector selection_option() const { return m_multi_selector; }
    void set_selection_option(_MultiMatchSelector o) { m_multi_selector = o; }
};

class BtreeValue {
  public:
    BtreeValue() {}
    //BtreeValue(const BtreeValue& other) = delete; // Deleting copy constructor forces the derived class to define its own copy constructor

    virtual homeds::blob get_blob() const = 0;
    virtual void set_blob(const homeds::blob& b) = 0;
    virtual void copy_blob(const homeds::blob& b) = 0;
    virtual void append_blob(const BtreeValue& new_val, std::shared_ptr<BtreeValue>& existing_val) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;
    virtual uint32_t estimate_size_after_append(const BtreeValue& new_val) = 0;

    virtual std::string to_string() const { return ""; }
};

/* This class is a top level class to keep track of the locks that are held currently. It is used for serializabke
 * query to unlock all nodes in right order at the end of the lock */
class BtreeLockTracker {
public:
    virtual ~BtreeLockTracker() = default;
};

struct BtreeQueryCursor {
    std::unique_ptr<BtreeKey> m_last_key;
    std::unique_ptr<BtreeLockTracker> m_locked_nodes;
};

enum BtreeQueryType {
    // This is default query which walks to first element in range, and then sweeps/walks across the leaf nodes. However,
    // if upon pagination, it again walks down the query from the key it left off.
    SWEEP_TRAVERSAL_ON_PAGINATION_QUERY,

    // Similar to sweep query, except that it retains the node and its lock during pagination. This is more of intrusive
    // query and if the caller is not careful, the read lock will never be unlocked and could cause deadlocks. Use this
    // option carefully.
    SWEEP_RETAIN_LOCK_ON_PAGINATION_QUERY,

    // This is relatively inefficient query where every leaf node goes from its parent node instead of walking the
    // leaf node across. This is useful only if we want to check and recover if parent and leaf node are in different
    // generations or crash recovery cases.
    TREE_TRAVERSAL_QUERY,

    // This is both inefficient and quiet intrusive/unsafe query, where it locks the range that is being queried for
    // and do not allow any insert or update within that range. It essentially create a serializable level of isolation.
    SERIALIZABLE_QUERY
};

using match_item_cb_t = std::function<bool(const BtreeKey&, const BtreeValue&)>;
class BtreeQueryRequest {
public:
    BtreeQueryRequest(const BtreeSearchRange& search_range,
                      BtreeQueryType query_type = BtreeQueryType::SWEEP_TRAVERSAL_ON_PAGINATION_QUERY,
                      uint32_t batch_size = 1000,
                      const match_item_cb_t& match_item_cb = nullptr) :
            m_match_item_cb(match_item_cb),
            m_input_range(search_range),
            m_batch_search_range(search_range),
            m_start_range(search_range.extract_start_of_range()),
            m_end_range(search_range.extract_end_of_range()),
            m_query_type(query_type),
            m_batch_size(batch_size) {}

    BtreeQueryRequest(const BtreeSearchRange& search_range, const match_item_cb_t& match_item_cb) :
            BtreeQueryRequest(search_range, BtreeQueryType::SWEEP_TRAVERSAL_ON_PAGINATION_QUERY, 1000, match_item_cb) {}

    ~BtreeQueryRequest() = default;

    void init_batch_range() {
        if (!is_empty_cursor()) {
            m_batch_search_range = BtreeSearchRange(*m_cursor.m_last_key, false, *m_input_range.get_end_key(),
                                         m_input_range.is_end_inclusive(), m_input_range.selection_option());
            m_start_range = BtreeSearchRange(*m_cursor.m_last_key, false, m_input_range.selection_option());
        }
    }

    BtreeSearchRange& get_batch_range() { return m_batch_search_range; }
    BtreeQueryCursor& cursor() { return m_cursor; }
    BtreeSearchRange& get_start_of_range() { return m_start_range; }
    BtreeSearchRange& get_end_of_range() { return m_end_range; }

    bool is_empty_cursor() const { return ((m_cursor.m_last_key == nullptr) && (m_cursor.m_locked_nodes == nullptr)); }
    //virtual bool is_serializable() const = 0;
    BtreeQueryType query_type() const { return m_query_type; }
    uint32_t get_batch_size() const { return m_batch_size; }
    void set_batch_size(uint32_t count) { m_batch_size = count; }

public:
    match_item_cb_t m_match_item_cb; // Callback for every match

protected:
    const BtreeSearchRange& get_input_range() { return m_input_range; }

protected:
    BtreeSearchRange m_input_range;         // Btree range filter originally provided
    BtreeSearchRange m_batch_search_range;  // Adjusted filter for current batch
    BtreeSearchRange m_start_range;         // Search Range contaning only start key
    BtreeSearchRange m_end_range;           // Search Range containing only end key
    BtreeQueryCursor m_cursor;              // An opaque cursor object for pagination
    BtreeQueryType   m_query_type;          // Type of the query
    uint32_t m_batch_size;   // Count of items needed in this batch. This value can be changed on every cursor iteration
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

#define INVALID_BNODEID -1

class BNodeptr : public BtreeValue {
  private:
    bnodeid_t m_id;

  public:
    BNodeptr() { m_id = INVALID_BNODEID; }

    explicit BNodeptr(const bnodeid_t& ptr) { m_id = ptr; }
    BNodeptr& operator=(const BNodeptr& other) = default;

    bnodeid_t get_node_id() const { return m_id; }
    void set_node_id(bnodeid_t id) { m_id = id; }
    bool is_valid_ptr() const { return (m_id != INVALID_BNODEID); }

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.size = sizeof(bnodeid_t);
        b.bytes = (uint8_t*)&m_id;
        return b;
    }

    void set_blob(const homeds::blob& b) override {
        assert(b.size == sizeof(bnodeid_t));
        m_id = *(bnodeid_t*)b.bytes;
    }

    void copy_blob(const homeds::blob& b) override { set_blob(b); }

    void append_blob(const BtreeValue& new_val, std::shared_ptr<BtreeValue>& existing_val) override {
        set_blob(new_val.get_blob());
    }

    uint32_t get_blob_size() const override { return sizeof(bnodeid_t); }

    static uint32_t get_fixed_size() { return sizeof(bnodeid_t); }

    void set_blob_size(uint32_t size) override {}

    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return sizeof(bnodeid_t); }

    bool operator==(const BNodeptr& other) const { return (m_id == other.m_id); }

#ifdef DEBUG
    std::string to_string() const override {
        std::stringstream ss;
        ss << m_id.m_x;
        return ss.str();
    }
#endif
};

class EmptyClass : public BtreeValue {
  public:
    EmptyClass() {}

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.size = 0;
        b.bytes = (uint8_t*)this;
        return b;
    }

    void set_blob(const homeds::blob& b) override {}

    void copy_blob(const homeds::blob& b) override {}

    void append_blob(const BtreeValue& new_val, std::shared_ptr<BtreeValue>& existing_val) override {}

    static uint32_t get_fixed_size() { return 0; }

    uint32_t get_blob_size() const override { return 0; }

    void set_blob_size(uint32_t size) override {}

    EmptyClass& operator=(const EmptyClass& other) { return (*this); }

    uint32_t estimate_size_after_append(const BtreeValue& new_val) override { return 0; }

#ifdef DEBUG
    std::string to_string() const override { return "<Empty>"; }
#endif
};

class BtreeConfig {
  private:
    uint64_t m_max_objs;
    uint32_t m_max_key_size;
    uint32_t m_max_value_size;

    uint32_t m_node_area_size;

    uint8_t m_ideal_fill_pct;
    uint8_t m_split_pct;

  public:
    BtreeConfig() {
        m_max_objs = 0;
        m_max_key_size = m_max_value_size = 0;
        m_ideal_fill_pct = 90;
        m_split_pct = 50;
    }

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
    uint32_t get_split_size() const { return (uint32_t)(get_node_area_size() * m_split_pct) / 100; }
};

#define DEFAULT_FREELIST_CACHE_COUNT 10000
template <size_t NodeSize, size_t CacheCount = DEFAULT_FREELIST_CACHE_COUNT> class BtreeNodeAllocator {
  public:
    static BtreeNodeAllocator<NodeSize, CacheCount>* create() {
        bool initialized = bt_node_allocator_initialized.load(std::memory_order_acquire);
        if (!initialized) {
            auto allocator = std::make_unique<BtreeNodeAllocator<NodeSize, CacheCount>>();
            if (bt_node_allocator_initialized.compare_exchange_strong(initialized, true, std::memory_order_acq_rel)) {
                bt_node_allocator = std::move(allocator);
            }
        }
        return bt_node_allocator.get();
    }

    static uint8_t* allocate() {
        assert(bt_node_allocator_initialized);
        return bt_node_allocator->get_allocator()->allocate(NodeSize);
    }

    static void deallocate(uint8_t* mem) {
        LOG(INFO) << "Deallocating memory " << (void*)mem;
        bt_node_allocator->get_allocator()->deallocate(mem, NodeSize);
    }

    static std::atomic<bool> bt_node_allocator_initialized;
    static std::unique_ptr<BtreeNodeAllocator<NodeSize, CacheCount>> bt_node_allocator;

    auto get_allocator() { return &m_allocator; }

  private:
    homeds::FreeListAllocator<CacheCount, NodeSize> m_allocator;
};

template <size_t NodeSize, size_t CacheCount>
std::atomic<bool> BtreeNodeAllocator<NodeSize, CacheCount>::bt_node_allocator_initialized(false);

template <size_t NodeSize, size_t CacheCount>
std::unique_ptr<BtreeNodeAllocator<NodeSize, CacheCount>> BtreeNodeAllocator<NodeSize, CacheCount>::bt_node_allocator =
    nullptr;

#if 0
#define MIN_NODE_SIZE 8192
#define MAX_NODE_SIZE 8192

class BtreeNodeAllocator
{
public:
    static constexpr uint32_t get_bucket_size(uint32_t count) {
        uint32_t result = MIN_NODE_SIZE;
        for (auto i = 0; i < count; i++) {
            result *= MIN_NODE_SIZE;
        }
        return result;
    }

    static constexpr uint32_t get_nbuckets() {
        return std::log2(MAX_NODE_SIZE) - std::log2(MIN_NODE_SIZE) + 1;
    }

    BtreeNodeAllocator() {
        m_allocators.reserve(get_nbuckets());
        for (auto i = 0U; i < get_nbuckets(); i++) {
            auto *allocator = new homeds::FreeListAllocator< FREELIST_CACHE_COUNT, get_bucket_size(i)>();
            m_allocators.push_back((void *)allocator);
        }
        // Allocate a default tail allocator for non-confirming sizes
        auto *allocator = new homeds::FreeListAllocator< FREELIST_CACHE_COUNT, 0>();
        m_allocators.push_back((void *)allocator);
    }

    ~BtreeNodeAllocator() {
        for (auto i = 0U; i < get_nbuckets(); i++) {
            auto *allocator = (homeds::FreeListAllocator< FREELIST_CACHE_COUNT, get_bucket_size(i)> *)m_allocators[i];
            delete(allocator);
        }
        // Allocate a default tail allocator for non-confirming sizes
        auto *allocator = (homeds::FreeListAllocator< FREELIST_CACHE_COUNT, 0> *)m_allocators[m_allocators.size()-1];
        delete(allocator);
    }

    static BtreeNodeAllocator *create() {
        bool initialized = bt_node_allocator_initialized.load(std::memory_order_acquire);
        if (!initialized) {
            std::unique_ptr< BtreeNodeAllocator > allocator = std::make_unique< BtreeNodeAllocator >();
            if (bt_node_allocator_initialized.compare_exchange_strong(initialized, true, std::memory_order_acq_rel)) {
                bt_node_allocator = std::move(allocator);
            }
        }
        return bt_node_allocator.get();
    }

    static uint8_t *allocate(uint32_t size_needed)  {
        uint32_t nbucket = (size_needed - 1)/MIN_NODE_SIZE + 1;
        if (unlikely(m_impl.get() == nullptr)) {
            m_impl.reset(new FreeListAllocatorImpl< MaxListCount, Size >());
        }

        return (m_impl->allocate(size_needed));
    }

    static void deallocate(T *mem) {
        mem->~T();
        get_obj_allocator()->m_allocator->deallocate((uint8_t *)mem, sizeof(T));
    }

    static std::atomic< bool > bt_node_allocator_initialized;
    static std::unique_ptr< BtreeNodeAllocator > bt_node_allocator;

private:
    homeds::FreeListAllocator< FREELIST_CACHE_COUNT, sizeof(T) > *get_freelist_allocator() {
        return m_allocator.get();
    }

private:
    std::vector< void * > m_allocators;

    static ObjectAllocator< T, CacheCount > *get_obj_allocator() {
        if (unlikely((obj_allocator == nullptr))) {
            obj_allocator = std::make_unique< ObjectAllocator< T, CacheCount > >();
        }
        return obj_allocator.get();
    }
};


std::atomic< bool > BtreeNodeAllocator::bt_node_allocator_initialized(false);
std::unique_ptr< BtreeNodeAllocator > BtreeNodeAllocator::bt_node_allocator = nullptr;
#endif

} // namespace btree
} // namespace homeds
