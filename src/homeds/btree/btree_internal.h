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
#include <cmath>
#include "homeds/utility/useful_defs.hpp"
#include "homeds/memory/freelist_allocator.hpp"
#include "error/error.h"

using namespace std;

struct empty_writeback_req {
    /* shouldn't contain anything */
    std::atomic<int> m_refcount;
    friend void intrusive_ptr_add_ref(empty_writeback_req *req) {
        req->m_refcount.fetch_add(1, std::memory_order_acquire);
    }
    friend void intrusive_ptr_release(empty_writeback_req *req) {
        if (req->m_refcount.fetch_sub(1, std::memory_order_acquire) == 1) {
            free(req);
        }
    }
};
struct uint48_t {
    uint64_t m_x:48;

    uint48_t() {
        m_x = 0;
    }

    uint48_t(uint64_t x) {
        m_x = x;
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

    uint64_t to_integer() {
        return m_x;
    }

} __attribute__((packed));

namespace homeds { namespace btree {

#define BTREE_VMODULE_SET (     \
        VMODULE_ADD(bt_insert), \
        VMODULE_ADD(bt_delete), \
    )
    
struct bnodeid{
    uint48_t m_id;
    uint8_t m_pc_gen_flag:1;//parent child gen flag used to recover from split and merge
    
    bnodeid() {m_id=0;m_pc_gen_flag=0;}
    
    bnodeid(const uint48_t &m_id, bool pc_gen_flag) : m_id(m_id), m_pc_gen_flag(pc_gen_flag?1:0) {}

    bnodeid(uint64_t m_id, bool pc_gen_flag) : m_id(m_id), m_pc_gen_flag(pc_gen_flag?1:0) {}

    bnodeid(const bnodeid &other) {
        m_id = other.m_id;
        m_pc_gen_flag = other.get_pc_gen_flag()?1:0;
    }
    
    uint48_t get_id()  {
        return m_id;
    }

    bool operator==(const bnodeid &other) const {
        return (m_id == other.m_id && m_pc_gen_flag == other.m_pc_gen_flag);
    }

    void set_id(const uint48_t &id) {
        m_id = id;
    }
    
    void set_pc_gen_flag(bool pc_gen_flag) {
        m_pc_gen_flag = pc_gen_flag?1:0;
    }
    
    bool get_pc_gen_flag() const{
        return m_pc_gen_flag;
    }
    
    std::string to_string() {
        std::stringstream ss;
        std::string temp="0";
        if(m_pc_gen_flag==1)
            temp="1";
        ss<< " Id:"<<m_id.m_x <<",pcgen:"<< temp;
        return ss.str();
    }
    
    bool is_invalidate_id() {
        bnodeid temp(-1,0);
        if(this->m_id.m_x == temp.m_id.m_x)return true;
        else return false;
    }
    
}__attribute__((packed));

typedef bnodeid bnodeid_t;

typedef enum {
    BTREE_SUCCESS = 0,
    BTREE_NOT_FOUND,
    BTREE_ITEM_FOUND,
    BTREE_CLOSEST_FOUND,
    BTREE_CLOSEST_REMOVED,
    BTREE_RETRY
} btree_status_t;

typedef enum {
    MEM_BTREE=0,
    SSD_BTREE=1
} btree_type;

typedef enum {
    BTREE_NODETYPE_SIMPLE = 0,
    BTREE_NODETYPE_VAR_VALUE,
    BTREE_NODETYPE_VAR_KEY,
    BTREE_NODETYPE_VAR_OBJECT,
    BTREE_NODETYPE_PREFIX,
    BTREE_NODETYPE_COMPACT
} btree_node_type;

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

class BtreeSearchRange;
class BtreeKey
{
public:
    BtreeKey() = default;
    virtual ~BtreeKey() = default;

    virtual int compare(const BtreeKey *other) const = 0;
    virtual int compare_range(const BtreeSearchRange &range) const = 0;
    virtual homeds::blob get_blob() const = 0;
    virtual void set_blob(const homeds::blob &b) = 0;
    virtual void copy_blob(const homeds::blob &b) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;
    
    virtual std::string to_string() const = 0;
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
    bool m_second_min;

public:
    BtreeSearchRange(const BtreeKey& start_key) :
            BtreeSearchRange(start_key, true, start_key, true) {}

    BtreeSearchRange(const BtreeKey& start_key, const BtreeKey& end_key) :
            BtreeSearchRange(start_key, true, end_key, true) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl) :
            BtreeSearchRange(start_key, start_incl, end_key, end_incl, true, false) {}

    BtreeSearchRange(const BtreeKey& start_key, bool start_incl, const BtreeKey& end_key, bool end_incl,
                  bool left_leaning, bool second_min) :
            m_start_key(&start_key),
            m_end_key(&end_key),
            m_start_incl(start_incl),
            m_end_incl(end_incl),
            m_left_leaning(left_leaning) ,
	    m_second_min(second_min) {
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
    
    virtual bool is_second_min() const {
        return m_second_min;;
    }
};

class BtreeValue
{
public:
    BtreeValue() {}

    virtual homeds::blob get_blob() const = 0;
    virtual void set_blob(const homeds::blob &b) = 0;
    virtual void copy_blob(const homeds::blob &b) = 0;
    virtual void append_blob(const BtreeValue &new_val, std::shared_ptr<BtreeValue> &existing_val) = 0;

    virtual uint32_t get_blob_size() const = 0;
    virtual void set_blob_size(uint32_t size) = 0;
    virtual uint32_t estimate_size_after_append(const BtreeValue &new_val) = 0;
    
    virtual std::string to_string() const {return "";}
};

#define INVALID_BNODEID   -1

class BNodeptr: public BtreeValue
{
private:
    bnodeid_t m_bnodeid;

public:
    BNodeptr() {
        m_bnodeid.set_id(INVALID_BNODEID);
    }

    BNodeptr(bnodeid_t ptr) {
        m_bnodeid = ptr;
    }
    
    bnodeid_t get_node_id() const {
        return m_bnodeid;
    }
    void set_node_id(bnodeid_t id) {
        m_bnodeid = id;
    }
    bool is_valid_ptr() const {
        return (m_bnodeid.m_id != INVALID_BNODEID);
    }

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.size = sizeof(bnodeid_t);
        b.bytes = (uint8_t *)&m_bnodeid;
        return b;
    }

    void set_blob(const homeds::blob &b) override {
        assert(b.size == sizeof(bnodeid_t));
        m_bnodeid = *(bnodeid_t *)b.bytes;
    }

    void copy_blob(const homeds::blob &b) override {
        set_blob(b);
    }

    void append_blob(const BtreeValue &new_val, std::shared_ptr<BtreeValue> &existing_val) override {
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
        m_bnodeid = otherp->m_bnodeid;
        return (*this);
    }

    uint32_t estimate_size_after_append(const BtreeValue &new_val) override {
        return sizeof(bnodeid_t);
    }
    
    std::string to_string() const override{
        std::stringstream ss;
        std::string isValid = is_valid_ptr()?"1":"0";
        ss<< get_node_id().to_string() << ",isValidPtr:" << isValid;
        return ss.str();
    }

#ifdef DEBUG
    std::string to_string() const override {
        std::stringstream ss; ss << m_id.m_x; return ss.str();
    }
#endif
};

class EmptyClass: public BtreeValue
{
public:
    EmptyClass() {}

    homeds::blob get_blob() const override {
        homeds::blob b;
        b.size = 0;
        b.bytes = (uint8_t *)this;
        return b;
    }

    void set_blob(const homeds::blob &b) override {
    }

    void copy_blob(const homeds::blob &b) override {
    }

    void append_blob(const BtreeValue &new_val, std::shared_ptr<BtreeValue> &existing_val) override {
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

    uint32_t estimate_size_after_append(const BtreeValue &new_val) override {
        return 0;
    }

#ifdef DEBUG
    std::string to_string() const override {
        return "<Empty>";
    }
#endif
};

class BtreeConfig
{
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

    uint32_t get_node_area_size() const {
        return m_node_area_size;
    }

    void set_node_area_size(uint32_t size) {
        m_node_area_size = size;
    }

    void set_max_value_size(uint32_t max_value_size) {
        m_max_value_size = max_value_size;
    }

    uint32_t get_ideal_fill_size() const {
        return (uint32_t) (get_node_area_size() * m_ideal_fill_pct)/100;
    }

    uint32_t get_merge_suggested_size() const {
        return get_node_area_size() - get_ideal_fill_size();
    }

    uint32_t get_split_size() const {
        return (uint32_t) (get_node_area_size() * m_split_pct)/100;
    }
};

#define DEFAULT_FREELIST_CACHE_COUNT         10000
template <size_t NodeSize, size_t CacheCount = DEFAULT_FREELIST_CACHE_COUNT>
class BtreeNodeAllocator {
public:
    static BtreeNodeAllocator<NodeSize, CacheCount> *create() {
        bool initialized = bt_node_allocator_initialized.load(std::memory_order_acquire);
        if (!initialized) {
            auto allocator = std::make_unique< BtreeNodeAllocator<NodeSize, CacheCount> >();
            if (bt_node_allocator_initialized.compare_exchange_strong(initialized, true, std::memory_order_acq_rel)) {
                bt_node_allocator = std::move(allocator);
            }
        }
        return bt_node_allocator.get();
    }

    static uint8_t *allocate()  {
        assert(bt_node_allocator_initialized);
        return bt_node_allocator->get_allocator()->allocate(NodeSize);
    }

    static void deallocate(uint8_t *mem) {
        //LOG(INFO) << "Deallocating memory " << (void *)mem;
        bt_node_allocator->get_allocator()->deallocate(mem, NodeSize);
    }

    static std::atomic< bool > bt_node_allocator_initialized;
    static std::unique_ptr< BtreeNodeAllocator<NodeSize, CacheCount> > bt_node_allocator;

    auto get_allocator() {
        return &m_allocator;
    }

private:
    homeds::FreeListAllocator< CacheCount, NodeSize > m_allocator;
};

template <size_t NodeSize, size_t CacheCount>
std::atomic< bool > BtreeNodeAllocator<NodeSize, CacheCount>::bt_node_allocator_initialized(false);

template <size_t NodeSize, size_t CacheCount>
std::unique_ptr< BtreeNodeAllocator<NodeSize, CacheCount> > BtreeNodeAllocator<NodeSize, CacheCount>::bt_node_allocator = nullptr;

#if 0
#define MIN_NODE_SIZE                8192
#define MAX_NODE_SIZE                8192

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

}}
#endif
