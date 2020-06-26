//
// Created by Kadayam, Hari on 19/10/17.
//

#pragma once

//#include "eviction.cpp"
#include "eviction.hpp"
#include <utility/atomic_counter.hpp>
#include "engine/homeds/hash/intrusive_hashset.hpp"
#include "lru_eviction.hpp"
#include <boost/intrusive_ptr.hpp>
#include <fds/obj_allocator.hpp>
#include "engine/common/homestore_config.hpp"
#include <execinfo.h>
#include <utility/obj_life_counter.hpp>
#include <metrics/metrics.hpp>
#include <fds/utils.hpp>

SDS_LOGGING_DECL(cache_vmod_evict, cache_vmod_read, cache_vmod_write)

namespace homestore {

#define CurrentEvictor LRUEvictor
#define LRUEvictor Evictor< LRUEvictionPolicy >
#define CurrentEvictorRecord CurrentEvictor::EvictRecordType

class CacheRecord : public homeds::HashNode, sisl::ObjLifeCounter< CacheRecord > {
public:
    typename CurrentEvictor::EvictRecordType m_evict_record; // Information about the eviction record itself.

    const CurrentEvictor::EvictRecordType& get_evict_record() const { return m_evict_record; }

    CurrentEvictor::EvictRecordType& get_evict_record_mutable() { return m_evict_record; }

    static CacheRecord* evict_to_cache_record(const CurrentEvictor::EvictRecordType* p_erec) {
        return (p_erec ? container_of(p_erec, &CacheRecord::m_evict_record) : nullptr);
    }
};

/* Number of entries we ideally want to have per hash bucket. This number if small, will reduce contention and
 * speed of read/writes, but at the cost of increased memory */
//#define ENTRIES_PER_BUCKET 2

/* Number of eviction partitions. More the partitions better the parallelization of requests, but lesser the
 * effectiveness of cache, since it could get evicted sooner than expected, if distribution of key hashing is not
 * even.*/
#define EVICTOR_PARTITIONS 32

class CacheMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit CacheMetrics() : sisl::MetricsGroupWrapper("Cache") {
        REGISTER_COUNTER(cache_insert_count, "Total number of inserts to cache", "cache_op_count", {"op", "insert"});
        REGISTER_COUNTER(cache_read_count, "Total number of reads to cache", "cache_op_count", {"op", "read"});
        REGISTER_COUNTER(cache_erase_count, "Total number of erases from cache", "cache_op_count", {"op", "erase"});
        REGISTER_COUNTER(cache_update_count, "Total number of updates to a cache entry", "cache_op_count",
                         {"op", "update"});
        REGISTER_COUNTER(cache_object_count, "Total number of cache entries", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(cache_size, "Total size of cache", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(cache_add_error_count, "Num cache entries unable to insert");
        REGISTER_COUNTER(cache_num_evictions, "Total number of cache evictions");
        REGISTER_COUNTER(cache_num_evictions_punt, "Total number of cache evictions punted because of busy");
        REGISTER_COUNTER(cache_num_duplicate_inserts, "Total number of cache inserts whose entry already exists");

        register_me_to_farm();
    }
};

template < typename K, typename V >
class IntrusiveCache {
public:
    static_assert(std::is_base_of< CacheRecord, V >::value, "IntrusiveCache Value must be derived from CacheRecord");

    IntrusiveCache(uint64_t max_cache_size, uint32_t avg_size_per_entry);
    ~IntrusiveCache() {
        for (auto i = 0; i < EVICTOR_PARTITIONS; i++)
            m_evictors[i].reset();
    }

    /* Put the raw buffer into the cache. Returns false if insert is not successful and if the key already
     * exists, it additionally fills up the out_ptr. If insert is successful, returns true and put the
     * new V also into out_ptr. */
    bool insert(V& v, V** out_ptr, const auto& found_cb);

    /* Update the value, if it already exists or insert if not exist. Returns true if operation is successful. In
     * additon, it also populates if the out_key exists with true if key exists or false if key does not */
    bool upsert(const V& v, bool* out_key_exists);

    /* Returns the raw pointer of the data corresponding to the key */
    V* get(const K& k);

    /* Erase the key from the cache. Returns true if key exists and erased, false otherwise */
    bool erase(V& v);

    bool is_safe_to_evict(const CurrentEvictor::EvictRecordType* rec);
    bool modify_size(V& v, uint32_t size);

protected:
    std::unique_ptr< CurrentEvictor > m_evictors[EVICTOR_PARTITIONS];
    homeds::IntrusiveHashSet< K, V > m_hash_set;
    CacheMetrics m_metrics;
};

template < typename K >
class CacheBuffer;

template < typename K >
class Cache : protected IntrusiveCache< K, CacheBuffer< K > > {
    typedef std::function< void(const boost::intrusive_ptr< CacheBuffer< K > >& bbuf) > erase_comp_cb;

public:
    Cache(uint64_t max_cache_size, uint32_t avg_size_per_entry);
    ~Cache();
    /* Put the raw buffer into the cache with key k. It returns whether put is successful and if so provides
     * the smart pointer of CacheBuffer. Upsert flag of false indicates if the data already exists, do not insert */
    bool insert(const K& k, const homeds::blob& b, uint32_t value_offset,
                boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf,
                const std::function< void(CacheBuffer< K >*) >& found_cb = nullptr);
    bool insert(const K& k, const boost::intrusive_ptr< CacheBuffer< K > > in_buf,
                boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf);

    /* Update is a special operation, where, it searches for the key and
     *  If found, appends the blob to the existing cached memory, new memory at specified offset.
     *  If not found, insert a new blob-offset combo into the cached memory.
     *
     *  Returns a named tuple of bools - key_found_already and successfully inserted/updated
     */
    auto update(const K& k, const homeds::blob& b, uint32_t value_offset,
                boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf);
    bool upsert(const K& k, const homeds::blob& b, boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf);
    bool get(const K& k, boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf);
    bool erase(boost::intrusive_ptr< CacheBuffer< K > > buf);
    bool erase(const K& k, boost::intrusive_ptr< CacheBuffer< K > >* out_bbuf);
    bool erase(const K& k, uint32_t offset, uint32_t size, boost::intrusive_ptr< CacheBuffer< K > >* ret_removed_buf);
    void safe_erase(boost::intrusive_ptr< CacheBuffer< K > > buf, erase_comp_cb cb);
    void safe_erase(const K& k, erase_comp_cb cb);
    bool insert_missing_pieces(const boost::intrusive_ptr< CacheBuffer< K > > buf, uint32_t offset,
                               uint32_t size_to_read, std::vector< std::pair< uint32_t, uint32_t > >& missing_mp);
};

enum cache_buf_state {
    CACHE_NOT_INSERTED = 1,
    CACHE_INSERTED = 2,
    CACHE_EVICTED = 3,
};

template < typename K >
class CacheBuffer : public CacheRecord {
private:
    typedef std::function< void(const boost::intrusive_ptr< CacheBuffer< K > >& bbuf) > erase_comp_cb;

public:
#ifndef NDEBUG
    bool recovered;
#endif
    K m_key;                                         // Key to access this cache
    boost::intrusive_ptr< homeds::MemVector > m_mem; // Memory address which is what this buffer contained with
    sisl::atomic_counter< uint32_t > m_refcount;     // Refcount
    uint32_t m_data_offset;                          // offset in m_mem that it points to
    std::atomic< uint32_t > m_cache_size;            // size inserted in a cache
    std::atomic< bool > m_can_free;
    Cache< K >* m_cache;
    erase_comp_cb m_cb;

    /* this mutex prevent erase and insert to happen in parallel. It is taken in two cases
     *  1. Whenever something changes in eviction :- upvode, downvote, erase and size.
     *  2. Whenever cache state is changed.
     */
    std::mutex m_mtx;
    cache_buf_state m_state;

#ifndef NDEBUG
    sisl::atomic_counter< int64_t > m_indx; // Refcount
#define MAX_ENTRIES 50
    /* to see if it is data buf or btree buf */
#endif

public:
#ifndef NDEBUG
    bool is_btree = false;
#endif

    typedef CacheBuffer< K > CacheBufferType;
    CacheBuffer() :
            m_mem(nullptr),
            m_refcount(0),
            m_data_offset(-1),
            m_cache_size(0),
            m_can_free(false),
            m_cache(nullptr),
            m_mtx(),
            m_state(CACHE_NOT_INSERTED)
#ifndef NDEBUG
            ,
            m_indx(-1)
#endif
    {
    }

    CacheBuffer(const K& key, const homeds::blob& blob, Cache< K >* cache, uint32_t offset = 0) :
            m_mem(nullptr),
            m_refcount(0),
            m_data_offset(-1),
            m_cache_size(0),
            m_can_free(false),
            m_cache(cache),
            m_mtx(),
            m_state(CACHE_NOT_INSERTED)
#ifndef NDEBUG
            ,
            m_indx(-1)
#endif
    {
        boost::intrusive_ptr< homeds::MemVector > mvec(new homeds::MemVector(), true);
        mvec->set(blob.bytes, blob.size, offset);

        set_memvec(mvec, 0, blob.size);
        m_key = key;
    }

    virtual ~CacheBuffer(){};

    const K& get_key() const { return m_key; }

    void set_key(K& k) { m_key = k; }

    void lock() { m_mtx.lock(); }

    void unlock() { m_mtx.unlock(); }

    bool try_lock() { return (m_mtx.try_lock()); }

    void on_cache_insert() { m_state = CACHE_INSERTED; }

    void on_cache_evict() { m_state = CACHE_EVICTED; }

    cache_buf_state get_cache_state() { return m_state; }

    void set_cache(Cache< K >* cache) { m_cache = cache; }

    uint32_t get_data_offset() const { return m_data_offset; }

    bool update_missing_piece(uint32_t offset, uint32_t size, uint8_t* ptr) {
        bool inserted = get_memvec().update_missing_piece(m_data_offset + offset, size, ptr, [this]() { init(); });
        return inserted;
    }

    uint32_t insert_missing_pieces(uint32_t offset, uint32_t size_to_read,
                                   std::vector< std::pair< uint32_t, uint32_t > >& missing_mp) {
        uint32_t inserted_size = get_memvec().insert_missing_pieces(m_data_offset + offset, size_to_read, missing_mp);
        /* it should return a relative offset */
        for (uint32_t i = 0; i < missing_mp.size(); i++) {
            assert(missing_mp[i].first >= m_data_offset);
            missing_mp[i].first -= m_data_offset;
        }

        return inserted_size;
    }

    void set_cb(erase_comp_cb& cb) { m_cb = cb; }

    erase_comp_cb get_cb() { return m_cb; }

    void set_memvec(boost::intrusive_ptr< homeds::MemVector > vec, uint32_t offset, uint32_t size) {
        assert(offset >= 0);
        m_mem = vec;
        m_data_offset = offset;
        m_cache_size = size;
    }

    void modify_cache_size(uint32_t size) { m_cache_size += size; }

    uint32_t get_cache_size() const { return m_cache_size; }

    homeds::MemVector& get_memvec() const {
        assert(m_mem != nullptr);
        return ((*(m_mem.get())));
    }

    boost::intrusive_ptr< homeds::MemVector > get_memvec_intrusive() const {
        assert(m_mem != nullptr);
        return m_mem;
    }

    homeds::blob at_offset(uint32_t offset) const {
        assert(m_data_offset >= 0);
        homeds::blob b;
        b.bytes = nullptr;
        b.size = 0;
        get_memvec().get(&b, m_data_offset + offset);
        return b;
    }

    friend void intrusive_ptr_add_ref(CacheBuffer< K >* buf) {
#ifndef NDEBUG
        int x = buf->m_indx.increment() % MAX_ENTRIES;
#endif
        buf->m_refcount.increment();
    }

    friend void intrusive_ptr_release(CacheBuffer< K >* buf) {
        const K k = *(extract_key(*buf));
        auto cache = buf->m_cache;
        bool can_free = buf->can_free();
        int cnt = buf->m_refcount.decrement();
        /* can not access the buffer after ref_Cnt is
         * decremented.
         */
        assert(cnt >= 0);
        if (cnt == 0) {
            // free the record
            buf->free_yourself();
        }

        if (cnt == 1 && can_free) {
            assert(cache != nullptr);
            cache->safe_erase(k, nullptr);
        }
    }

    virtual void init(){};

    void set_free_state() { m_can_free = true; }

    void reset_free_state() { m_can_free = false; }
    bool can_free() { return (m_can_free); }
    std::string to_string() const {
        std::stringstream ss;
        ss << "Cache Key = " << m_key.to_string() << " Cache Mem = " << m_mem->to_string()
           << " Cache refcount = " << m_refcount.get();
        return ss.str();
    }

    virtual void free_yourself() { sisl::ObjectAllocator< CacheBufferType >::deallocate(this); }
    // virtual size_t get_your_size() const { return sizeof(CacheBuffer< K >); }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(CacheBuffer< K >& b) { intrusive_ptr_add_ref(&b); }

    static void set_free_state(CacheBuffer< K >& b) { b.set_free_state(); }

    static void reset_free_state(CacheBuffer< K >& b) { b.reset_free_state(); }

    static void deref(CacheBuffer< K >& b) { intrusive_ptr_release(&b); }

    static bool test_le(CacheBuffer< K >& b, int32_t check) { return b.m_refcount.test_le(check); }

    static bool test_le(const CacheBuffer< K >& b, int32_t check) { return b.m_refcount.test_le(check); }

    static const K* extract_key(const CacheBuffer< K >& b) { return &(b.m_key); }

    static uint32_t get_size(const CurrentEvictor::EvictRecordType* rec) {
        const CacheBuffer< K >* cbuf = static_cast< const CacheBuffer< K >* >(CacheRecord::evict_to_cache_record(rec));
        return cbuf->m_cache_size;
    }
};
} // namespace homestore
