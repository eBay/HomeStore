//
// Created by Kadayam, Hari on 19/10/17.
//

#ifndef OMSTORAGE_CACHE_HPP
#define OMSTORAGE_CACHE_HPP

//#include "eviction.cpp"
#include "eviction.hpp"
#include "homeds/utility/atomic_counter.hpp"
#include "homeds/hash/intrusive_hashset.hpp"
#include "lru_eviction.hpp"
#include <boost/intrusive_ptr.hpp>
#include "homeds/memory/obj_allocator.hpp"
#include "main/store_limits.h"
#include "homeds/utility/logging.hpp"

namespace homestore {

// TODO: We need to change this to config driven at the start of the app
#define FREELIST_CACHE_COUNT         10000

#define CurrentEvictor LRUEvictor
#define LRUEvictor Evictor< LRUEvictionPolicy >
#define CurrentEvictorRecord CurrentEvictor::EvictRecordType

class CacheRecord : public homeds::HashNode {
public:
    typename CurrentEvictor::EvictRecordType m_evict_record;  // Information about the eviction record itself.

    const CurrentEvictor::EvictRecordType &get_evict_record() const {
        return m_evict_record;
    }

    CurrentEvictor::EvictRecordType &get_evict_record_mutable() {
        return m_evict_record;
    }

    static CacheRecord *evict_to_cache_record(const CurrentEvictor::EvictRecordType *p_erec) {
        return (p_erec? homeds::container_of(p_erec, &CacheRecord::m_evict_record) : nullptr);
    }
};

/* Number of entries we ideally want to have per hash bucket. This number if small, will reduce contention and
 * speed of read/writes, but at the cost of increased memory */
#define ENTRIES_PER_BUCKET   2

/* Number of eviction partitions. More the partitions better the parallelization of requests, but lesser the
 * effectiveness of cache, since it could get evicted sooner than expected, if distribution of key hashing is not even.*/
#define EVICTOR_PARTITIONS 32

template <typename K, typename V>
class IntrusiveCache {
public:

    static_assert(std::is_base_of<CacheRecord, V >::value,
                  "IntrusiveCache Value must be derived from CacheRecord");

    IntrusiveCache(uint64_t max_cache_size, uint32_t avg_size_per_entry);

    /* Put the raw buffer into the cache. Returns false if insert is not successful and if the key already
     * exists, it additionally fills up the out_ptr. If insert is successful, returns true and put the
     * new V also into out_ptr. */
    bool insert(V &v, V **out_ptr, const std::function<void(V *)> &found_cb = nullptr);

    /* Update the value, if it already exists or insert if not exist. Returns true if operation is successful. In
     * additon, it also populates if the out_key exists with true if key exists or false if key does not */
    bool upsert(const V &v, bool *out_key_exists);

    /* Returns the raw pointer of the data corresponding to the key */
    V* get(const K &k);

    /* Erase the key from the cache. Returns true if key exists and erased, false otherwise */
    bool erase(V &v);

    static bool is_safe_to_evict(const CurrentEvictor::EvictRecordType *rec);

protected:
    std::unique_ptr< CurrentEvictor > m_evictors[EVICTOR_PARTITIONS];
    homeds::IntrusiveHashSet< K, V > m_hash_set;
    CacheStats m_stats;
};

template <typename K>
class CacheBuffer;

template <typename K>
class Cache : protected IntrusiveCache< K, CacheBuffer< K > > {
public:
    Cache(uint64_t max_cache_size, uint32_t avg_size_per_entry);

    /* Put the raw buffer into the cache with key k. It returns whether put is successful and if so provides
     * the smart pointer of CacheBuffer. Upsert flag of false indicates if the data already exists, do not insert */
    bool insert(const K &k, const homeds::blob &b, uint32_t value_offset,
                boost::intrusive_ptr< CacheBuffer< K > > *out_smart_buf,
                const std::function<void(CacheBuffer< K > *)> &found_cb = nullptr);
    bool insert(const K &k, const boost::intrusive_ptr< CacheBuffer< K > > in_buf,
                boost::intrusive_ptr< CacheBuffer< K > > *out_smart_buf);

    /* Update is a special operation, where, it searches for the key and
     *  If found, appends the blob to the existing cached memory, new memory at specified offset.
     *  If not found, insert a new blob-offset combo into the cached memory.
     *
     *  Returns a named tuple of bools - key_found_already and successfully inserted/updated
     */
    auto update(const K &k, const homeds::blob &b, uint32_t value_offset,
                boost::intrusive_ptr< CacheBuffer<K> > *out_smart_buf);
    bool upsert(const K &k, const homeds::blob &b, boost::intrusive_ptr< CacheBuffer< K > > *out_smart_buf);
    bool get(const K &k, boost::intrusive_ptr< CacheBuffer< K > > *out_smart_buf);
    bool erase(boost::intrusive_ptr< CacheBuffer< K > > buf);
    bool erase(const K &k, boost::intrusive_ptr<CacheBuffer< K > > *removed_buf);
    const CacheStats &get_stats() {return this->m_stats;}
};

template <typename K>
class CacheBuffer : public CacheRecord {
private:
    K m_key;                                        // Key to access this cache
    homeds::MemVector< BLKSTORE_BLK_SIZE > m_mem;   // Memory address which is what this buffer contained with
    homeds::atomic_counter< uint32_t > m_refcount;  // Refcount

public:
    typedef CacheBuffer<K> CacheBufferType;

    CacheBuffer() : m_refcount(0) {}

    CacheBuffer(const K &key, const homeds::blob &blob, uint32_t offset = 0) :
            m_refcount(0) {
        m_mem.set(blob, offset);
        m_key = key;
    }

    const K &get_key() const {
        return m_key;
    }

    void set_key(K &k) {
        m_key = k;
    }

    void set_memvec(const homeds::MemVector< BLKSTORE_BLK_SIZE > &vec) {
        m_mem = vec;
    }

    const homeds::MemVector< BLKSTORE_BLK_SIZE > &get_memvec() const {
        return m_mem;
    }

    homeds::MemVector< BLKSTORE_BLK_SIZE > &get_memvec_mutable() {
        return m_mem;
    }

    homeds::blob at_offset(uint32_t offset) const {
        homeds::blob b;
        get_memvec().get(&b, offset);
        return b;
    }

    friend void intrusive_ptr_add_ref(CacheBuffer<K> *buf) {
        buf->m_refcount.increment();
    }

    friend void intrusive_ptr_release(CacheBuffer<K> *buf) {
        if (buf->m_refcount.decrement_testz()) {
            // First free the bytes it covers
            homeds::blob blob;
            buf->m_mem.get(&blob);
            free((void *) blob.bytes);

            // Then free the record itself
            homeds::ObjectAllocator< CacheBufferType >::deallocate(buf);
        }
    }

    std::string to_string() const {
        std::stringstream ss;
        ss << "Cache Key = " << m_key.to_string() << " Cache Mem = " << m_mem.to_string()
            << " Cache refcount = " << m_refcount.get();
        return ss.str();
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(CacheBuffer<K> &b) {
        b.m_refcount.increment();
    }

    static void deref(CacheBuffer<K> &b) {
        b.m_refcount.decrement();
    }

    static bool deref_testz(CacheBuffer<K> &b) {
        return b.m_refcount.decrement_testz();
    }

    static bool deref_test_le(CacheBuffer<K> &b, int32_t check) {
        return b.m_refcount.decrement_test_le(check);
    }

    static bool test_le(const CacheBuffer<K> &b, int32_t check) {
        return b.m_refcount.test_le(check);
    }

    static const K *extract_key(const CacheBuffer<K> &b) {
        return &(b.m_key);
    }

    static uint32_t get_size(const CurrentEvictor::EvictRecordType *rec) {
        const CacheBuffer<K> *cbuf = static_cast<const CacheBuffer<K> *>(CacheRecord::evict_to_cache_record(rec));
        return cbuf->get_memvec().size();
    }
};
} // namespace homestore
#endif //OMSTORAGE_CACHE_HPP
