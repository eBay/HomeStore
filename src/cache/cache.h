//
// Created by Kadayam, Hari on 19/10/17.
//

#ifndef OMSTORAGE_CACHE_HPP
#define OMSTORAGE_CACHE_HPP

#include "eviction.cpp"
#include "omds/utility/atomic_counter.hpp"
#include "omds/hash/intrusive_hashset.hpp"
#include "lru_eviction.hpp"
#include <boost/intrusive_ptr.hpp>
#include "omds/memory/obj_allocator.hpp"

namespace omstore {

// TODO: We need to change this to config driven at the start of the app
#define FREELIST_CACHE_COUNT         10000

#define CurrentEvictor LRUEvictor
#define LRUEvictor Evictor< LRUEvictionPolicy >
#define CurrentEvictorRecord CurrentEvictor::EvictRecordType

template <typename K, typename V>
class CacheRecord : public omds::HashNode {
private:
    typename CurrentEvictor::EvictRecordType m_evict_record;  // Information about the memory.

public:
    typedef CacheRecord<K, V> CacheRecordType;

    CacheRecord() = default;
    CacheRecord(const omds::blob &b) :
            CacheRecord(b.bytes, b.size) {}
    CacheRecord(uint8_t *bytes, uint32_t size) {
        auto &blk = m_evict_record.m_mem;
        blk.set_piece(bytes, size);
    }

    void set(const omds::blob &b) {
        set(b.bytes, b.size);
    }

    void set(uint8_t *bytes, uint32_t size) {
        auto &blk = m_evict_record.m_mem;
        blk.set_piece(bytes, size);
    }

    void get(omds::blob *out_b) {
        auto &blk = m_evict_record.m_mem;
        blk.get(out_b);
    }

    typename CurrentEvictor::EvictRecordType &get_evict_record() {
        return m_evict_record;
    }

    const typename CurrentEvictor::EvictRecordType &get_evict_record_const() const {
        return m_evict_record;
    }

    static CacheRecordType *evict_to_cache_record(CurrentEvictor::EvictRecordType *p_erec) {
        return (CacheRecordType *)omds::container_of(p_erec, &CacheRecord<K, V>::m_evict_record);
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static const K *extract_key(const CacheRecordType &r) {
        return V::extract_key(r);
    }

    static void ref(CacheRecordType &r) {
        V::ref(r);
    }

    static bool deref_testz(CacheRecordType &r) {
        return V::deref_test_le(r, 0);
    }

    static omds::blob get_blob(CacheRecordType &r) {
        omds::blob b;
        r.get_evict_record().m_mem.get(&b);
        return b;
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
    typedef CacheRecord<K, V> CacheRecordType;

    static_assert(std::is_base_of<CacheRecordType, V >::value,
                  "IntrusiveCache Value must be derived from CacheRecord");

    IntrusiveCache(uint32_t max_cache_size, uint32_t avg_size_per_entry);

    /* Put the raw buffer into the cache. Returns false if insert is not successful and if the key already
     * exists, it additionally fills up the out_ptr. If insert is successful, returns true and put the
     * new V also into out_ptr. */
    bool insert(V &v, V **out_ptr);

    /* Update the value, if it already exists or insert if not exist. Returns true if operation is successful. In
     * additon, it also populates if the out_key exists with true if key exists or false if key does not */
    bool upsert(V &v, bool *out_key_exists);

    /* Returns the raw pointer of the data corresponding to the key */
    V* get(K &k);

    /* Erase the key from the cache. Returns true if key exists and erased, false otherwise */
    bool erase(V &v);

    static bool is_safe_to_evict(CurrentEvictor::EvictRecordType *rec);

private:
    std::unique_ptr< CurrentEvictor > m_evictors[EVICTOR_PARTITIONS];
    omds::IntrusiveHashSet< K, CacheRecordType > m_hash_set;
};

template <typename K>
class CacheBuffer;

template <typename K>
class Cache : private IntrusiveCache< K, CacheBuffer< K > > {
private:

public:
    typedef CacheBuffer<K> CacheBufferType;
    typedef CacheRecord<K, CacheBufferType> CacheRecordType;

    Cache(uint32_t max_cache_size, uint32_t avg_size_per_entry);

    /* Put the raw buffer into the cache with key k. It returns whether put is successful and if so provides
     * the smart pointer of CacheBuffer. Upsert flag of false indicates if the data already exists, do not insert */
    bool insert(K &k, const omds::blob &b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf);

    bool upsert(K &k, const omds::blob &b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf);

    bool get(K &k, boost::intrusive_ptr< CacheBufferType > *out_smart_buf);

    bool erase(boost::intrusive_ptr< CacheBufferType > buf);
};

template <typename K>
class CacheBuffer : public CacheRecord<K, CacheBuffer<K> > {
private:
    K m_key;                     // Key to access this cache
    omds::atomic_counter< uint32_t > m_refcount;

    typedef CacheRecord<K, CacheBuffer> CacheRecordType;
    typedef CacheBuffer<K> CacheBufferType;

public:
    CacheBuffer() : m_refcount(0) {
    }

    CacheBuffer(const K &key, uint8_t *ptr, uint32_t size) :
            CacheRecordType(ptr, size),
            m_refcount(0) {
        m_key = key;
    }

    CacheBuffer(const K &key, omds::blob blob) : CacheBuffer(key, blob.bytes, blob.size) {}

    friend void intrusive_ptr_add_ref(CacheBuffer<K> *buf) {
        buf->m_refcount.increment();
    }

    friend void intrusive_ptr_release(CacheBuffer<K> *buf) {
        if (buf->m_refcount.decrement_testz()) {
            // First free the bytes it covers
            omds::blob blob;
            buf->get_evict_record().m_mem.get(&blob);
            free((void *) blob.bytes);

            // Then free the record itself
            omds::ObjectAllocator< CacheBufferType >::deallocate(buf);
        }
    }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(CacheRecordType &r) {
        auto &b = (CacheBufferType &)r;
        b.m_refcount.increment();
    }

    static bool deref_test_le(CacheRecordType &r, int32_t check) {
        auto &b = (CacheBufferType &)r;
        return b.m_refcount.decrement_test_le(check);
    }

    static const K *extract_key(const CacheRecordType &r) {
        auto &b = (CacheBufferType &)r;
        return &(b.m_key);
    }
};

} // namespace omstore
#endif //OMSTORAGE_CACHE_HPP
