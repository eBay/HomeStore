//
// Created by Kadayam, Hari on 19/10/17.
//

#ifndef OMSTORAGE_CACHE_HPP
#define OMSTORAGE_CACHE_HPP

#include "eviction.hpp"
#include "omds/utility/atomic_counter.hpp"
#include "omds/hash/intrusive_hashset.hpp"
#include "omds/memory/composite_allocator.hpp"
#include "lru_eviction.hpp"
#include <boost/intrusive_ptr.hpp>

namespace omstore {

template <typename K, typename V, typename EvictionPolicy>
class CacheRecord : public omds::HashNode {
private:
    typename Evictor<EvictionPolicy>::EvictRecordType m_evict_record;  // Information about the memory.

public:
    typedef CacheRecord<K, V, EvictionPolicy> CacheRecordType;

    CacheRecord() = default;
    CacheRecord(const omds::blob &b) :
            CacheRecord(b.bytes, b.size) {}
    CacheRecord(uint8_t *bytes, uint32_t size) {
        auto &blk = m_evict_record.get_mem_blk();
        blk.set_piece(bytes, size);
    }

    void set(const omds::blob &b) {
        set(b.bytes, b.size);
    }

    void set(uint8_t *bytes, uint32_t size) {
        auto &blk = m_evict_record.get_mem_blk();
        blk.set_piece(bytes, size);
    }

    typename Evictor<EvictionPolicy>::EvictRecordType &get_evict_record() {
        return m_evict_record;
    }

    static const K *extract_key(const CacheRecordType *r) {
        return &V::extract_key(r);
    }

    static void ref(CacheRecordType &pr) {
        V::ref(pr);
    }

    static bool deref_testz(CacheRecordType &pr) {
        return V::deref_testz(pr);
    }
};

template <typename K, typename EvictionPolicy>
class CacheBuffer : public CacheRecord<K, CacheBuffer<K, EvictionPolicy>, EvictionPolicy> {
private:
    K m_key;                     // Key to access this cache
    omds::atomic_counter< uint32_t > m_refcount;

    typedef CacheRecord<K, CacheBuffer, EvictionPolicy> CacheRecordType;
    typedef CacheBuffer<K, EvictionPolicy> CacheBufferType;

public:
    CacheBuffer() : m_refcount(0) {
    }

    CacheBuffer(uint8_t *ptr, uint32_t size) :
            CacheRecordType(ptr, size),
            m_refcount(0) {
    }

    friend void intrusive_ptr_add_ref(const CacheBufferType *b) {
        b->m_refcount.increment();
    }

    friend void intrusive_ptr_release(const CacheBufferType *b) {
        if (b->m_refcount.decrement_testz()) {
            delete(b);
        }
    }

    static void ref(CacheRecordType &r) {
        auto &b = dynamic_cast<CacheBufferType &>(r);
        b.m_refcount.increment();
    }

    static bool deref_testz(CacheRecordType &r) {
        auto &b = dynamic_cast<CacheBufferType &>(r);
        return b.m_refcount.decrement_testz();
    }

    static const K *extract_key(const CacheRecordType &r) {
        auto &b = dynamic_cast<const CacheBufferType &>(r);
        return &(b.m_key);
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
    typedef CacheRecord<K, V, LRUEvictionPolicy> CacheRecordType;

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

private:
    std::unique_ptr< Evictor< LRUEvictionPolicy > > m_evictors[EVICTOR_PARTITIONS];
    omds::IntrusiveHashSet< K, V > m_hash_set;
};


template <typename K>
class Cache : private IntrusiveCache< K, CacheBuffer> {
public:
    typedef CacheRecord<K, CacheBuffer, LRUEvictionPolicy> CacheRecordType;
    typedef CacheBuffer<K, LRUEvictionPolicy> CacheBufferType;

    Cache(uint32_t max_cache_size, uint32_t avg_size_per_entry);

    /* Put the raw buffer into the cache with key k. It returns whether put is successful and if so provides
     * the smart pointer of CacheBuffer. Upsert flag of false indicates if the data already exists, do not insert */
    bool insert(K &k, const omds::blob b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf);

    bool upsert(K &k, const omds::blob b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf);

    bool get(K &k, boost::intrusive_ptr< CacheBufferType > *out_smart_buf);

    bool erase(boost::intrusive_ptr< CacheBufferType > &buf);

private:
    omds::StackedMemAllocator m_allocators;
};

} // namespace omstore
#endif //OMSTORAGE_CACHE_HPP
