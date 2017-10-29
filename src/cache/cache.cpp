//
// Created by Kadayam, Hari on 19/10/17.
//

#include "cache.h"
#include "omds/memory/chunk_allocator.hpp"
#include "omds/memory/sys_allocator.hpp"

namespace omstore {

////////////////////////////////// Intrusive Cache Section /////////////////////////////////
template< typename K, typename V>
IntrusiveCache<K, V>::IntrusiveCache(uint32_t max_cache_size, uint32_t avg_size_per_entry) :
        m_hash_set(max_cache_size/avg_size_per_entry/ENTRIES_PER_BUCKET) {
    for (auto i = 0; i < EVICTOR_PARTITIONS; i++) {
        m_evictors[i] = std::make_unique<Evictor< LRUEvictionPolicy > >(max_cache_size);
    }
};

template< typename K, typename V>
bool IntrusiveCache<K, V>::insert(V &v, V **out_ptr) {
    // Get the key and compute the hash code for the key
    const K *pk = V::extract_key(v);
    auto b = K::get_blob(*pk);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    // Update the cache record/evict record with the memory address of the buffer we are storing.
    CacheRecordType crec = static_cast<CacheRecordType &>(v);
    auto &new_evrec = crec.get_evict_record();
    new_evrec.m_mem.set_piece(V::get_blob(v));

    // Try adding the record into the hash set.
    bool inserted = m_hash_set.insert(*pk, v, out_ptr, hash_code);
    if (!inserted) {
        // Entry is already inside the hash, just upvote this in eviction to simulate someone has read the blk
        m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote(v);
        return false;
    }

    // If we successfully added to the hash set, inform the evictor to evict a block if needed.
    auto *evicted_rec = m_evictors[hash_code % EVICTOR_PARTITIONS]->add_record(new_evrec);
    if (evicted_rec) {
        // We indeed evicted an entry, lets remove the evicted entry from the hash set
        bool removed;
        bool found = m_hash_set.remove(*(V::extract_key(*evicted_rec)), &removed);
        assert(found);
    }
    return true;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::upsert(V &v, bool *out_key_exists) {
    // Not supported yet
    assert(0);
    return false;
}

template< typename K, typename V>
V* IntrusiveCache<K, V>::get(K &k) {
    V *v;
    auto b = K::get_blob(k);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    bool found = m_hash_set.get(k, &v, hash_code);
    if (!found) {
        return nullptr;
    }

    // We got the data from hash set, upvote the entry
    CacheRecordType crec = static_cast<CacheRecordType &>(v);
    m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote(crec.get_evict_record());

    return v;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::erase(V &v) {
    const K *pk = V::extract_key(v);
    auto b = K::get_blob(*pk);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    bool removed;
    bool found = m_hash_set.remove(*pk, &removed, hash_code);
    if (found) {
        // We successfully removed the entry from hash set. So we can remove the record from eviction list as well.
        CacheRecordType crec = static_cast<CacheRecordType &>(v);
        m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record(crec.get_evict_record());
    }
    return found;
}

////////////////////////////////// Cache Section /////////////////////////////////
template <typename K>
Cache<K>::Cache(uint32_t max_cache_size, uint32_t avg_size_per_entry) :
        IntrusiveCache<K, CacheBufferType >::IntrusiveCache(max_cache_size, avg_size_per_entry) {
    // Initialize allocators for CacheRecords
    m_allocators.add(std::make_unique< omds::ChunkMemAllocator<0, 0> >(
            sizeof(CacheBufferType), max_cache_size/avg_size_per_entry);
    m_allocators.add(std::make_unique< omds::SysMemAllocator >());
}

template <typename K>
bool Cache<K>::insert(K &k, const omds::blob b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf) {
    // Allocate a new Cachebuffer and set the blob address to it.
    auto cbuf = (CacheBufferType *)m_allocators.allocate(sizeof(CacheBufferType));
    cbuf->set(b);

    CacheBufferType *out_buf;
    bool inserted = IntrusiveCache< K, CacheBufferType >::insert(*cbuf, &out_buf);
    *out_smart_buf = boost::intrusive_ptr< CacheBufferType >(out_buf);

    return inserted;
}

template <typename K>
bool Cache<K>::get(K &k, boost::intrusive_ptr< CacheBufferType> *out_smart_buf) {
    auto cbuf = IntrusiveCache< K, CacheBufferType >::get(k);
    *out_smart_buf = boost::intrusive_ptr< CacheBufferType>(cbuf);
    return (cbuf != nullptr);
}

template <typename K>
bool Cache<K>::erase(boost::intrusive_ptr< CacheBufferType > &buf) {

}

} // namespace omstore
