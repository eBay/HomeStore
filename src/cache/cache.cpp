//
// Created by Kadayam, Hari on 19/10/17.
//

#include "cache.h"
#include "homeds/memory/obj_allocator.hpp"
#include <memory>
#include "cache_common.hpp"

namespace homestore {

////////////////////////////////// Intrusive Cache Section /////////////////////////////////
template< typename K, typename V>
IntrusiveCache<K, V>::IntrusiveCache(uint64_t max_cache_size, uint32_t avg_size_per_entry) :
        m_hash_set(max_cache_size/avg_size_per_entry/ENTRIES_PER_BUCKET) {
    LOG(INFO) << "Initializing cache with cache_size = " << max_cache_size << " with " << EVICTOR_PARTITIONS << " partitions";
    for (auto i = 0; i < EVICTOR_PARTITIONS; i++) {
        m_evictors[i] = std::make_unique<CurrentEvictor>(i, max_cache_size/EVICTOR_PARTITIONS, &m_stats,
                                                         IntrusiveCache<K, V>::is_safe_to_evict,
                                                         V::get_size);
    }
};

template< typename K, typename V>
bool IntrusiveCache<K, V>::insert(V &v, V **out_ptr, const std::function<void(V *)> &found_cb) {
    // Get the key and compute the hash code for the key
    const K *pk = V::extract_key(v);
    auto b = K::get_blob(*pk);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    DCVLOG(cache_vmod_write, 5) << "Attemping to insert in cache: " << v.to_string();

    // Try adding the record into the hash set.
    bool inserted = m_hash_set.insert(*pk, v, out_ptr, hash_code, found_cb);
    if (!inserted) {
        // Entry is already inside the hash, just upvote this in eviction to simulate someone has read the blk
        m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote((*out_ptr)->get_evict_record_mutable());
        DCVLOG(cache_vmod_write, 3) << "Following entry exist in cache already: " << (*out_ptr)->to_string();
        return false;
    }

    // If we successfully added to the hash set, inform the evictor to evict a block if needed.
    CacheRecord *evicted_rec = CacheRecord::evict_to_cache_record(
            m_evictors[hash_code % EVICTOR_PARTITIONS]->add_record(v.get_evict_record_mutable()));
    if (evicted_rec) {
        // We indeed evicted an entry, lets remove the evicted entry from the hash set
        V *evicted_v = static_cast<V *>(evicted_rec);
        DCVLOG(cache_vmod_write, 3) << "Had to evict following entry from cache: " << evicted_v->to_string();

        m_stats.inc_count(CACHE_STATS_EVICT_COUNT);
        bool found = m_hash_set.remove(*(V::extract_key(*evicted_v)));
        assert(found);
    } else {
        m_stats.inc_count(CACHE_STATS_OBJ_COUNT);
    }
    return true;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::upsert(const V &v, bool *out_key_exists) {
    // Not supported yet
    assert(0);
    return false;
}

template< typename K, typename V>
V* IntrusiveCache<K, V>::get(const K &k) {
    V *v{nullptr};
    auto b = K::get_blob(k);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    bool found = m_hash_set.get(k, &v, hash_code);
    if (!found) {
        return nullptr;
    }

    // We got the data from hash set, upvote the entry
    m_stats.inc_count(CACHE_STATS_HIT_COUNT);
    m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote(v->get_evict_record_mutable());
    return v;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::erase(V &v) {
    const K *pk = V::extract_key(v);
    auto b = K::get_blob(*pk);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    bool found = m_hash_set.remove(*pk, hash_code);
    if (found) {
        // We successfully removed the entry from hash set. So we can remove the record from eviction list as well.
        m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record(v.get_evict_record_mutable());
        m_stats.dec_count(CACHE_STATS_OBJ_COUNT);
    }
    return found;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::is_safe_to_evict(const CurrentEvictor::EvictRecordType *erec) {
    const CacheRecord *crec = CacheRecord::evict_to_cache_record(erec);
    return V::test_le((const V &)*crec, 1); // Ensure reference count is atmost one (one that is stored in hashset for)
}

////////////////////////////////// Cache Section /////////////////////////////////
template <typename K>
Cache<K>::Cache(uint64_t max_cache_size, uint32_t avg_size_per_entry) :
        IntrusiveCache<K, CacheBuffer<K> >::IntrusiveCache(max_cache_size, avg_size_per_entry) {
}

template <typename K>
bool Cache<K>::upsert(const K &k, const homeds::blob &b, boost::intrusive_ptr< CacheBuffer<K> > *out_smart_buf) {
    // TODO: Not supported yet
    assert(0);
    return false;
}

template <typename K>
bool Cache<K>::insert(const K &k, const homeds::blob &b, uint32_t value_offset,
                      boost::intrusive_ptr< CacheBuffer<K> > *out_smart_buf,
                      const std::function<void(CacheBuffer<K> *)> &found_cb) {
    // Allocate a new Cachebuffer and set the blob address to it.
    auto cbuf = homeds::ObjectAllocator< CacheBuffer<K> >::make_object(k, b, value_offset);

    CacheBuffer<K> *out_buf;
    bool inserted = IntrusiveCache< K, CacheBuffer<K> >::insert(*cbuf, &out_buf, found_cb);
    *out_smart_buf = boost::intrusive_ptr< CacheBuffer<K> >(out_buf, inserted);

    if (!inserted) {
        homeds::ObjectAllocator< CacheBuffer<K> >::deallocate(cbuf);
    }
    return inserted;
}

template <typename K>
bool Cache<K>::insert(const K &k, const boost::intrusive_ptr< CacheBuffer<K> > in_buf,
                      boost::intrusive_ptr< CacheBuffer<K> > *out_smart_buf) {
    CacheBuffer<K> *out_buf;
    bool inserted = IntrusiveCache< K, CacheBuffer<K> >::insert(*in_buf, &out_buf);
    *out_smart_buf = boost::intrusive_ptr< CacheBuffer < K > > (out_buf, inserted);

    return inserted;
}

template <typename K>
auto Cache<K>::update(const K &k, const homeds::blob &b, uint32_t value_offset,
                      boost::intrusive_ptr< CacheBuffer<K> >*out_smart_buf) {
    struct {
        bool key_found_already;
        bool success;
    } ret{false, false};
    bool appended = false;

    // First try to insert the blob into the key as is. If key is already found, use the found_cb callback to
    // atomically append the memory to the found buffer.
    bool inserted = insert(k, b, value_offset, out_smart_buf,
                           [&b, value_offset, &appended](CacheBuffer< K > *cbuf) {
                               appended = cbuf->get_memvec_mutable().append(b.bytes, value_offset, b.size);
                           });
    if (inserted) {
        // Key does not exists already and insertion at offset successful.
        ret.key_found_already = false;
        ret.success = true;
    } else {
        ret.key_found_already = true;
        ret.success = appended;
    }
    return ret;
}

template <typename K>
bool Cache<K>::get(const K &k, boost::intrusive_ptr< CacheBuffer<K>> *out_smart_buf) {
    auto cbuf = IntrusiveCache< K, CacheBuffer<K> >::get(k);
    if (cbuf) {
        *out_smart_buf = boost::intrusive_ptr< CacheBuffer<K>>(cbuf, false);
        return true;
    }
    return false;
}

template <typename K>
bool Cache<K>::erase(boost::intrusive_ptr< CacheBuffer<K> > buf) {
    return (IntrusiveCache< K, CacheBuffer<K> >::erase(*(buf.get())));
}

template <typename K >
bool Cache<K>::erase(const K &k, boost::intrusive_ptr< CacheBuffer<K> > *out_removed_buf) {
    auto b = K::get_blob(k);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    assert(out_removed_buf != nullptr);
    bool found = this->m_hash_set.remove(k, hash_code,
                                   [&out_removed_buf](CacheBuffer< K > *about_to_remove_ptr) {
                                       // Make a smart ptr of the buffer we are removing
                                       *out_removed_buf = boost::intrusive_ptr< CacheBuffer<K>>(about_to_remove_ptr);
                                   });
    if (found) {
        // We successfully removed the entry from hash set. So we can remove the record from eviction list as well.
        this->m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record((*out_removed_buf)->get_evict_record_mutable());
    }
    return found;
};
} // namespace homestore
