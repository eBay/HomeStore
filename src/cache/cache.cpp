//
// Created by Kadayam, Hari on 19/10/17.
//

#include "cache.h"
#include "omds/memory/obj_allocator.hpp"
#include <memory>

namespace omstore {

////////////////////////////////// Intrusive Cache Section /////////////////////////////////
template< typename K, typename V>
IntrusiveCache<K, V>::IntrusiveCache(uint32_t max_cache_size, uint32_t avg_size_per_entry) :
        m_hash_set(max_cache_size/avg_size_per_entry/ENTRIES_PER_BUCKET) {
    for (auto i = 0; i < EVICTOR_PARTITIONS; i++) {
        m_evictors[i] = std::make_unique<CurrentEvictor>(max_cache_size, IntrusiveCache<K, V>::is_safe_to_evict,
                                                         V::get_size);
    }
};

template< typename K, typename V>
bool IntrusiveCache<K, V>::insert(V &v, V **out_ptr, const std::function<void(V *)> &found_cb) {
    // Get the key and compute the hash code for the key
    const K *pk = V::extract_key(v);
    auto b = K::get_blob(*pk);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    // Try adding the record into the hash set.
    bool inserted = m_hash_set.insert(*pk, v, out_ptr, hash_code, found_cb);
    if (!inserted) {
        // Entry is already inside the hash, just upvote this in eviction to simulate someone has read the blk
        m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote((*out_ptr)->get_evict_record_mutable());
        return false;
    }

    // If we successfully added to the hash set, inform the evictor to evict a block if needed.
    CacheRecord *evicted_rec = (CacheRecord *)
            m_evictors[hash_code % EVICTOR_PARTITIONS]->add_record(v.get_evict_record_mutable());
    if (evicted_rec) {
        // We indeed evicted an entry, lets remove the evicted entry from the hash set
        V *evicted_v = static_cast<V *>(evicted_rec);
        bool found = m_hash_set.remove(*(V::extract_key(*evicted_v)));
        assert(found);
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
    V *v;
    auto b = K::get_blob(k);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    bool found = m_hash_set.get(k, &v, hash_code);
    if (!found) {
        return nullptr;
    }

    // We got the data from hash set, upvote the entry
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
    }
    return found;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::is_safe_to_evict(CurrentEvictor::EvictRecordType *erec) {
    CacheRecord *crec = CacheRecord::evict_to_cache_record(erec);
    return V::deref_test_le((V &)*crec, 1); // Ensure reference count is atmost one (one that is stored in hashset for)
}

////////////////////////////////// Cache Section /////////////////////////////////
template <typename K>
Cache<K>::Cache(uint32_t max_cache_size, uint32_t avg_size_per_entry) :
        IntrusiveCache<K, CacheBuffer<K> >::IntrusiveCache(max_cache_size, avg_size_per_entry) {
}

template <typename K>
bool Cache<K>::upsert(const K &k, const omds::blob &b, boost::intrusive_ptr< CacheBuffer<K> > *out_smart_buf) {
    // TODO: Not supported yet
    assert(0);
    return false;
}

template <typename K>
bool Cache<K>::insert(const K &k, const omds::blob &b, uint32_t value_offset,
                      boost::intrusive_ptr< CacheBuffer<K> > *out_smart_buf,
                      const std::function<void(CacheBuffer<K> *)> &found_cb) {
    // Allocate a new Cachebuffer and set the blob address to it.
    auto cbuf = omds::ObjectAllocator< CacheBuffer<K> >::make_object(k, b, value_offset);

    CacheBuffer<K> *out_buf;
    bool inserted = IntrusiveCache< K, CacheBuffer<K> >::insert(*cbuf, &out_buf, found_cb);
    *out_smart_buf = boost::intrusive_ptr< CacheBuffer<K> >(out_buf, inserted);

    if (!inserted) {
        omds::ObjectAllocator< CacheBuffer<K> >::deallocate(cbuf);
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
auto Cache<K>::update(const K &k, const omds::blob &b, uint32_t value_offset,
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
#if 0
////////////////////////////////// Intrusive Cache Section /////////////////////////////////
template< typename K, typename V>
IntrusiveCache<K, V>::IntrusiveCache(uint32_t max_cache_size, uint32_t avg_size_per_entry) :
        m_hash_set(max_cache_size/avg_size_per_entry/ENTRIES_PER_BUCKET) {
    for (auto i = 0; i < EVICTOR_PARTITIONS; i++) {
        m_evictors[i] = std::make_unique<CurrentEvictor>(max_cache_size, IntrusiveCache<K, V>::is_safe_to_evict);
    }
};

template< typename K, typename V>
bool IntrusiveCache<K, V>::insert(V &v, V **out_ptr) {
    // Get the key and compute the hash code for the key
    const K *pk = V::extract_key(v);
    auto b = K::get_blob(*pk);
    uint64_t hash_code = util::Hash64((const char *)b.bytes, (size_t)b.size);

    // Update the cache record/evict record with the memory address of the buffer we are storing.
    CacheRecordType &crec = static_cast<CacheRecordType &>(v);
    auto &new_evrec = crec.get_evict_record();
    new_evrec.m_mem = V::get_mem(v);

    // Try adding the record into the hash set.
    CacheRecordType **out_rec = (CacheRecordType **)out_ptr;
    bool inserted = m_hash_set.insert(*pk, crec, out_rec, hash_code);
    if (!inserted) {
        // Entry is already inside the hash, just upvote this in eviction to simulate someone has read the blk
        m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote((*out_rec)->get_evict_record());
        return false;
    }

    // If we successfully added to the hash set, inform the evictor to evict a block if needed.
    CacheRecordType *evicted_rec = (CacheRecordType *)m_evictors[hash_code % EVICTOR_PARTITIONS]->add_record(new_evrec);
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

    bool found = m_hash_set.get(k, (CacheRecordType **)&v, hash_code);
    if (!found) {
        return nullptr;
    }

    // We got the data from hash set, upvote the entry
    CacheRecordType *crec = static_cast<CacheRecordType *>(v);
    m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote(crec->get_evict_record());

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
        CacheRecordType &crec = static_cast<CacheRecordType &>(v);
        m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record(crec.get_evict_record());
    }
    return found;
}

template< typename K, typename V>
bool IntrusiveCache<K, V>::is_safe_to_evict(CurrentEvictor::EvictRecordType *erec) {
    auto *crec = CacheRecordType::evict_to_cache_record(erec);
    return V::deref_test_le(*crec, 1); // Ensure reference count is atmost one (one that is stored in hashset for)
}

////////////////////////////////// Cache Section /////////////////////////////////
template <typename K>
Cache<K>::Cache(uint32_t max_cache_size, uint32_t avg_size_per_entry) :
        IntrusiveCache<K, CacheBufferType >::IntrusiveCache(max_cache_size, avg_size_per_entry) {
}

template <typename K>
bool Cache<K>::upsert(K &k, const omds::blob &b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf) {
    // TODO: Not supported yet
    assert(0);
    return false;
}

template <typename K>
bool Cache<K>::insert(K &k, const omds::blob &b, boost::intrusive_ptr< CacheBufferType > *out_smart_buf) {
    // Allocate a new Cachebuffer and set the blob address to it.
    auto cbuf = omds::ObjectAllocator< CacheBufferType >::make_object(k, b);

    CacheBufferType *out_buf;
    bool inserted = IntrusiveCache< K, CacheBufferType >::insert(*cbuf, &out_buf);
    *out_smart_buf = boost::intrusive_ptr< CacheBufferType >(out_buf);

    return inserted;
}

template <typename K>
bool Cache<K>::insert(K &k, const boost::intrusive_ptr< CacheBufferType > in_buf,
                      boost::intrusive_ptr< CacheBufferType > *out_smart_buf) {
    CacheBufferType *out_buf;
    bool inserted = IntrusiveCache< K, CacheBufferType >::insert(*in_buf, &out_buf);
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
bool Cache<K>::erase(boost::intrusive_ptr< CacheBufferType > buf) {
    return (IntrusiveCache< K, CacheBufferType >::erase(*(buf.get())));
}
#endif
} // namespace omstore
