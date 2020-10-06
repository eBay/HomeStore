//
// Created by Kadayam, Hari on 19/10/17.
//

#include <cstdint>
#include <functional>
#include <memory>
#include <type_traits>

#include <fds/obj_allocator.hpp>

#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_assert.hpp"

#include "cache.h"

SDS_LOGGING_DECL(cache, cache_vmod_evict, cache_vmod_read, cache_vmod_write)

namespace homestore {

//////////////////////////////////// SFINAE Hash Selection /////////////////////////////////

namespace {
template < typename T, typename = std::void_t<> >
struct is_std_hashable : std::false_type {};

template < typename T >
struct is_std_hashable< T, std::void_t< decltype(std::declval< std::hash< T > >()(std::declval< T >())) > >
        : std::true_type {};

template < typename T >
constexpr bool is_std_hashable_v{is_std_hashable< T >::value};

template < typename KeyType >
uint64_t compute_hash_imp(const KeyType& key, std::true_type) {
    return static_cast< uint64_t >(std::hash< KeyType >()(key));
}

template < typename KeyType >
uint64_t compute_hash_imp(const KeyType& key, std::false_type) {
    const auto b{KeyType::get_blob(key)};
    const uint64_t hash_code{util::Hash64(reinterpret_cast<const char*>(b.bytes), static_cast<size_t>(b.size))};
    return hash_code;
}

// range by data helper templates that does tag dispatching based on multivalued
template < typename KeyType >
uint64_t compute_hash(const KeyType& key) {
    return compute_hash_imp< KeyType >(key, is_std_hashable< KeyType >{});
}
}


////////////////////////////////// Intrusive Cache Section /////////////////////////////////
template < typename K, typename V >
IntrusiveCache< K, V >::IntrusiveCache(uint64_t max_cache_size, uint32_t avg_size_per_entry) :
        m_hash_set((max_cache_size / avg_size_per_entry) / HS_DYNAMIC_CONFIG(cache->entries_per_hash_bucket)) {
    HS_LOG(INFO, base, "Initializing cache with cache_size = {} with {} partitions", max_cache_size,
           EVICTOR_PARTITIONS);
    for (auto i = 0; i < EVICTOR_PARTITIONS; i++) {
        m_evictors[i] = std::make_unique< CurrentEvictor >(
            i, max_cache_size / EVICTOR_PARTITIONS,
            (std::bind(&IntrusiveCache< K, V >::is_safe_to_evict, this, std::placeholders::_1)), V::get_size);
    }
};

template < typename K, typename V >
bool IntrusiveCache< K, V >::insert(V& v, V** out_ptr, const auto& found_cb) {
    // Get the key and compute the hash code for the key
    const K* const pk{V::extract_key(v)};
    const uint64_t hash_code{compute_hash< K >(*pk)};
    HS_LOG(DEBUG, cache, "Attemping to insert in cache: {} key {}", v.to_string(), pk->to_string());

    // Try adding the record into the hash set.
    bool inserted = m_hash_set.insert(*pk, v, out_ptr, hash_code, found_cb);
    if (!inserted) {
        // Entry is already inside the hash, just upvote this in eviction to simulate someone has read the blk
        (*out_ptr)->lock();
        if ((*out_ptr)->get_cache_state() == CACHE_INSERTED) {
            m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote((*out_ptr)->get_evict_record_mutable());
        }
        (*out_ptr)->unlock();
        HS_LOG(DEBUG, cache, "Following entry exist in cache already: {}", (*out_ptr)->to_string());
        COUNTER_INCREMENT(m_metrics, cache_num_duplicate_inserts, 1);
        return false;
    }

    // If we successfully added to the hash set, inform the evictor to evict a block if needed.
    v.lock();
    bool ret = true;
    if (v.get_cache_state() == CACHE_NOT_INSERTED &&
        m_evictors[hash_code % EVICTOR_PARTITIONS]->add_record(v.get_evict_record_mutable())) {
        COUNTER_INCREMENT(m_metrics, cache_insert_count, 1);
        COUNTER_INCREMENT(m_metrics, cache_object_count, 1);
        COUNTER_INCREMENT(m_metrics, cache_size, V::get_size(&(v.get_evict_record_mutable())));
        v.on_cache_insert();
    } else {
        /* remove from the hash table */
        HS_LOG(INFO, cache, "Unable to evict any record, removing entry {} from cache", v.to_string());
        COUNTER_INCREMENT(m_metrics, cache_add_error_count, 1);
        m_hash_set.remove(*pk, hash_code, NULL_LAMBDA);
        ret = false;
    }
    v.unlock();
    return ret;
}

/* This api is called when size of an existing entry is modified in hash */
template < typename K, typename V >
bool IntrusiveCache< K, V >::modify_size(V& v, uint32_t size) {
    const K* const pk{V::extract_key(v)};
    const uint64_t hash_code{compute_hash< K >(*pk)};
    auto ret = (m_evictors[hash_code % EVICTOR_PARTITIONS]->modify_size(size));

    if (ret) { COUNTER_INCREMENT(m_metrics, cache_size, size); }

    return ret;
}

template < typename K, typename V >
bool IntrusiveCache< K, V >::upsert(const V& v, bool* out_key_exists) {
    // Not supported yet
    HS_ASSERT(DEBUG, 0, "Not Supported yet!");
    return false;
}

template < typename K, typename V >
V* IntrusiveCache< K, V >::get(const K& k) {
    V* v{nullptr};
    const uint64_t hash_code{compute_hash< K >(k)};

    bool found = m_hash_set.get(k, &v, hash_code);
    if (!found) { return nullptr; }

    v->lock();
    if (v->get_cache_state() == CACHE_INSERTED) {
        // We got the data from hash set, upvote the entry
        COUNTER_INCREMENT(m_metrics, cache_read_count, 1);
        m_evictors[hash_code % EVICTOR_PARTITIONS]->upvote(v->get_evict_record_mutable());
    }

    v->unlock();
    return v;
}

template < typename K, typename V >
bool IntrusiveCache< K, V >::erase(V& v) {
    const K* const pk{V::extract_key(v)};
    const uint64_t hash_code{compute_hash< K >(*pk)};

    bool found = m_hash_set.remove(*pk, hash_code, NULL_LAMBDA);
    if (found) {
        v.lock();
        if (v->get_cache_state() == CACHE_INSERTED) {
            // We successfully removed the entry from hash set. So we can remove the record from eviction list as well.
            m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record(v.get_evict_record_mutable());
            COUNTER_INCREMENT(m_metrics, cache_erase_count, 1);
            COUNTER_DECREMENT(m_metrics, cache_object_count, 1);
            COUNTER_DECREMENT(m_metrics, cache_size, V::get_size(v.get_evict_record_mutable()));
            v.on_cache_evict();
        }
        v.unlock();
    }
    return found;
}

template < typename K, typename V >
bool IntrusiveCache< K, V >::is_safe_to_evict(const CurrentEvictor::EvictRecordType* erec) {
    /* Should not evict the record if anyone is using it. It would break the btree locking logic
     * which depends on cache not freeing the object if it is using it.
     */
    const CacheRecord* crec = CacheRecord::evict_to_cache_record(erec);
    V* v = (V*)crec;
    bool safe_to_evict = false;

    if (V::test_le(reinterpret_cast< const V& >(*crec), 1)) { // Ensure reference count is atmost one (one that is stored in hashset for)
        /* we can not wait for the lock if there is contention as it can lead to
         * deadlock. This API is called under the eviction lock. Normally, eviction
         * lock is taken after taking this lock in case of insert and erase.
         * Here we need to take the lock to set the cache state.
         */
        if (v->try_lock()) {
            boost::intrusive_ptr< CacheBuffer< K > > out_removed_buf(nullptr);
            HS_ASSERT_CMP(LOGMSG, v->get_cache_state(), ==, CACHE_INSERTED);
            /* It remove the entry only if ref cnt is one */
            const K* const pk { V::extract_key(reinterpret_cast<const V&>(*crec)) };
            const uint64_t hash_code{compute_hash< K >(*pk)};
            auto ret =
                m_hash_set.check_and_remove(*pk, hash_code, [&out_removed_buf](CacheBuffer< K >* about_to_remove_ptr) {
                    // Make a smart ptr of the buffer we are removing
                    out_removed_buf = boost::intrusive_ptr< CacheBuffer< K > >(about_to_remove_ptr);
                });
            if (ret) {
                v->on_cache_evict();
                COUNTER_DECREMENT(m_metrics, cache_object_count, 1);
                COUNTER_DECREMENT(m_metrics, cache_size, V::get_size(erec));
            }
            v->unlock();
            safe_to_evict = ret;
        }
    }

    COUNTER_INCREMENT_IF_ELSE(m_metrics, safe_to_evict, cache_num_evictions, cache_num_evictions_punt, 1);
    return safe_to_evict;
}

////////////////////////////////// Cache Section /////////////////////////////////
template < typename K >
Cache< K >::Cache(uint64_t max_cache_size, uint32_t avg_size_per_entry) :
        IntrusiveCache< K, CacheBuffer< K > >::IntrusiveCache(max_cache_size, avg_size_per_entry) {}

template < typename K >
Cache< K >::~Cache() {}

template < typename K >
bool Cache< K >::upsert(const K& k, const sisl::blob& b, boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf) {
    // TODO: Not supported yet
    HS_ASSERT(DEBUG, 0, "Not Supported yet!");
    return false;
}

template < typename K >
bool Cache< K >::insert(const K& k, const sisl::blob& b, uint32_t value_offset,
                        boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf, const auto& found_cb) {
    // Allocate a new Cachebuffer and set the blob address to it.
    auto cbuf = sisl::ObjectAllocator< CacheBuffer< K > >::make_object(k, b, this, value_offset);

    CacheBuffer< K >* out_buf;
    bool inserted = IntrusiveCache< K, CacheBuffer< K > >::insert(*cbuf, &out_buf, found_cb);
    if (out_buf != nullptr) { *out_smart_buf = boost::intrusive_ptr< CacheBuffer< K > >(out_buf, false); }

    (*out_smart_buf)->set_cache(this);
    if (!inserted) { sisl::ObjectAllocator< CacheBuffer< K > >::deallocate(cbuf); }
    return inserted;
}

template < typename K >
bool Cache< K >::insert(const K& k, const boost::intrusive_ptr< CacheBuffer< K > > in_buf,
                        boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf) {
    CacheBuffer< K >* out_buf;
    bool inserted = IntrusiveCache< K, CacheBuffer< K > >::insert(*in_buf, &out_buf, NULL_LAMBDA);
    if (out_buf != nullptr) { *out_smart_buf = boost::intrusive_ptr< CacheBuffer< K > >(out_buf, false); }

    (*out_smart_buf)->set_cache(this);
    return inserted;
}

template < typename K >
bool Cache< K >::insert_missing_pieces(const boost::intrusive_ptr< CacheBuffer< K > > buf, uint32_t offset,
                                       uint32_t size_to_read,
                                       std::vector< std::pair< uint32_t, uint32_t > >& missing_mp) {
    bool inserted = false;
    auto size = buf->insert_missing_pieces(offset, size_to_read, missing_mp);
    /* check if buffer is still part of cache or not */
    buf->lock();
    if (buf->get_cache_state() == CACHE_INSERTED) {
        inserted = IntrusiveCache< K, CacheBuffer< K > >::modify_size(*buf, size);
        if (inserted) { buf->modify_cache_size(size); }
    }
    buf->unlock();
    return inserted;
}

template < typename K >
auto Cache< K >::update(const K& k, const sisl::blob& b, uint32_t value_offset,
                        boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf) {
    struct {
        bool key_found_already;
        bool success;
    } ret{false, false};
    bool appended = false;

    // First try to insert the blob into the key as is. If key is already found, use the found_cb callback to
    // atomically append the memory to the found buffer.
    bool inserted = insert(k, b, value_offset, out_smart_buf, [&b, value_offset, &appended](CacheBuffer< K >* cbuf) {
        appended = cbuf->get_memvec().append(b.bytes, value_offset, b.size);
    });
    if (inserted) {
        // Key does not exists already and insertion at offset successful.
        ret.key_found_already = false;
        ret.success = true;
    } else {
        ret.key_found_already = true;
        ret.success = appended;
        if (appended) { COUNTER_INCREMENT(this->m_metrics, cache_update_count, 1); }
    }
    return ret;
}

template < typename K >
bool Cache< K >::get(const K& k, boost::intrusive_ptr< CacheBuffer< K > >* out_smart_buf) {
    auto cbuf = IntrusiveCache< K, CacheBuffer< K > >::get(k);
    if (cbuf) {
        *out_smart_buf = boost::intrusive_ptr< CacheBuffer< K > >(cbuf, false);
        return true;
    }
    return false;
}

/* While calling this API, Caller ensures that there is no reference to this buffer. We simply
 * remove it without checking for the ref_cnt.
 */
template < typename K >
bool Cache< K >::erase(boost::intrusive_ptr< CacheBuffer< K > > buf) {
    const K* pk = CacheBuffer< K >::extract_key(*buf);
    return (erase(*pk, 0, 0, nullptr));
}

template < typename K >
bool Cache< K >::erase(const K& k, boost::intrusive_ptr< CacheBuffer< K > >* out_bbuf) {
    return (erase(k, 0, 0, out_bbuf));
}

/* It remove the entry from the cache right away. It doesn't wait for ref_cnt to
 * be zero. Currently it doesn't support partial cache remove. It remove
 * the full entry. But functionality can be easily extended later easily.
 * if size is zero, it means it has to free the full entry.
 */
template < typename K >
bool Cache< K >::erase(const K& k, uint32_t offset, uint32_t size,
                       boost::intrusive_ptr< CacheBuffer< K > >* ret_removed_buf) {
    const uint64_t hash_code{compute_hash< K >(k)};
    boost::intrusive_ptr< CacheBuffer< K > > out_removed_buf(nullptr);

    bool found = this->m_hash_set.remove(k, hash_code, [&out_removed_buf](CacheBuffer< K >* about_to_remove_ptr) {
        // Make a smart ptr of the buffer we are removing
        out_removed_buf = boost::intrusive_ptr< CacheBuffer< K > >(about_to_remove_ptr);
    });
    if (found) {
        out_removed_buf->lock();
        if (out_removed_buf->get_cache_state() == CACHE_INSERTED) {
            // We successfully removed the entry from hash set. So we can remove the record from eviction list as well.
            COUNTER_DECREMENT(this->m_metrics, cache_size,
                              CacheBuffer< K >::get_size(&(out_removed_buf->get_evict_record_mutable())));
            COUNTER_INCREMENT(this->m_metrics, cache_erase_count, 1);
            COUNTER_DECREMENT(this->m_metrics, cache_object_count, 1);
            this->m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record(
                (out_removed_buf)->get_evict_record_mutable());
            out_removed_buf->on_cache_evict();
        }
        out_removed_buf->unlock();
    }

    if (ret_removed_buf != nullptr && out_removed_buf != nullptr) { *ret_removed_buf = out_removed_buf; }
    return found;
};

template < typename K >
void Cache< K >::safe_erase(boost::intrusive_ptr< CacheBuffer< K > > buf, const erase_comp_cb& cb) {
    const K* pk = CacheBuffer< K >::extract_key(*buf);
    safe_erase(*pk, cb);
}

/* It remove the buffer only when ref_cnt becomes zero. If it is not zero, it set the state
 * and delete it later when ref_count becomes zero. Until then, Caller can get the entry
 * from the cache if it asks for the entry. We don't support partial cache free in
 * case of safe_erase. Entry has to be fully removed.
 */
template < typename K >
void Cache< K >::safe_erase(const K& k, const erase_comp_cb& cb) {
    /* we don't support partial cache entry for safe_erase. */
    const uint64_t hash_code{compute_hash< K >(k)};
    boost::intrusive_ptr< CacheBuffer< K > > out_buf(nullptr);
    bool can_remove = false;
    ;

    bool found =
        this->m_hash_set.safe_remove(k, hash_code, can_remove, [&out_buf](CacheBuffer< K >* about_to_remove_ptr) {
            // Make a smart ptr of the buffer we are removing
            out_buf = boost::intrusive_ptr< CacheBuffer< K > >(about_to_remove_ptr);
        });
    if (found) {
        if (cb != nullptr) {
            HS_ASSERT_NOTNULL(DEBUG, out_buf.get());
            out_buf->set_cb(cb);
        }
        if (can_remove) {
            // We successfully removed the entry from hash set. So we can remove the record from eviction list as well.
            out_buf->lock();
            if (out_buf->get_cache_state() == CACHE_INSERTED) {
                COUNTER_INCREMENT(this->m_metrics, cache_erase_count, 1);
                COUNTER_DECREMENT(this->m_metrics, cache_object_count, 1);
                COUNTER_DECREMENT(this->m_metrics, cache_size,
                                  CacheBuffer< K >::get_size(&(out_buf->get_evict_record_mutable())));
                this->m_evictors[hash_code % EVICTOR_PARTITIONS]->delete_record((out_buf)->get_evict_record_mutable());
                out_buf->on_cache_evict();
            }
            out_buf->unlock();

            auto cb = out_buf->get_cb();
            if (cb != nullptr) { cb(out_buf); }
        }
    } else {
        HS_ASSERT_CMP(DEBUG, can_remove, ==, false);
        cb(out_buf);
    }
};
} // namespace homestore
