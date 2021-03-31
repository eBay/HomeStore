/*
 * hashmap.hpp
 *
 *  Created on: 20-Dec-2015
 *      Author: hkadayam
 */
#pragma once

#include <cassert>
#include <atomic>
#include <memory>
#include <farmhash.h>
#include <folly/SharedMutex.h>
#include <fds/utils.hpp>
#include <boost/intrusive/slist.hpp>
#include <boost/optional.hpp>
#include "engine/common/homestore_header.hpp"

#ifdef GLOBAL_HASHSET_LOCK
#include <mutex>
#endif

namespace homeds {

#define hash_read_lock() lock(true)
#define hash_read_unlock() unlock(true)
#define hash_write_lock() lock(false)
#define hash_write_unlock() unlock(false)

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
    const uint64_t hash_code{util::Hash64(reinterpret_cast< const char* >(b.bytes), static_cast< size_t >(b.size))};
    return hash_code;
}

// range by data helper templates that does tag dispatching based on multivalued
template < typename KeyType >
uint64_t compute_hash(const KeyType& key) {
    return compute_hash_imp< KeyType >(key, is_std_hashable< KeyType >{});
}
} // namespace

class HashNode : public boost::intrusive::slist_base_hook<> {};

////////////// hash_bucket implementation /////////////////
template < typename K, typename V >
class HashBucket {
public:
    HashBucket() {}

    ~HashBucket() {
        auto it(m_list.begin());
        while (it != m_list.end()) {
            m_list.erase(it);
            V::deref(*it); // <<< Dobule free which will decrease CacheBuffer::m_refcount to -1 during shutdown
            it = m_list.begin();
        }
    }

    bool insert(const K& k, V& v, V** outv, const auto& found_cb) {
        bool found = false;

        hash_write_lock();
        auto it(m_list.begin());
        for (auto itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*V::extract_key(*it), k);
            if (x == 0) {
                *outv = &*it;
                V::ref(**outv);
                found = true;
                found_cb(*outv);
                break;
            } else if (x > 0) {
                break;
            }
        }

        if (!found) {
            m_list.insert(it, v);
            *outv = &v;
            /* first reference is for the hash set and second for return value.
             * it is caller responsibility to decrement the ref count if it does not
             * intend to use.
             */
            V::ref(**outv);
            V::ref(**outv);
        }
        hash_write_unlock();
        return !found;
    }

    bool get(const K& k, V** outv) {
        bool found = false;

        hash_read_lock();
        for (auto it(m_list.begin()), itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*(V::extract_key(*it)), k);
            if (x == 0) {
                found = true;
                *outv = &*it;
                V::ref(**outv);
                break;
            } else if (x > 0) {
                found = false;
                break;
            }
        }
        hash_read_unlock();
        return found;
    }

    bool remove(const K& k, const auto& found_cb) {
        bool found = false;

        hash_write_lock();
        for (auto it(m_list.begin()), itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*(V::extract_key(*it)), k);
            if (x == 0) {
                found = true;
                found_cb(&*it);
                m_list.erase(it);
                V::deref(*it);
                break;
            } else if (x > 0) {
                break;
            }
        }
        hash_write_unlock();
        return found;
    }

    uint64_t get_size() { return m_list.size(); }

    bool safe_remove(const K& k, const auto& found_cb, bool& can_remove) {
        bool ret = false;

        hash_write_lock();
        for (auto it(m_list.begin()), itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*(V::extract_key(*it)), k);
            if (x == 0) {

                /* set the state. It doesn't free the buffer
                 * right away if ref count is not 1. It set the
                 * state and free it later when ref count becomes 1
                 */
                V::set_free_state(*it);
                ret = true;
                if (V::test_le((const V&)*it, 1)) {
                    can_remove = true;
                    found_cb(&*it);
                    m_list.erase(it);
                    hash_write_unlock();
                    V::reset_free_state(*it);
                    /* don't call deref while holding the lock */
                    V::deref(*it);
                    hash_write_lock();
                } else {
                    found_cb(&*it);
                }
                break;
            } else if (x > 0) {
                break;
            }
        }
        hash_write_unlock();
        return ret;
    }

    /* It remove only if ref_cnt is 1 */
    bool check_and_remove(const K& k, const auto& found_cb, bool dec_ref = false) {
        bool ret = false;

        hash_write_lock();
        for (auto it(m_list.begin()), itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*(V::extract_key(*it)), k);
            if (x == 0) {
                if (dec_ref) { V::deref(*it); }
                if (V::test_le((const V&)*it, 1)) {
                    found_cb(&*it);
                    m_list.erase(it);
                    V::deref(*it);
                    ret = true;
                } else {
                    ret = false;
                }
                break;
            } else if (x > 0) {
                break;
            }
        }
        hash_write_unlock();
        return ret;
    }

    bool release(const K& k) {
        bool removed;
        return remove(k, &removed, nullptr);
    }

    bool release(V* n) {
        bool removed;
        return remove(*(V::extract_key(n)), &removed, nullptr);
    }

    void lock(bool shared) {
#ifndef GLOBAL_HASHSET_LOCK
        if (shared) {
            m_lock.lock_shared();
        } else {
            m_lock.lock();
        }
#endif
    }

    void unlock(bool shared) {
#ifndef GLOBAL_HASHSET_LOCK
        if (shared) {
            m_lock.unlock_shared();
        } else {
            m_lock.unlock();
        }
#endif
    }

private:
#ifndef GLOBAL_HASHSET_LOCK
    folly::SharedMutexReadPriority m_lock;
#endif
    typedef boost::intrusive::slist< V > hash_node_list;
    hash_node_list m_list;
};

////////////// hash_table implementation /////////////////
template < typename K, typename V >
class IntrusiveHashSet {
public:
    IntrusiveHashSet(uint32_t nBuckets) {
        m_size = 0;
        m_nbuckets = nBuckets;
        m_buckets = new HashBucket< K, V >[nBuckets];
    }

    ~IntrusiveHashSet() { delete[] m_buckets; }

    uint64_t get_size() const {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        return m_size;
    }

    bool insert(V& v, V** outv, const auto& found_cb) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        const K* pk = V::extract_key(v);
        HashBucket< K, V >* hb = get_bucket(*pk);
        bool inserted = (hb->insert(*pk, v, outv, found_cb));
        if (inserted) m_size++;
        return inserted;
    }

    bool insert(const K& k, V& v, V** outv, uint64_t hash_code, const auto& found_cb) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif

        HashBucket< K, V >* hb = get_bucket(hash_code);
        bool inserted = (hb->insert(k, v, outv, found_cb));
        if (inserted) m_size++;
        return inserted;
    }

    bool get(const K& k, V** outv) const {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        HashBucket< K, V >* hb = get_bucket(k);
        return (hb->get(k, outv));
    }

    bool get(const K& k, V** outv, uint64_t hash_code) const {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        HashBucket< K, V >* hb = get_bucket(hash_code);
        return (hb->get(k, outv));
    }

    bool safe_remove(const K& k, uint64_t hash_code, bool& can_remove, const auto& found_cb) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        HashBucket< K, V >* hb = get_bucket(hash_code);
        bool removed = (hb->safe_remove(k, found_cb, can_remove));
        if (removed) m_size--;
        return removed;
    }

    bool remove(const K& k, const auto& found_cb) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        HashBucket< K, V >* hb = get_bucket(k);
        bool removed = (hb->remove(k, found_cb));
        if (removed) m_size--;
        return removed;
    }

    bool remove(const K& k, uint64_t hash_code, const auto& found_cb) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        HashBucket< K, V >* hb = get_bucket(hash_code);
        bool removed = (hb->remove(k, found_cb));
        if (removed) m_size--;
        return removed;
    }

    bool check_and_remove(const K& k, uint64_t hash_code, const auto& found_cb, bool dec_ref = false) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk(m);
#endif
        HashBucket< K, V >* hb = get_bucket(hash_code);
        bool removed = (hb->check_and_remove(k, found_cb, dec_ref));
        if (removed) m_size--;
        return removed;
    }

private:
    HashBucket< K, V >* get_bucket(const K& k) const { return &(m_buckets[compute_hash(k) % m_nbuckets]); }

    HashBucket< K, V >* get_bucket(uint64_t hash_code) const { return &(m_buckets[hash_code % m_nbuckets]); }

private:
    std::atomic< uint64_t > m_size;
    uint32_t m_nbuckets;
    HashBucket< K, V >* m_buckets;

#ifdef GLOBAL_HASHSET_LOCK
    mutable std::mutex m;
#endif
};

} // namespace homeds
