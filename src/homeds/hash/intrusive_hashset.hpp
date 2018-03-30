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
#include "homeds/utility/useful_defs.hpp"
#include <boost/intrusive/slist.hpp>
#include <boost/optional.hpp>

#ifdef GLOBAL_HASHSET_LOCK
#include <mutex>
#endif

namespace homeds {

#define read_lock()    lock(true)
#define read_unlock()  unlock(true)
#define write_lock()   lock(false)
#define write_unlock() unlock(false)

static uint64_t compute_hash_code(homeds::blob b) {
    return util::Hash64((const char *)b.bytes, (size_t)b.size);
}

class HashNode : public boost::intrusive::slist_base_hook<> {
};

////////////// hash_bucket implementation /////////////////
template <typename K, typename V>
class HashBucket
{
public:
    HashBucket() {
    }

    ~HashBucket() {
    }

    bool insert(const K &k, V &v, V **outv, const std::function<void(V *)> &found_cb = nullptr) {
        bool found = false;

        write_lock();
        auto it(m_list.begin());
        for (auto itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*V::extract_key(*it), k);
            if (x == 0) {
                *outv = &*it;
                V::ref(**outv);
                found = true;
                if (found_cb) {
                    found_cb(*outv);
                }
                break;
            } else if (x > 0) {
                break;
            }
        }

        if (!found) {
            m_list.insert(it, v);
            *outv = &v;
            V::ref(**outv);
        }
        write_unlock();
        return !found;
    }

    bool get(const K &k, V **outv) {
        bool found = false;

        read_lock();
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
        read_unlock();
        return found;
    }

    bool remove(const K &k, const std::function<void(V *)> &found_cb) {
        bool found = false;

        write_lock();
        for (auto it(m_list.begin()), itend(m_list.end()); it != itend; ++it) {
            int x = K::compare(*(V::extract_key(*it)), k);
            if (x == 0) {
                found = true;
                if (found_cb) {
                    found_cb(&*it);
                }
                V::deref(*it);
                m_list.erase(it);
                break;
            } else if (x > 0) {
                break;
            }
        }
        write_unlock();
        return found;
    }

    bool release(const K &k) {
        bool removed;
        return remove(k, &removed, nullptr);
    }

    bool release(V *n) {
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
template <typename K, typename V>
class IntrusiveHashSet {
public:
    IntrusiveHashSet(uint32_t nBuckets) {
        m_nbuckets = nBuckets;
        m_buckets = new HashBucket<K, V>[nBuckets];
    }

    ~IntrusiveHashSet() {
        delete[] m_buckets;
    }

    bool insert(V &v, V **outv, const std::function<void(V *)> &found_cb = nullptr) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard<std::mutex> lk(m);
#endif

        const K *pk = V::extract_key(v);
        HashBucket<K, V> *hb = get_bucket(*pk);
        return (hb->insert(*pk, v, outv, found_cb));
    }

    bool insert(const K &k, V &v, V **outv, uint64_t hash_code, const std::function<void(V *)> &found_cb = nullptr) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard<std::mutex> lk(m);
#endif

        HashBucket<K, V> *hb = get_bucket(hash_code);
        return (hb->insert(k, v, outv, found_cb));
    }

    bool get(const K &k, V **outv) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard<std::mutex> lk(m);
#endif
        HashBucket<K, V> *hb = get_bucket(k);
        return (hb->get(k, outv));
    }

    bool get(const K &k, V **outv, uint64_t hash_code) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard<std::mutex> lk(m);
#endif
        HashBucket<K, V> *hb = get_bucket(hash_code);
        return (hb->get(k, outv));
    }

    bool remove(const K &k, const std::function<void(V *)> &found_cb = nullptr) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard<std::mutex> lk(m);
#endif
        HashBucket<K, V> *hb = get_bucket(k);
        return (hb->remove(k, found_cb));
    }

    bool remove(const K &k, uint64_t hash_code, const std::function<void(V *)> &found_cb = nullptr) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard<std::mutex> lk(m);
#endif
        HashBucket<K, V> *hb = get_bucket(hash_code);
        return (hb->remove(k, found_cb));
    }

private:
    HashBucket<K, V> *get_bucket(const K &k) {
        return &(m_buckets[compute_hash_code(K::get_blob(k)) % m_nbuckets]);
    }

    HashBucket<K, V> *get_bucket(uint64_t hash_code) {
        return &(m_buckets[hash_code % m_nbuckets]);
    }

private:
    uint32_t m_nbuckets;
    HashBucket<K, V> *m_buckets;

#ifdef GLOBAL_HASHSET_LOCK
    std::mutex m;
#endif
};

} // namespace homeds

