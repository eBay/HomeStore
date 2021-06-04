/*
 * hashmap.hpp
 *
 *  Created on: 20-Dec-2015
 *      Author: hkadayam
 */
#pragma once

#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#ifdef GLOBAL_HASHSET_LOCK
#include <mutex>
#endif
#include <type_traits>

#include <boost/intrusive/slist.hpp>
#include <boost/optional.hpp>
#include <farmhash.h>
#include <fds/buffer.hpp>
#include <folly/SharedMutex.h>

#include "engine/common/homestore_header.hpp"

namespace homeds {

//////////////////////////////////// SFINAE Hash Selection /////////////////////////////////

namespace instrusive_hashset_detail {
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

template < typename FunctionType, typename CallbackType, typename... Args>
void invoke_callback(CallbackType&& callback, Args&&... args) {
    if constexpr (std::is_same_v< std::decay_t< CallbackType >, FunctionType >) {
        if (std::forward< CallbackType >(callback))
            std::forward< CallbackType >(callback)(std::forward< Args >(args)...);
    } else
        std::forward< CallbackType >(callback)(std::forward< Args >(args)...);
}

} // namespace instrusive_hashset_detail

class HashNode : public boost::intrusive::slist_base_hook<> {};

////////////// hash_bucket implementation /////////////////
template < typename K, typename V >
class HashBucket {
private:
    class ReadLockGuard {
    public:
        ReadLockGuard(HashBucket* const hb) : m_hb{hb} { m_hb->lock(true); }
        ~ReadLockGuard() { m_hb->unlock(true); }
        ReadLockGuard(const ReadLockGuard&) = delete;
        ReadLockGuard& operator=(const ReadLockGuard&) = delete;
        ReadLockGuard(ReadLockGuard&&) noexcept = delete;
        ReadLockGuard& operator=(ReadLockGuard&&) noexcept = delete;

    private:
        HashBucket* const m_hb;
    };

    class WriteLockGuard {
    public:
        WriteLockGuard(HashBucket* const hb) : m_hb{hb} { m_hb->lock(false); }
        ~WriteLockGuard() { m_hb->unlock(false); }
        WriteLockGuard(const WriteLockGuard&) = delete;
        WriteLockGuard& operator=(const WriteLockGuard&) = delete;
        WriteLockGuard(WriteLockGuard&&) noexcept = delete;
        WriteLockGuard& operator=(WriteLockGuard&&) noexcept = delete;

    private:
        HashBucket* const m_hb;
    };

public:
    typedef std::function< void(V* const) > found_callback_t;

    HashBucket() = default;
    HashBucket(const HashBucket&) = delete;
    HashBucket& operator=(const HashBucket&) = delete;
    HashBucket(HashBucket&&) noexcept = delete;
    HashBucket& operator=(HashBucket&&) noexcept = delete;

    ~HashBucket() {
        WriteLockGuard write_lock{this};
        auto it{std::begin(m_list)};
        while (it != std::end(m_list)) {
            V* const val_ptr{&(*it)};
            it = m_list.erase(it);
            V::deref(*val_ptr); // <<< Double free which will decrease CacheBuffer::m_refcount to -1 during shutdown
        }
    }

    template < typename CallbackType >
    bool insert(const K& k, V& v, V** const outv, CallbackType&& found_cb) {
        bool found{false};

        WriteLockGuard write_lock{this};
        auto it{std::begin(m_list)};
        for (auto itend{std::end(m_list)}; it != itend; ++it) {
            const int x{K::compare(*V::extract_key(*it), k)};
            if (x == 0) {
                *outv = &*it;
                V::ref(**outv);
                found = true;
                instrusive_hashset_detail::invoke_callback< found_callback_t >(std::forward< CallbackType >(found_cb),
                                                                               *outv);
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
        return !found;
    }

    bool get(const K& k, V** const outv) {
        bool found{false};

        ReadLockGuard read_lock{this};
        for (auto it{std::begin(m_list)}, itend{std::end(m_list)}; it != itend; ++it) {
            const int x{K::compare(*(V::extract_key(*it)), k)};
            if (x == 0) {
                found = true;
                *outv = &(*it);
                V::ref(**outv);
                break;
            } else if (x > 0) {
                found = false;
                break;
            }
        }
        return found;
    }

    template < typename CallbackType >
    bool remove(const K& k, CallbackType&& found_cb) {
        bool found{false};

        WriteLockGuard write_lock{this};
        auto it{std::begin(m_list)};
        while (it != std::end(m_list)) {
            const int x{K::compare(*(V::extract_key(*it)), k)};
            if (x == 0) {
                found = true;
                instrusive_hashset_detail::invoke_callback< found_callback_t >(std::forward< CallbackType >(found_cb),
                                                                               &*it);
                V* const val_ptr{&(*it)};
                m_list.erase(it);
                V::deref(*val_ptr);
                break;
            } else if (x > 0) {
                break;
            } else {
                ++it;
            }
        }
        return found;
    }

    uint64_t get_size() {
        ReadLockGuard read_lock{this};
        return m_list.size();
    }

    template < typename CallbackType >
    bool safe_remove(const K& k, CallbackType&& found_cb, bool& can_remove) {
        bool ret{false};

        std::vector< typename hash_node_list::value_type* > free_list{};
        {
            WriteLockGuard write_lock{this};
            auto it{std::begin(m_list)};
            while (it != std::end(m_list)) {
                const int x{K::compare(*(V::extract_key(*it)), k)};
                if (x == 0) {

                    /* set the state. It doesn't free the buffer
                     * right away if ref count is not 1. It set the
                     * state and free it later when ref count becomes 1
                     */
                    V::set_free_state(*it);
                    ret = true;
                    if (V::test_le(*it, 1)) {
                        can_remove = true;
                        instrusive_hashset_detail::invoke_callback< found_callback_t >(std::forward<CallbackType>(found_cb), &*it);
                        V* const val_ptr{&(*it)};
                        m_list.erase(it);
                        V::reset_free_state(*val_ptr);
                        free_list.emplace_back(val_ptr);
                    } else {
                        instrusive_hashset_detail::invoke_callback< found_callback_t >(
                            std::forward< CallbackType >(found_cb), &*it);
                    }
                    break;
                } else if (x > 0) {
                    break;
                } else {
                    ++it;
                }
            }
        }
        // free items outside lock
        for (auto& val_ptr : free_list) {
            V::deref(*val_ptr);
        }
        return ret;
    }

    /* It remove only if ref_cnt is 1 */
    template < typename CallbackType >
    bool check_and_remove(const K& k, CallbackType&& found_cb, const bool dec_ref = false) {
        bool ret{false};

        WriteLockGuard write_lock{this};
        auto it{std::begin(m_list)};
        while (it != std::end(m_list)) {
            const int x{K::compare(*(V::extract_key(*it)), k)};
            if (x == 0) {
                if (dec_ref) { V::deref(*it); }
                if (V::test_le(*it, 1)) {
                    instrusive_hashset_detail::invoke_callback< found_callback_t >(
                        std::forward< CallbackType >(found_cb), &*it);
                    V* const val_ptr{&(*it)};
                    m_list.erase(it);
                    V::deref(*val_ptr);
                    ret = true;
                } else {
                    ret = false;
                }
                break;
            } else if (x > 0) {
                break;
            } else {
                ++it;
            }
        }
        return ret;
    }

    bool release(const K& k) {
        bool removed;
        return remove(k, &removed, nullptr);
    }

    bool release(V* const n) {
        bool removed;
        return remove(*(V::extract_key(n)), &removed, nullptr);
    }

    void lock(const bool shared) {
#ifndef GLOBAL_HASHSET_LOCK
        if (shared) {
            m_lock.lock_shared();
        } else {
            m_lock.lock();
        }
#endif
    }

    void unlock(const bool shared) {
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
    typedef HashBucket< K, V > HashBucketType;
    typedef typename HashBucketType::found_callback_t found_callback_t;

    IntrusiveHashSet(const uint32_t nBuckets) :
            m_size{0}, m_nbuckets{nBuckets}, m_buckets{std::make_unique< HashBucketType[] >(m_nbuckets)} {}
    IntrusiveHashSet(const IntrusiveHashSet&) = delete;
    IntrusiveHashSet& operator=(const IntrusiveHashSet&) = delete;
    IntrusiveHashSet(IntrusiveHashSet&&) noexcept = delete;
    IntrusiveHashSet& operator=(IntrusiveHashSet&&) noexcept = delete;

    ~IntrusiveHashSet() = default;

    uint64_t get_size() const {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        return m_size;
    }

    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool insert(V& v, V** const outv, CallbackType&& found_cb = CallbackType{}) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        const K* const pk{V::extract_key(v)};
        HashBucketType* const hb{get_bucket(*pk)};
        const bool inserted{hb->insert(*pk, v, outv, std::forward< CallbackType >(found_cb))};
        if (inserted) ++m_size;
        return inserted;
    }

    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool insert(const K& k, V& v, V** const outv, const uint64_t hash_code, CallbackType&& found_cb = CallbackType{}) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif

        HashBucketType* const hb{get_bucket(hash_code)};
        const bool inserted{hb->insert(k, v, outv, std::forward< CallbackType >(found_cb))};
        if (inserted) ++m_size;
        return inserted;
    }

    bool get(const K& k, V** const outv) const {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        HashBucketType* const hb{get_bucket(k)};
        return (hb->get(k, outv));
    }

    bool get(const K& k, V** const outv, const uint64_t hash_code) const {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        HashBucketType* const hb{get_bucket(hash_code)};
        return (hb->get(k, outv));
    }

    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool safe_remove(const K& k, const uint64_t hash_code, bool& can_remove, CallbackType&& found_cb = CallbackType{}) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        HashBucketType* const hb{get_bucket(hash_code)};
        const bool removed{hb->safe_remove(k, std::forward< CallbackType >(found_cb), can_remove)};
        if (removed) --m_size;
        return removed;
    }

    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool remove(const K& k, CallbackType&& found_cb = CallbackType{}) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        HashBucketType* const hb{get_bucket(k)};
        const bool removed{hb->remove(k, std::forward< CallbackType >(found_cb))};
        if (removed) --m_size;
        return removed;
    }

    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool remove(const K& k, const uint64_t hash_code, CallbackType&& found_cb = CallbackType{}) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        HashBucketType* const hb{get_bucket(hash_code)};
        const bool removed{hb->remove(k, std::forward< CallbackType >(found_cb))};
        if (removed) --m_size;
        return removed;
    }

    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool check_and_remove(const K& k, const uint64_t hash_code, CallbackType&& found_cb = CallbackType{},
                          const bool dec_ref = false) {
#ifdef GLOBAL_HASHSET_LOCK
        std::lock_guard< std::mutex > lk{m};
#endif
        HashBucketType* const hb{get_bucket(hash_code)};
        const bool removed{hb->check_and_remove(k, std::forward< CallbackType >(found_cb), dec_ref)};
        if (removed) --m_size;
        return removed;
    }

private:
    HashBucketType* get_bucket(const K& k) const {
        return &(m_buckets[instrusive_hashset_detail::compute_hash(k) % m_nbuckets]);
    }

    HashBucketType* get_bucket(const uint64_t hash_code) const { return &(m_buckets[hash_code % m_nbuckets]); }

private:
    std::atomic< uint64_t > m_size;
    uint32_t m_nbuckets;
    std::unique_ptr< HashBucketType[] > m_buckets;

#ifdef GLOBAL_HASHSET_LOCK
    mutable std::mutex m;
#endif
};

} // namespace homeds
