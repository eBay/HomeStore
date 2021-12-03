//
// Created by Kadayam, Hari on 19/10/17.
//

#pragma once

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#include <boost/intrusive_ptr.hpp>
#include <sisl/fds/obj_allocator.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/utility/atomic_counter.hpp>
#include <sisl/utility/enum.hpp>
#include <sisl/utility/obj_life_counter.hpp>

#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/homeds/hash/intrusive_hashset.hpp"
#include "eviction.hpp"
#include "lru_eviction.hpp"

SDS_LOGGING_DECL(cache, cache_vmod_evict, cache_vmod_read, cache_vmod_write)

namespace homestore {

#define CurrentEvictor LRUEvictor
#define LRUEvictor Evictor< LRUEvictionPolicy >
#define CurrentEvictorRecord CurrentEvictor::EvictRecordType

class CacheRecord : public homeds::HashNode, sisl::ObjLifeCounter< CacheRecord > {
public:
    CacheRecord(void* const cache_buffer) : m_evict_record{cache_buffer} {};
    CacheRecord(const CacheRecord&) = delete;
    CacheRecord(CacheRecord&&) noexcept = delete;
    CacheRecord& operator=(const CacheRecord&) = delete;
    CacheRecord& operator=(CacheRecord&&) noexcept = delete;

    typename CurrentEvictor::EvictRecordType m_evict_record; // Information about the eviction record itself.

    const CurrentEvictor::EvictRecordType& get_evict_record() const { return m_evict_record; }

    CurrentEvictor::EvictRecordType& get_evict_record_mutable() { return m_evict_record; }
};

/* Number of entries we ideally want to have per hash bucket. This number if small, will reduce contention and
 * speed of read/writes, but at the cost of increased memory */
//#define ENTRIES_PER_BUCKET 2

/* Number of eviction partitions. More the partitions better the parallelization of requests, but lesser the
 * effectiveness of cache, since it could get evicted sooner than expected, if distribution of key hashing is not
 * even.*/
constexpr uint64_t EVICTOR_PARTITIONS{32};

class CacheMetrics : public sisl::MetricsGroupWrapper {
public:
    explicit CacheMetrics() : sisl::MetricsGroupWrapper("Cache") {
        REGISTER_COUNTER(cache_insert_count, "Total number of inserts to cache", "cache_op_count", {"op", "insert"});
        REGISTER_COUNTER(cache_read_count, "Total number of reads to cache", "cache_op_count", {"op", "read"});
        REGISTER_COUNTER(cache_erase_count, "Total number of erases from cache", "cache_op_count", {"op", "erase"});
        REGISTER_COUNTER(cache_update_count, "Total number of updates to a cache entry", "cache_op_count",
                         {"op", "update"});
        REGISTER_COUNTER(cache_object_count, "Total number of cache entries", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(cache_size, "Total size of cache", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(cache_add_error_count, "Num cache entries unable to insert");
        REGISTER_COUNTER(cache_num_evictions, "Total number of cache evictions");
        REGISTER_COUNTER(cache_num_evictions_punt, "Total number of cache evictions punted because of busy");
        REGISTER_COUNTER(cache_num_duplicate_inserts, "Total number of cache inserts whose entry already exists");

        register_me_to_farm();
    }

    CacheMetrics(const CacheMetrics&) = delete;
    CacheMetrics(CacheMetrics&&) noexcept = delete;
    CacheMetrics& operator=(const CacheMetrics&) = delete;
    CacheMetrics& operator=(CacheMetrics&&) noexcept = delete;

    ~CacheMetrics() { deregister_me_from_farm(); }
};

template < typename K >
class CacheBuffer;

template < typename K, typename V >
class IntrusiveCache {
public:
    typedef CacheBuffer< K > CacheBufferType;
    static_assert(std::is_base_of< CacheBufferType, V >::value,
                  "IntrusiveCache Value must be derived from CacheBuffer<K>");
    typedef typename homeds::IntrusiveHashSet< K, V >::found_callback_t found_callback_t;

    IntrusiveCache(const uint64_t max_cache_size, const uint32_t avg_size_per_entry);
    IntrusiveCache(const IntrusiveCache&) = delete;
    IntrusiveCache& operator=(const IntrusiveCache&) = delete;
    IntrusiveCache(IntrusiveCache&&) noexcept = delete;
    IntrusiveCache& operator=(IntrusiveCache&&) noexcept = delete;

    ~IntrusiveCache() {
        for (uint64_t i{0}; i < EVICTOR_PARTITIONS; ++i)
            m_evictors[i].reset();
    }

    /* Put the raw buffer into the cache. Returns false if insert is not successful and if the key already
     * exists, it additionally fills up the out_ptr. If insert is successful, returns true and put the
     * new V also into out_ptr. */
    template < typename CallbackType = found_callback_t,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_callback_t > > >
    bool insert(V& v, V** const out_ptr, CallbackType&& found_cb = CallbackType{});

    /* Update the value, if it already exists or insert if not exist. Returns true if operation is successful. In
     * additon, it also populates if the out_key exists with true if key exists or false if key does not */
    bool upsert(const V& v, bool* const out_key_exists);

    /* Returns the raw pointer of the data corresponding to the key */
    V* get(const K& k);

    /* Erase the key from the cache. Returns true if key exists and erased, false otherwise */
    bool erase(V& v);

    bool is_safe_to_evict(const CurrentEvictor::EvictRecordType* const rec);
    bool modify_size(V& v, const uint32_t size);

protected:
    std::array< std::unique_ptr< CurrentEvictor >, EVICTOR_PARTITIONS > m_evictors;
    homeds::IntrusiveHashSet< K, V > m_hash_set;
    CacheMetrics m_metrics;
};

template < typename K, typename V >
class Cache : protected IntrusiveCache< K, V > {
    typedef IntrusiveCache< K, V > IntrusiveCacheType;
    typedef std::function< void(const boost::intrusive_ptr< V >& bbuf) > erase_comp_cb;
    typedef std::function< void(V* const bbuf) > found_cb_type;

public:
    Cache(const uint64_t max_cache_size, const uint32_t avg_size_per_entry);
    ~Cache();
    /* Put the raw buffer into the cache with key k. It returns whether put is successful and if so provides
     * the smart pointer of CacheBuffer. Upsert flag of false indicates if the data already exists, do not insert */
    template < typename CallbackType = found_cb_type,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, found_cb_type > > >
    bool insert(const K& k, const sisl::blob& b, const uint32_t value_offset,
                boost::intrusive_ptr< V >* const out_smart_buf, CallbackType&& found_cb = CallbackType{});
    bool insert(const K& k, const boost::intrusive_ptr< V >& in_buf, boost::intrusive_ptr< V >* const out_smart_buf);

    /* Update is a special operation, where, it searches for the key and
     *  If found, appends the blob to the existing cached memory, new memory at specified offset.
     *  If not found, insert a new blob-offset combo into the cached memory.
     *
     *  Returns a named tuple of bools - key_found_already and successfully inserted/updated
     */
    typedef struct {
        bool key_found_already;
        bool success;
    } update_result;

    update_result update(const K& k, const sisl::blob& b, const uint32_t value_offset,
                         boost::intrusive_ptr< V >* const out_smart_buf);
    bool upsert(const K& k, const sisl::blob& b, boost::intrusive_ptr< V >* const out_smart_buf);
    bool get(const K& k, boost::intrusive_ptr< V >* const out_smart_buf);
    bool erase(const boost::intrusive_ptr< V >& buf);
    bool erase(const K& k, boost::intrusive_ptr< V >* const out_bbuf);
    bool erase(const K& k, const uint32_t offset, const uint32_t size,
               boost::intrusive_ptr< V >* const ret_removed_buf);
    template < typename CallbackType = erase_comp_cb,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, erase_comp_cb > > >
    void safe_erase(const boost::intrusive_ptr< V >& buf, CallbackType&& cb = CallbackType{});
    template < typename CallbackType = erase_comp_cb,
               typename = std::enable_if_t< std::is_convertible_v< CallbackType, erase_comp_cb > > >
    void safe_erase(const K& k, CallbackType&& cb = CallbackType{});
    bool insert_missing_pieces(const boost::intrusive_ptr< V >& buf, const uint32_t offset, const uint32_t size_to_read,
                               std::vector< std::pair< uint32_t, uint32_t > >& missing_mp);
};

VENUM(cache_buf_state, uint8_t, CACHE_NOT_INSERTED = 1, CACHE_INSERTED = 2, CACHE_EVICTED = 3)

template < typename K >
class CacheBuffer : public CacheRecord {
    typedef CacheBuffer CacheBufferType;
    typedef Cache< K, CacheBufferType > CacheType;
    typedef std::function< void(const boost::intrusive_ptr< CacheBufferType >& bbuf) > erase_comp_cb;

public:
#ifndef NDEBUG
    bool recovered;
#endif
    K m_key;                                         // Key to access this cache
    boost::intrusive_ptr< homeds::MemVector > m_mem; // Memory address which is what this buffer contained with
    sisl::atomic_counter< uint32_t > m_refcount;     // Refcount
    uint32_t m_data_offset;                          // offset in m_mem that it points to
    std::atomic< uint32_t > m_cache_size;            // size inserted in a cache
    std::atomic< bool > m_can_free;
    CacheType* m_cache;
    erase_comp_cb m_cb;

    /* this mutex prevent erase and insert to happen in parallel. It is taken in two cases
     *  1. Whenever something changes in eviction :- upvode, downvote, erase and size.
     *  2. Whenever cache state is changed.
     */
    std::mutex m_mtx;
    cache_buf_state m_state;

#ifndef NDEBUG
    sisl::atomic_counter< int64_t > m_indx; // Refcount
    static constexpr int64_t MAX_ENTRIES{50};
    /* to see if it is data buf or btree buf */
#endif

public:
#ifndef NDEBUG
    bool is_btree{false};
#endif

    CacheBuffer() :
            CacheRecord{this},
            m_mem{nullptr},
            m_refcount{0},
            m_data_offset{std::numeric_limits< uint32_t >::max()},
            m_cache_size{0},
            m_can_free{false},
            m_cache{nullptr},
            m_state {
        cache_buf_state::CACHE_NOT_INSERTED
    }
#ifndef NDEBUG
    , m_indx { static_cast< int64_t >(-1) }
#endif
    {}

    CacheBuffer(const K& key, const sisl::blob& blob, CacheType* const cache, const uint32_t offset = 0) :
            CacheRecord{this},
            m_mem{nullptr},
            m_refcount{0},
            m_data_offset{std::numeric_limits< uint32_t >::max()},
            m_cache_size{0},
            m_can_free{false},
            m_cache{cache},
            m_state {
        cache_buf_state::CACHE_NOT_INSERTED
    }
#ifndef NDEBUG
    , m_indx { static_cast< int64_t >(-1) }
#endif
    {
        boost::intrusive_ptr< homeds::MemVector > mvec{new homeds::MemVector{}, true};
        mvec->set(blob.bytes, blob.size, offset);

        set_memvec(mvec, 0, blob.size);
        m_key = key;
    }

    CacheBuffer(const CacheBuffer&) = delete;
    CacheBuffer(CacheBuffer&&) noexcept = delete;
    CacheBuffer& operator=(const CacheBuffer&) = delete;
    CacheBuffer& operator=(CacheBuffer&&) noexcept = delete;

    virtual ~CacheBuffer() = default;

    const K& get_key() const { return m_key; }

    template < typename InputType, typename = std::enable_if_t< std::is_convertible_v< InputType, K > > >
    void set_key(InputType&& k) {
        m_key = std::forward< InputType >(k);
    }

    void lock() { m_mtx.lock(); }

    void unlock() { m_mtx.unlock(); }

    bool try_lock() { return (m_mtx.try_lock()); }

    void on_cache_insert() { m_state = cache_buf_state::CACHE_INSERTED; }

    void on_cache_evict() { m_state = cache_buf_state::CACHE_EVICTED; }

    cache_buf_state get_cache_state() const { return m_state; }

    void set_cache(CacheType* const cache) { m_cache = cache; }

    uint32_t get_data_offset() const { return m_data_offset; }

    bool update_missing_piece(const uint32_t offset, const uint32_t size, uint8_t* const ptr) {
        const bool inserted{get_memvec().update_missing_piece(m_data_offset + offset, size, ptr, [this]() { init(); })};
        return inserted;
    }

    uint32_t insert_missing_pieces(const uint32_t offset, const uint32_t size_to_read,
                                   std::vector< std::pair< uint32_t, uint32_t > >& missing_mp) {
        const uint32_t inserted_size{
            get_memvec().insert_missing_pieces(m_data_offset + offset, size_to_read, missing_mp)};
        /* it should return a relative offset */
        for (auto& missing_mp : missing_mp) {
            assert(missing_mp.first >= m_data_offset);
            missing_mp.first -= m_data_offset;
        }

        return inserted_size;
    }

    void set_cb(erase_comp_cb cb) { m_cb = std::move(cb); }

    const erase_comp_cb& get_cb() const { return m_cb; }

    void set_memvec(boost::intrusive_ptr< homeds::MemVector > vec, const uint32_t offset, const uint32_t size) {
        HS_DBG_ASSERT_LE(size, UINT16_MAX);
        m_mem = std::move(vec);
        m_data_offset = offset;
        m_cache_size = size;

        // TODO: turn back on after correct size can be returned based on ptr;
        // m_cache_size = m_mem->get_buffer_size();
    }

    void modify_cache_size(const uint32_t size) { m_cache_size += size; }

    uint32_t get_cache_size() const { return m_cache_size; }

    homeds::MemVector& get_memvec() {
        assert(m_mem != nullptr);
        return *(m_mem.get());
    }

    const homeds::MemVector& get_memvec() const {
        assert(m_mem != nullptr);
        return *(m_mem.get());
    }

    boost::intrusive_ptr< homeds::MemVector > get_memvec_intrusive() const {
        assert(m_mem != nullptr);
        return m_mem;
    }

    sisl::blob at_offset(const uint32_t offset) const {
        sisl::blob b;
        b.bytes = nullptr;
        b.size = 0;
        get_memvec().get(&b, m_data_offset + offset);
        return b;
    }

    friend void intrusive_ptr_add_ref(CacheBufferType* const buf) {
#ifndef NDEBUG
        [[maybe_unused]] const auto x{buf->m_indx.increment() % MAX_ENTRIES};
#endif
        buf->m_refcount.increment();
    }

    friend void intrusive_ptr_release(CacheBufferType* const buf) {
        const K k{*(extract_key(*buf))};
        auto* const cache{buf->m_cache};
        const bool can_free{buf->can_free()};
        const auto [happened, count]{buf->m_refcount.decrement_test_le_with_count(1)};

        // NOTE: The safe_erase is needed in order to reclaim memory because of not
        // removing via erase so ref count will remain at 1 without it
        if (happened) {
            HS_DBG_ASSERT_LE(count, 1, "Invalid count in buf refcount");
            if (count == 1) {
                if (can_free) {
                    HS_DBG_ASSERT(cache != nullptr, "Expected cache to be non null");
                    cache->safe_erase(k);
                }
            } else if (count == 0) {
                // free the record
                buf->free_yourself();
            }
        }
    }

    virtual void init() {}

    void set_free_state() { m_can_free = true; }
    void reset_free_state() { m_can_free = false; }
    bool can_free() const { return m_can_free; }

    std::string to_string() const {
        std::ostringstream ss;
        ss << "Cache Key = " << m_key.to_string() << " Cache Mem = " << m_mem->to_string()
           << " Cache refcount = " << m_refcount.get();
        return ss.str();
    }

    static CacheBufferType* make_object() { return sisl::ObjectAllocator< CacheBufferType >::make_object(); }

    virtual void free_yourself() { sisl::ObjectAllocator< CacheBufferType >::deallocate(this); }

    //////////// Mandatory IntrusiveHashSet definitions ////////////////
    static void ref(CacheBufferType& b) { intrusive_ptr_add_ref(&b); }

    static void set_free_state(CacheBufferType& b) { b.set_free_state(); }

    static void reset_free_state(CacheBufferType& b) { b.reset_free_state(); }

    static void deref(CacheBufferType& b) { intrusive_ptr_release(&b); }

    static bool test_eq(const CacheBufferType& b, const uint32_t check) { return b.m_refcount.test_eq(check); }

    static bool test_le(const CacheBufferType& b, const uint32_t check) { return b.m_refcount.test_le(check); }

    static const K* extract_key(const CacheBufferType& b) { return &(b.m_key); }

    static uint32_t get_size(const CurrentEvictor::EvictRecordType* const rec) {
        const CacheBufferType* cbuf{static_cast< CacheBufferType* >(rec->cache_buffer)};
        return cbuf->get_cache_size();
    }
};

#include "cache.ipp"

} // namespace homestore
