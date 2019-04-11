//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_KEYSET_HPP
#define HOMESTORE_KEYSET_HPP

#include "loadgen_common.hpp"
#include <boost/circular_buffer.hpp>
#include <farmhash.h>
#include <shared_mutex>
#include <folly/RWSpinLock.h>
#include <iostream>

#define MAX_HASH_CODE_ENTRIES 10 // Max hash codes to store in each keyinfo structure

namespace homeds {
namespace loadgen {
template < typename K >
struct key_info {
    folly::RWSpinLock                                     m_lock;
    K                                                     m_key;
    bool                                                  m_exclusive_access = true;
    bool                                                  m_free_pending  = false;
    uint32_t                                              m_mutate_count = 0;
    uint32_t                                              m_read_count;
    int32_t                                               m_slot_num;
    std::unique_ptr< boost::circular_buffer< uint64_t > > m_val_hash_codes;

    key_info(const K& key, int32_t slot_num = -1) :
            m_key(key),
            m_slot_num(slot_num) {}

    key_info(const K& key, int32_t slot_num, uint64_t val_hash_code) : key_info(key, slot_num) {
        add_hash_code(val_hash_code);
    }

    void mutation_started() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_mutate_count++;
    }

    void read_started() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_read_count++;
    }

    bool mutation_completed() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_exclusive_access = false;
        m_mutate_count--;
        return _should_free();
    }

    bool read_completed() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_exclusive_access = false;
        m_read_count--;
        return _should_free();
    }

    bool is_mutation_ongoing() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_mutate_count != 0);
    }

    bool is_read_ongoing() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_read_count != 0);
    }

    void mark_freed() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_free_pending = true;
    }

    void mark_exclusive() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_exclusive_access = true;
    }

    bool is_exclusive() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_exclusive_access);
    }

    void add_hash_code(uint64_t hash_code) {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        if (!m_val_hash_codes) {
            m_val_hash_codes = std::make_unique< boost::circular_buffer< uint64_t > >(MAX_HASH_CODE_ENTRIES);
        }
        m_val_hash_codes->push_back(hash_code);
    }

    bool validate_hash_code(uint64_t hash_code, bool only_last) const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        if (only_last) {
            return (m_val_hash_codes->back() == hash_code);
        }
        for (auto h : *m_val_hash_codes) {
            if (h == hash_code) {
                return true;
            }
        }

        return false;
    }

    uint64_t get_last_hash_code() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_val_hash_codes->back());
    }

    friend std::ostream& operator<<(std::ostream& os, const key_info< K >& ki) {
        os << "KeyInfo: [Key=" << ki.m_key
           << " last_hash_code=" << ki.get_last_hash_code()
           << " slot_num=" << ki.m_slot_num
           << " mutating_count=" << ki.m_mutate_count
           << " read_count=" << ki.m_read_count
           << " exclusive_access?=" << ki.m_exclusive_access
           << "]";
        return os;
    }

private:
    bool _should_free() const { return (m_free_pending && !m_mutate_count && !m_read_count); }
};

template < typename K >
struct compare_key_info {
public:
    bool operator()(key_info< K >* const& ki1, key_info< K >* const& ki2) const {
        //LOGINFO("Comparing k1 => {} k2 => {}, compare = {}", *ki1, *ki2, ki1->m_key.compare(&ki2->m_key));
        return (ki1->m_key.compare(&ki2->m_key) < 0);
    }
};

template < typename K >
struct key_info_hash {
    size_t operator()(const key_info< K >*& ki) const {
        auto b = ki->m_key.get_blob();
        return util::Hash32((const char*)b.bytes, (size_t)b.size);
    }
};

template < typename K >
class KeyRegistry;

template< typename K >
struct key_info_ptr {
    key_info_ptr(KeyRegistry< K > *reg, key_info< K > *ki, bool is_mutate) :
        m_registry(reg),
        m_ki(ki),
        m_is_mutate(is_mutate) {
        is_mutate ? ki->mutation_started() : ki->read_started();
    }
    ~key_info_ptr();

    key_info< K >& operator*() const { return *m_ki; }
    key_info< K >* operator->() const { return m_ki; }
    operator bool(void) const { return (m_ki == nullptr); }

    KeyRegistry< K > *m_registry;
    key_info< K > *m_ki;
    bool m_is_mutate;
};

template < typename K >
class KeyRegistry {
public:
    KeyRegistry() : m_invalid_ki(K::gen_key(KeyPattern::OUT_OF_BOUND, nullptr)) {
        for (auto i = 0u; i < KEY_PATTERN_SENTINEL; i++) {
            m_last_gen_slots[i].store(-1);
            m_next_read_slots[i].store(0);
        }
        //_generate_key(KeyPattern::SEQUENTIAL); // Atleast generate 1 key for us to be ready for read
    }

    virtual ~KeyRegistry() = default;

    key_info_ptr< K > generate_key(KeyPattern gen_pattern) {
        std::unique_lock l(m_rwlock);
        return key_info_ptr(this, _generate_key(gen_pattern), true);
    }

    std::vector< key_info_ptr< K > > generate_keys(KeyPattern gen_pattern, uint32_t n) {
        std::vector< key_info_ptr< K > > gen_keys;
        gen_keys.reserve(n);

        std::unique_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            gen_keys.emplace_back(key_info_ptr(this, _generate_key(gen_pattern), true));
        }
        return gen_keys;
    }

    // Assume last key as invalid key always. NOTE: This will no longer be invalid in case it is actually
    // inserted into the store.
    key_info_ptr< K > generate_invalid_key() { return key_info_ptr(this, &m_invalid_ki, true); }

    key_info_ptr< K > get_key(KeyPattern pattern, bool is_mutate, bool exclusive_access) {
        std::shared_lock l(m_rwlock);
        return key_info_ptr(this, _get_key(pattern, is_mutate, exclusive_access), is_mutate);
    }

    std::vector< key_info_ptr< K > > get_contiguous_keys(KeyPattern pattern, bool exclusive_access, bool is_mutate,
                                                         uint32_t num_needed) {
        std::shared_lock l(m_rwlock);
        return _get_contigoous_keys(pattern, exclusive_access, is_mutate, num_needed);
    }

    std::vector< key_info_ptr< K > > get_keys(KeyPattern pattern, uint32_t n, bool is_mutate, bool exclusive_access) {
        std::vector< key_info_ptr< K > > kis;
        kis.reserve(n);

        std::shared_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            kis.emplace_back(key_info_ptr(_get_key(pattern, exclusive_access), is_mutate));
        }
        return kis;
    }

    void put_key(key_info_ptr< K >& kip) {
        std::unique_lock l(m_rwlock);
        m_data_set.insert(kip.m_ki);
    }

    void remove_key(key_info_ptr< K >& kip) {
        std::unique_lock l(m_rwlock);
        m_data_set.erase(kip.m_ki);
//        kip->mark_freed();
    }

    auto find_key(const key_info_ptr< K >& kip) {
        std::shared_lock l(m_rwlock);
        return m_data_set.find(kip.m_ki);
    }

    friend struct key_info_ptr< K >;

    void reset_pattern(KeyPattern pattern, int index=0){
        m_next_read_slots[pattern].store(index, std::memory_order_relaxed);
    }
private:
    void free_key(key_info< K >* ki) {
        std::unique_lock l(m_rwlock);
        _free_key(ki);
    }

    key_info< K >* _generate_key(KeyPattern gen_pattern) {
        auto slot_num = m_keys.size();

        // Generate a key and put in the key list and mark that slot as valid.
        m_keys.emplace_back(new key_info< K >(K::gen_key(gen_pattern, _get_last_gen_key(gen_pattern)), slot_num));
        m_used_slots.push_back(true);
        m_last_gen_slots[gen_pattern].store(slot_num, std::memory_order_relaxed);

        return m_keys.back().get();
    }

    key_info< K >* _get_key(KeyPattern pattern, bool is_mutate, bool exclusive_access) {
        assert((pattern == SEQUENTIAL) || (pattern == UNI_RANDOM) || (pattern == PSEUDO_RANDOM));

        int32_t        start_slot = 0;
        key_info< K >* ki = nullptr;

        typename std::set< key_info< K >*, compare_key_info< K > >::iterator it;
        if (pattern == SEQUENTIAL) {
            start_slot = m_next_read_slots[pattern].load(std::memory_order_acquire);
            it = m_data_set.find(m_keys[start_slot].get());
            assert(it != m_data_set.end());
        } else if (pattern == UNI_RANDOM) {
            start_slot = rand() % m_keys.size();
        }
        auto cur_slot = start_slot;
        bool rotated=false;
        while(rotated==false || cur_slot != start_slot) {
            auto next_slot = _get_next_slot(cur_slot, pattern, it, &rotated);
            if (_can_use_for_get(cur_slot)) {
                ki = m_keys[cur_slot].get();
                if (exclusive_access) { ki->mark_exclusive(); }
                m_next_read_slots[pattern].store(next_slot, std::memory_order_release);
                break;
            }
            cur_slot=next_slot;
        } 

        return ki;
    }

    std::vector< key_info_ptr< K > > _get_contigoous_keys(KeyPattern first_key_pattern, bool exclusive_access,
                                                          bool is_mutate, uint32_t num_needed) {
        assert((first_key_pattern == SEQUENTIAL) || (first_key_pattern == UNI_RANDOM) ||
               (first_key_pattern == PSEUDO_RANDOM));

        std::vector< key_info_ptr < K > > kis;
        kis.reserve(num_needed);

        // Get the first key based on the pattern
        auto ki = _get_key(first_key_pattern, is_mutate, exclusive_access);
        if (ki == nullptr) { return kis; }
        kis.push_back(key_info_ptr(this, ki, is_mutate));

        // Subsequent keys cannot use given pattern, but stricly based on hte data_map sorted order
        auto it = m_data_set.find(ki);
        assert(it != m_data_set.end());
        ++it;

        while ((it != m_data_set.end()) && (num_needed < kis.size())) {
            ki = *it;
            if (_can_use_for_get(ki->m_slot_num)) {
                if (exclusive_access) { ki->mark_exclusive(); }
                kis.push_back(key_info_ptr(this, ki, is_mutate));
            } else {
                // Unable to use for get, so it breaks contiguity.
                m_next_read_slots[first_key_pattern].store(ki->m_slot_num, std::memory_order_release);
                return kis;
            }
        }
        auto next_slot=-1;
        if (it == m_data_set.end()) {
            it = m_data_set.begin();
            next_slot= (*it)->m_slot_num;
        }else{
            bool rotated=false;
            next_slot = _get_next_slot(ki->m_slot_num, first_key_pattern, it, &rotated);
        }
        m_next_read_slots[first_key_pattern].store(next_slot, std::memory_order_release);
        return kis;
    }

    K* _get_last_gen_key(KeyPattern pattern) {
        auto last_slot = m_last_gen_slots[pattern].load(std::memory_order_relaxed);
        if (last_slot == -1) {
            return nullptr;
        }
        return &m_keys[last_slot]->m_key;
    }

    void _set_last_gen_slot(KeyPattern pattern, size_t slot) {
        m_last_gen_slots[pattern].store(slot, std::memory_order_relaxed);
    }

    int32_t _get_next_slot(int32_t cur_slot, KeyPattern pattern, auto& it, bool *rotated) {
        *rotated = false;
        if (pattern == SEQUENTIAL) {
            ++it;
            if (it == m_data_set.end()) {
                it = m_data_set.begin();
                *rotated = true;
            }
            return (*it)->m_slot_num;
        } else {
            cur_slot = m_used_slots.find_next(cur_slot);
            if (cur_slot == (int32_t)boost::dynamic_bitset<>::npos) {
                cur_slot = m_used_slots.find_first();
                *rotated = true;
            }
            return cur_slot;
        }
    }

    bool _can_use_for_get(int32_t slot) {
        return (m_used_slots[slot] && !m_keys[slot]->is_exclusive());
    }

    void _free_key(key_info< K >* ki) {
        assert(m_used_slots[ki->m_slot_num]);

        m_used_slots[ki->m_slot_num] = false;
        if (++m_ndirty >= (int32_t)compact_trigger_limit()) {
            _compact();
        }
    }

    uint32_t _compact() {
        uint32_t n_gcd = 0;

        // Find the first free slot in the set, by doing a flip of bits and search for first 1.
        auto left_ind = (~m_used_slots).find_first();
        if (left_ind == boost::dynamic_bitset<>::npos) {
            // All slots are valid, nothing to compact
            return 0;
        }

        auto right_ind = left_ind;
        while ((right_ind = m_used_slots.find_next(right_ind)) != boost::dynamic_bitset<>::npos) {
            m_keys[left_ind] = std::move(m_keys[right_ind]);
            _adjust_slot_num(right_ind, left_ind);

            m_used_slots[right_ind] = false;
            m_used_slots[left_ind++] = true;
        }

        n_gcd = m_keys.size() - left_ind;
        if (n_gcd > 0) {
            m_used_slots.resize(left_ind);
            m_keys.resize(left_ind);

            assert(m_ndirty >= (int32_t)n_gcd);
            m_ndirty -= n_gcd;
        }

        // LOG(INFO) << "Sorted vector set: After compacting " << n_gcd << " entries: " << to_string();
        return n_gcd;
    }

    void _adjust_slot_num(int32_t old_slot, int32_t new_slot) {
        for (auto i = 0; i < KEY_PATTERN_SENTINEL; i++) {
            m_last_gen_slots[i].compare_exchange_strong(old_slot, new_slot, std::memory_order_relaxed);
            m_next_read_slots[i].compare_exchange_strong(old_slot, new_slot, std::memory_order_relaxed);
        }
    }

    static constexpr uint32_t compact_trigger_limit() { return 100000; }

private:
    std::shared_mutex                                 m_rwlock;
    std::vector< std::unique_ptr< key_info< K > > >   m_keys;
    boost::dynamic_bitset<>                           m_used_slots;
    std::set< key_info< K >*, compare_key_info< K > > m_data_set;
    int32_t                                           m_ndirty = 0;

    key_info< K >                                              m_invalid_ki;
    std::array< std::atomic< int32_t >, KEY_PATTERN_SENTINEL > m_last_gen_slots;
    std::array< std::atomic< int32_t >, KEY_PATTERN_SENTINEL > m_next_read_slots;
};

template< typename K>
key_info_ptr< K >::~key_info_ptr() {
    bool need_to_free = (m_is_mutate ? m_ki->mutation_completed() : m_ki->read_completed());
    if (need_to_free) { m_registry->free_key(m_ki); }
}

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_KEYSET_HPP
