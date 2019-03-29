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
    bool                                                  m_just_created;
    uint32_t                                              m_mutate_count;
    int32_t                                               m_slot_num;
    std::unique_ptr< boost::circular_buffer< uint64_t > > m_val_hash_codes;

    key_info(const K& key, int32_t slot_num = -1) :
            m_key(key),
            m_just_created(true),
            m_mutate_count(0),
            m_slot_num(slot_num) {}

    key_info(const K& key, int32_t slot_num, uint64_t val_hash_code) : key_info(key, slot_num) {
        add_hash_code(val_hash_code);
    }

    void mutation_completed() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_just_created = false;
        m_mutate_count--;
    }

    void mutation_started() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        m_mutate_count++;
    }

    bool is_mutation_ongoing() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_mutate_count != 0);
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
           << " just_created?=" << ki.m_just_created
           << "]";
        return os;
    }
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
class KeyRegistry {
public:
    KeyRegistry() : m_invalid_ki(K::gen_key(KeyPattern::OUT_OF_BOUND, nullptr)) {
        for (auto i = 0u; i < KEY_PATTERN_SENTINEL; i++) {
            m_last_gen_slots[i].store(-1);
            m_last_read_slots[i].store(0);
        }
        //_generate_key(KeyPattern::SEQUENTIAL); // Atleast generate 1 key for us to be ready for read
    }

    virtual ~KeyRegistry() = default;

    key_info< K >* generate_key(KeyPattern gen_pattern) {
        std::unique_lock l(m_rwlock);
        return _generate_key(gen_pattern);
    }

    std::vector< key_info< K >* > generate_keys(KeyPattern gen_pattern, uint32_t n) {
        std::vector< key_info< K >* > gen_keys;
        gen_keys.reserve(n);

        std::unique_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            gen_keys.emplace_back(_generate_key(gen_pattern));
        }
        return gen_keys;
    }

    // Assume last key as invalid key always. NOTE: This will no longer be invalid in case it is actually
    // inserted into the store.
    key_info< K >* generate_invalid_key() { return &m_invalid_ki; }

    key_info< K >* get_key(KeyPattern pattern, bool mutating_key_ok) {
        std::shared_lock l(m_rwlock);
        return _get_key(pattern, mutating_key_ok);
    }

    std::vector< key_info< K >* > get_keys(KeyPattern pattern, uint32_t n, bool mutating_key_ok) {
        std::vector< key_info< K >* > kis;
        kis.reserve(n);

        std::shared_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            kis.emplace_back(_get_key(pattern, mutating_key_ok));
        }
        return kis;
    }

    void put_key(key_info< K >* ki) {
        std::unique_lock l(m_rwlock);
        m_data_set.insert(ki);
    }

    void free_key(key_info< K >* ki) {
        std::unique_lock l(m_rwlock);
        m_data_set.erase(ki);

        assert(m_used_slots[ki->m_slot_num]);
        ki->mutation_completed();

        m_used_slots[ki->m_slot_num] = false;
        if (++m_ndirty >= compact_trigger_limit()) {
            _compact();
        }
    }

    auto find_key(key_info< K >* const& ki) {
        std::shared_lock l(m_rwlock);
        return m_data_set.find(ki);
    }

private:
    key_info< K >* _generate_key(KeyPattern gen_pattern) {
        auto slot_num = m_keys.size();

        // Generate a key and put in the key list and mark that slot as valid.
        m_keys.emplace_back(new key_info< K >(K::gen_key(gen_pattern, _get_last_gen_key(gen_pattern)), slot_num));
        m_used_slots.push_back(true);
        m_last_gen_slots[gen_pattern].store(slot_num, std::memory_order_relaxed);

        return m_keys.back().get();
    }

    key_info< K >* _get_key(KeyPattern pattern, bool mutating_key_ok) {
        assert((pattern == SEQUENTIAL) || (pattern == UNI_RANDOM) || (pattern == PSEUDO_RANDOM));

        int32_t        start_slot = 0;
        key_info< K >* ki = nullptr;

#if 0
        if (pattern == SEQUENTIAL) {
            start_slot = m_last_read_slots[pattern].load(std::memory_order_acquire);
        } else if (pattern == UNI_RANDOM) {
            start_slot = rand() % m_keys.size();
        }
#endif

        typename std::set< key_info< K >*, compare_key_info< K > >::iterator it;
        if (pattern == SEQUENTIAL) {
            start_slot = m_last_read_slots[pattern].load(std::memory_order_acquire);
            it = m_data_set.find(m_keys[start_slot].get());
            assert(it != m_data_set.end());
        } else if (pattern == UNI_RANDOM) {
            start_slot = rand() % m_keys.size();
        }
        auto cur_slot = start_slot;

        do {
            cur_slot = _get_next_slot(cur_slot, pattern, it);

            if (_can_use_for_get(cur_slot, mutating_key_ok)) {
                ki = m_keys[cur_slot].get();
                m_last_read_slots[pattern].store(cur_slot, std::memory_order_release);
                break;
            }
        } while (cur_slot != start_slot);

        return ki;

#if 0
        auto cur_slot = start_slot + 1;
        auto i = 0;

    retry:
        if (cur_slot == start_slot) { // We came one full circle and no default key
            return ki;
        }

        // If the slot is freed or if we are not ok in picking a mutating key, move on to next one.
        if ((!m_used_slots[cur_slot]) || m_keys[cur_slot]->m_just_created ||
            (!mutating_key_ok && m_keys[cur_slot]->is_mutation_ongoing())) {
            cur_slot = m_used_slots.find_next(cur_slot);
            if (cur_slot == (int32_t)boost::dynamic_bitset<>::npos) {
                cur_slot = 0;
                goto retry;
            }
        }

        ki = m_keys[cur_slot].get();

        m_last_read_slots[pattern].store(cur_slot, std::memory_order_release);
        return ki;
#endif
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

    int32_t _get_next_slot(int32_t cur_slot, KeyPattern pattern, auto& it) {
        if (pattern == SEQUENTIAL) {
            ++it;
            if (it == m_data_set.end()) {
                it = m_data_set.begin();
            }
            return (*it)->m_slot_num;
        } else {
            cur_slot = m_used_slots.find_next(cur_slot);
            if (cur_slot == (int32_t)boost::dynamic_bitset<>::npos) {
                cur_slot = m_used_slots.find_first();
            }
            return cur_slot;
        }
    }

    bool _can_use_for_get(int32_t slot, bool mutating_key_ok) {
        return (m_used_slots[slot] && !m_keys[slot]->m_just_created &&
                (!m_keys[slot]->is_mutation_ongoing() || mutating_key_ok));
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

            assert(m_ndirty >= n_gcd);
            m_ndirty -= n_gcd;
        }

        // LOG(INFO) << "Sorted vector set: After compacting " << n_gcd << " entries: " << to_string();
        return n_gcd;
    }

    void _adjust_slot_num(int32_t old_slot, int32_t new_slot) {
        for (auto i = 0; i < KEY_PATTERN_SENTINEL; i++) {
            m_last_gen_slots[i].compare_exchange_strong(old_slot, new_slot, std::memory_order_relaxed);
            m_last_read_slots[i].compare_exchange_strong(old_slot, new_slot, std::memory_order_relaxed);
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
    std::array< std::atomic< int32_t >, KEY_PATTERN_SENTINEL > m_last_read_slots;
};
} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_KEYSET_HPP
