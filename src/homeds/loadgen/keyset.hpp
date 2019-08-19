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
#include <boost/dynamic_bitset.hpp>

#define MAX_HASH_CODE_ENTRIES 10 // Max hash codes to store in each keyinfo structure
#define MAX_VALUE_RANGE 100000000
#define MAX_KEY_RANGE 100000000

namespace homeds {
namespace loadgen {
template < typename K, typename V >
struct key_info {
    folly::RWSpinLock                                     m_lock;
    K                                                     m_key;
    bool                                                  m_exclusive_access = true;
    bool                                                  m_free_pending = false;
    uint32_t                                              m_mutate_count = 0;
    uint32_t                                              m_read_count = 0;
    int32_t                                               m_slot_num;
    std::unique_ptr< boost::circular_buffer< uint64_t > > m_val_hash_codes;
    std::shared_ptr< V >                                  m_val;      // current value
    std::shared_ptr< V >                                  m_last_val; // last value

    key_info(const K& key, int32_t slot_num = -1) : m_key(key), m_slot_num(slot_num) {}

    key_info(const K& key, int32_t slot_num, V& value, uint64_t val_hash_code) : key_info(key, slot_num) {
        update_value(value);
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
        assert(m_mutate_count > 0);
        m_mutate_count--;
        if (m_mutate_count == 0 && m_read_count == 0)
            m_exclusive_access = false;
        return _should_free();
    }

    bool read_completed() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        assert(m_read_count > 0);
        m_read_count--;
        if (m_mutate_count == 0 && m_read_count == 0)
            m_exclusive_access = false;
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

    bool is_marked_free() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_free_pending);
    }

    bool mark_exclusive() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        if (m_exclusive_access == true)
            return false; // someone marked it exclusive already
        m_exclusive_access = true;
        return true;
    }

    bool is_exclusive() const {
        folly::RWSpinLock::ReadHolder guard(const_cast< folly::RWSpinLock& >(m_lock));
        return (m_exclusive_access);
    }

    void update_value(std::shared_ptr< V > v) {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        assert(m_last_val == nullptr);
        m_last_val = m_val;
        m_val = v;
    }

    std::shared_ptr< V > get_and_reset_last_value() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        std::shared_ptr< V >           temp = m_last_val;
        m_last_val = nullptr;
        return temp;
    }

    std::shared_ptr< V > get_value() {
        folly::RWSpinLock::WriteHolder guard(m_lock);
        return m_val;
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

    friend std::ostream& operator<<(std::ostream& os, const key_info< K, V >& ki) {
        os << "KeyInfo: [Key=" << ki.m_key << " last_hash_code=" << ki.get_last_hash_code()
           << " slot_num=" << ki.m_slot_num << " mutating_count=" << ki.m_mutate_count
           << " read_count=" << ki.m_read_count << " exclusive_access?=" << ki.m_exclusive_access
           << " last_value=" << ki.m_val << "]";
        return os;
    }

private:
    bool _should_free() const { return (m_free_pending && !m_mutate_count && !m_read_count); }
};

template < typename K, typename V >
struct compare_key_info {
public:
    bool operator()(key_info< K, V >* const& ki1, key_info< K, V >* const& ki2) const {
        // LOGINFO("Comparing k1 => {} k2 => {}, compare = {}", *ki1, *ki2, ki1->m_key.compare(&ki2->m_key));
        return (ki1->m_key.compare(&ki2->m_key) < 0);
    }
};

template < typename K, typename V >
struct key_info_hash {
    size_t operator()(const key_info< K, V >*& ki) const {
        auto b = ki->m_key.get_blob();
        return util::Hash32((const char*)b.bytes, (size_t)b.size);
    }
};

template < typename K, typename V >
class KeyRegistry;

template < typename K, typename V >
struct key_info_ptr {
    key_info_ptr(KeyRegistry< K, V >* reg, key_info< K, V >* ki, bool is_mutate) :
            m_registry(reg),
            m_ki(ki),
            m_is_mutate(is_mutate) {
        is_mutate ? ki->mutation_started() : ki->read_started();
    }

    key_info_ptr(const key_info_ptr& p) {
        m_ki = p.m_ki;
        m_registry = p.m_registry;
        m_is_mutate = p.m_is_mutate;
        // used for pushback in vector
        if (m_is_mutate)
            m_ki->m_mutate_count++;
        else
            m_ki->m_read_count++;
    }

    ~key_info_ptr();

    key_info< K, V >& operator*() const { return *m_ki; }
    key_info< K, V >* operator->() const { return m_ki; }
                      operator bool(void) const { return (m_ki == nullptr); }

    KeyRegistry< K, V >* m_registry;
    key_info< K, V >*    m_ki;
    bool                 m_is_mutate;
};

template < typename K, typename V >
class KeyRegistry {
public:
    KeyRegistry() : m_invalid_ki(K::gen_key(KeyPattern::OUT_OF_BOUND, nullptr)) {

        for (auto i = 0u; i < KEY_PATTERN_SENTINEL; i++) {
            m_last_gen_slots[i].store(-1);
            m_next_read_slots[i].store(0);
        }
    }

    void set_max_keys(uint64_t max_keys) {
        K::MAX_KEYS = max_keys;
        V::MAX_VALUES = 2 * max_keys;
    }

    virtual ~KeyRegistry() {

        auto itr = m_keys.begin();
        while (itr != m_keys.end()) {
            auto ki = std::move(*itr);
            assert(ki->m_read_count == 0 && ki->m_mutate_count == 0);
            ++itr;
        }

        assert(m_data_set.size() == m_value_set.size());
    };

    uint64_t get_keys_count() { return m_data_set.size(); }

    void print_data_set() {
        auto              itr = m_data_set.begin();
        std::stringstream ss;
        while (itr != m_data_set.end()) {
            ss << (*itr)->m_key.to_string() << "\n";
            ++itr;
        }
        LOGERROR("key set:{}", ss.str());
    }
    
    void print_value_set() {
        auto              itr = m_value_set.begin();
        std::stringstream ss;
        while (itr != m_value_set.end()) {
            ss << (*itr)->to_string() << "\n";
            ++itr;
        }
        LOGERROR("value set:{}", ss.str());
    }

    int update_contigious_kv(std::vector< key_info_ptr< K, V > >& kv) {
        std::unique_lock l(m_rwlock);
        if (kv.size() == 0)
            return 0;

        std::shared_ptr< V > val = _generate_value(ValuePattern::RANDOM_BYTES); // GENERATE RANDOM NON-EXISTENT VALUE
        auto                 keyit = kv.begin();
        int                  count = 0;
        bool                 pregenerated = true;

        while (keyit != kv.end()) { // keys and values
            auto kip = *keyit;

            if (pregenerated) {
                pregenerated = false;
            } else {
                /** GENERATE SEQ VALUE AND SEE IF IT ALREADY EXISTS **/
                std::shared_ptr< V > temp =
                    std::make_shared< V >(V::gen_value(ValuePattern::SEQUENTIAL_VAL, val.get()));

                if (!val->is_consecutive(*temp.get()))
                    break; // rolled over values

                val = temp;

                if (has_value((val))) {
                    break; // continuity brokern
                }
                auto result = m_value_set.insert(val);
                if (result.second == false) {
                    LOGERROR("generated value is not unique!");
                    assert(0);
                }
            }

            /** LINK NEW VALUE TO EXISTING KEY */
            kip->update_value(val); // REMOVAL OF VALUE TAKEN CARE SEPERATLY
            kip->add_hash_code(val->get_hash_code());

            count++;
            ++keyit;
        }
        return count;
    }

    void remove_old_values(std::vector< key_info_ptr< K, V > >& res) {
        std::unique_lock l(m_rwlock);
        auto             itr = res.begin();
        while (itr != res.end()) {
            auto                 kip = *itr;
            std::shared_ptr< V > val = kip->get_and_reset_last_value();
            if (val)
                _remove_value(val);
            ++itr;
        }
    }

    std::shared_ptr< V > generate_value(ValuePattern value_pattern) {
        std::unique_lock l(m_rwlock);
        return _generate_value(value_pattern);
    }

    key_info_ptr< K, V > generate_and_put_key(KeyPattern gen_pattern) {
        std::unique_lock l(m_rwlock);
        key_info_ptr     kip = key_info_ptr(this, _generate_key(gen_pattern), true);
        auto             result = m_data_set.insert(kip.m_ki);
        if (result.second == false) {
            LOGERROR("generated key is not unique!");
            assert(0);
        }
        return kip;
    }

    key_info_ptr< K, V > generate_key(KeyPattern gen_pattern) {
        std::unique_lock l(m_rwlock);
        return key_info_ptr(this, _generate_key(gen_pattern), true);
    }

    std::vector< key_info_ptr< K, V > > generate_keys(KeyPattern gen_pattern, uint32_t n) {
        std::vector< key_info_ptr< K, V > > gen_keys;
        gen_keys.reserve(n);

        std::unique_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            gen_keys.emplace_back(key_info_ptr(this, _generate_key(gen_pattern), true));
        }
        return gen_keys;
    }

    // Assume last key as invalid key always. NOTE: This will no longer be invalid in case it is actually
    // inserted into the store.
    key_info_ptr< K, V > generate_invalid_key() { return key_info_ptr(this, &m_invalid_ki, true); }

    std::shared_ptr< V > get_value(ValuePattern value_pattern) {
        assert(0); // TODO -support reuse of values, need to track using smart ptrs of when to delete unused val
        return nullptr;
    }

    key_info_ptr< K, V > get_key(KeyPattern pattern, bool is_mutate, bool exclusive_access) {

        key_info< K, V >* ki = nullptr;
        while (ki == nullptr) {           // relase locks and retry
            std::unique_lock l(m_rwlock); // uniq lock needed since multiple threads can aquire next slot
            ki = _get_key(pattern, is_mutate, exclusive_access);
        }
        return key_info_ptr(this, ki, is_mutate);
    }

    key_info_ptr< K, V > get_key(K& key, bool is_mutate) {
        key_info< K, V >* k = find_key(key);
        assert(k != nullptr);
        return key_info_ptr(this, k, is_mutate);
    }

    // make sures contigious keys returned from data set is also consecutive
    std::vector< key_info_ptr< K, V > > get_consecutive_keys(KeyPattern pattern, bool exclusive_access, bool is_mutate,
                                                             uint32_t num_needed) {
        std::unique_lock                    l(m_rwlock);
        std::vector< key_info_ptr< K, V > > kips =
            _get_contigoous_keys(pattern, exclusive_access, is_mutate, num_needed);
        if (kips.size() <= 1)
            return kips;

        uint32_t count = 1;

        for (auto i = 1u; i < kips.size(); i++) {
            if (!kips[i - 1]->m_key.is_consecutive(kips[i]->m_key))
                break;
            count++;
        }

        if (count != kips.size()) {
            kips.erase(kips.begin() + count, kips.end());
        }
        assert(count == kips.size());
        return kips;
    }

    // returns keys contigious according to available dataset
    std::vector< key_info_ptr< K, V > > get_contiguous_keys(KeyPattern pattern, bool exclusive_access, bool is_mutate,
                                                            uint32_t num_needed) {
        std::unique_lock l(m_rwlock); // uniq lock needed since multiple threads can aquire next slot
        return _get_contigoous_keys(pattern, exclusive_access, is_mutate, num_needed);
    }

    std::vector< V > get_contiguous_values(ValuePattern pattern, bool exclusive_access, bool is_mutate,
                                           uint32_t num_needed) {
        std::unique_lock l(m_rwlock); // uniq lock needed since multiple threads can aquire next slot
        return _get_contigoous_values(pattern, exclusive_access, is_mutate, num_needed);
    }

    std::vector< key_info_ptr< K, V > > get_keys(KeyPattern pattern, uint32_t n, bool is_mutate,
                                                 bool exclusive_access) {
        std::vector< key_info_ptr< K, V > > kis;
        kis.reserve(n);

        std::shared_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            kis.emplace_back(key_info_ptr(_get_key(pattern, exclusive_access), is_mutate));
        }
        return kis;
    }

    void put_key(key_info_ptr< K, V >& kip) {
        std::unique_lock l(m_rwlock);
        auto             result = m_data_set.insert(kip.m_ki);
        if (result.second == false) {
            LOGERROR("generated key is not unique!");
            assert(0);
        }
        assert(result.second);
    }

    void remove_value(std::shared_ptr< V > value) {
        std::unique_lock l(m_rwlock);
        _remove_value(value);
    }

    void _remove_value(std::shared_ptr< V > value) {
        LOGDEBUG("Erasing value:{}", value->to_string());
        auto x = m_value_set.erase(value);
        if (x == 0) {
            LOGERROR("Value not found!");
            assert(0);
        }
    }

    void remove_key(key_info_ptr< K, V >& kip) {
        std::unique_lock l(m_rwlock);
        LOGDEBUG("Erasing key:{}", kip.m_ki->m_key.to_string());
        auto x = m_data_set.erase(kip.m_ki);
        if (x == 0) {
            LOGERROR("Key not found!");
            assert(0);
        }
        kip->mark_freed();
        assert(m_alive_slots[kip.m_ki->m_slot_num] == true);
        // LOGDEBUG("Removed key {} , marked dead slot: {}",kip.m_ki->m_key,kip.m_ki->m_slot_num);
        m_alive_slots[kip.m_ki->m_slot_num] = false; // declare dead slot so as get_key do not pick it up
    }

    // no locking done here, client is expected to get lock
    key_info< K, V >* find_key(K& key) {
        key_info< K, V >* ki = new key_info< K, V >(key, 0); // provide dummy slot
        auto              it = m_data_set.find(ki);
        delete ki;
        if (it == m_data_set.end())
            return nullptr;
        key_info< K, V >* expected_ki = *it;
        if (expected_ki->m_key.compare(&key) != 0)
            return nullptr;
        return expected_ki;
    }

    // no locking done here, client is expected to get lock
    bool has_key(key_info< K, V >* ki) {
        auto it = m_data_set.find(ki);
        if (it == m_data_set.end())
            return false;
        const key_info< K, V >* expected_ki = *it;
        if (expected_ki->m_key.compare(&ki->m_key) != 0)
            return false;
        return true;
    }

    bool has_value(std::shared_ptr< V > value) {
        auto it = m_value_set.find(value);
        if (it == m_value_set.end())
            return false;
        const std::shared_ptr< V > exp_value = *it;
        if (exp_value->compare(*value.get()) != 0)
            return false;
        return true;
    }

    friend struct key_info_ptr< K, V >;

    void reset_pattern(KeyPattern pattern, int index = 0) {
        std::unique_lock l(m_rwlock);
        m_next_read_slots[pattern].store(index, std::memory_order_relaxed);
    }

private:
    key_info< K, V >* _generate_key(K& key) {
        auto              slot_num = m_keys.size();
        key_info< K, V >* newKi = new key_info< K, V >(key, slot_num);
        assert(newKi->m_mutate_count < 1000000000);
        m_keys.emplace_back(newKi);
        m_used_slots.push_back(true);
        m_alive_slots.push_back(true);
        m_last_gen_slots[KeyPattern::UNI_RANDOM].store(slot_num, std::memory_order_relaxed);
        LOGDEBUG("Generated key:{}", key.to_string());
        return m_keys.back().get();
    }

    void free_key(key_info< K, V >* ki) {
        std::unique_lock l(m_rwlock);
        _free_key(ki);
    }

    std::shared_ptr< V > _generate_value(ValuePattern value_pattern) {
        
        std::shared_ptr< V > nv = nullptr;
        int                  trygen = 0;
        do {
            if (trygen++ == MAX_VALUE_RANGE) {
                LOGERROR("Could not generate values!!!");
                assert(0);
            }
        
            nv = std::make_shared< V >(V::gen_value(value_pattern, _get_last_gen_value(value_pattern)));
        } while (has_value(nv));
        auto result = m_value_set.insert(nv);
        if (result.second == false) {
            LOGERROR("generated value is not unique!");
            assert(0);
        }
        _set_last_gen_value(nv);
        LOGDEBUG("Generated value:{}", nv->to_string());
        return nv;
    }

    key_info< K, V >* _generate_key(KeyPattern gen_pattern) {
        auto              slot_num = m_keys.size();
        key_info< K, V >* newKi = nullptr;
        int               trygen = 0;
        do {
            if (trygen++ == MAX_KEY_RANGE) {
                LOGERROR("Could not generate keys!!!");
                assert(0);
            }
            if (newKi)
                delete newKi;
            newKi = new key_info< K, V >(K::gen_key(gen_pattern, _get_last_gen_key(gen_pattern)), slot_num);
        } while (has_key(newKi));

        // Generate a key and put in the key list and mark that slot as valid.
        m_keys.emplace_back(newKi);
        m_used_slots.push_back(true);
        m_alive_slots.push_back(true);
        m_last_gen_slots[gen_pattern].store(slot_num, std::memory_order_relaxed);
        LOGDEBUG("Generated key:{}", newKi->m_key.to_string());
        return m_keys.back().get();
    }

    key_info< K, V >* _get_key(KeyPattern pattern, bool is_mutate, bool exclusive_access) {
        assert((pattern == SEQUENTIAL) || (pattern == UNI_RANDOM) || (pattern == PSEUDO_RANDOM));

        int32_t           start_slot = 0;
        key_info< K, V >* ki = nullptr;
        assert(m_data_set.size() != 0);
        bool                                                                       rotated = false, temprotate = false;
        typename std::set< key_info< K, V >*, compare_key_info< K, V > >::iterator it;
        if (pattern == SEQUENTIAL) {
            start_slot = m_next_read_slots[pattern].load(std::memory_order_acquire);
            it = m_data_set.find(m_keys[start_slot].get());

            // remove punches holes, if it was last slot being punched, we have to start over
            if (it == m_data_set.end()) {
                start_slot = _get_next_slot(start_slot, pattern, it, &temprotate); // auto increments *it
            }
        } else if (pattern == UNI_RANDOM) {
            start_slot = rand() % m_keys.size();
            if (!_can_use_for_get(start_slot)) {
                start_slot = _get_next_slot(start_slot, pattern, it, &temprotate);
            }
        }
        auto cur_slot = start_slot;
        while (rotated == false || cur_slot != start_slot) {
            auto next_slot = _get_next_slot(cur_slot, pattern, it, &rotated);
            if (_can_use_for_get(cur_slot)) {
                auto temp = m_keys[cur_slot].get();
                if (exclusive_access && !temp->mark_exclusive()) {
                    cur_slot = next_slot; // try next as someone else took exclusive lock
                    continue;
                }
                ki = temp;
                m_next_read_slots[pattern].store(next_slot, std::memory_order_release);
                break;
            }
            cur_slot = next_slot;
        }
        assert(ki->m_mutate_count < 1000000000);
        return ki;
    }

    std::vector< key_info_ptr< K, V > > _get_contigoous_keys(KeyPattern first_key_pattern, bool exclusive_access,
                                                             bool is_mutate, uint32_t num_needed) {
        assert((first_key_pattern == SEQUENTIAL) || (first_key_pattern == UNI_RANDOM) ||
               (first_key_pattern == PSEUDO_RANDOM));

        std::vector< key_info_ptr< K, V > > kis;
        kis.reserve(num_needed);

        // Get the first key based on the pattern
        auto ki = _get_key(first_key_pattern, is_mutate, exclusive_access);
        if (ki == nullptr) {
            return kis;
        }
        kis.push_back(key_info_ptr(this, ki, is_mutate));

        // Subsequent keys cannot use given pattern, but stricly based on the data_map sorted order
        auto it = m_data_set.find(ki);
        assert(it != m_data_set.end());
        ++it;

        while ((it != m_data_set.end()) && (num_needed > kis.size())) {
            ki = *it;
            if (_can_use_for_get(ki->m_slot_num)) {
                if (exclusive_access) {
                    if (!ki->mark_exclusive()) { // contiquity broken due to non-exclsuive exceess
                        m_next_read_slots[first_key_pattern].store(ki->m_slot_num, std::memory_order_release);
                        return kis;
                    }
                }
                kis.push_back(key_info_ptr(this, ki, is_mutate));
            } else {
                // Unable to use for get, so it breaks contiguity.
                m_next_read_slots[first_key_pattern].store(ki->m_slot_num, std::memory_order_release);
                return kis;
            }
            ++it;
        }
        auto next_slot = -1;
        if (it == m_data_set.end()) {
            it = m_data_set.begin();
            next_slot = (*it)->m_slot_num;
        } else {
            bool rotated = false;
            next_slot = _get_next_slot(ki->m_slot_num, first_key_pattern, it, &rotated);
        }
        m_next_read_slots[first_key_pattern].store(next_slot, std::memory_order_release);
        return kis;
    }

    std::vector< V > _get_contigoous_values(ValuePattern first_value_pattern, bool exclusive_access, bool is_mutate,
                                            uint32_t num_needed) {
        assert((first_value_pattern == SEQUENTIAL_VAL) || (first_value_pattern == RANDOM_BYTES));

        assert(0); // TODO
    }

    K* _get_last_gen_key(KeyPattern pattern) {
        auto last_slot = m_last_gen_slots[pattern].load(std::memory_order_relaxed);
        if (last_slot == -1) {
            return nullptr;
        }
        return &m_keys[last_slot]->m_key;
    }

    V* _get_last_gen_value(ValuePattern pattern) {
        return m_last_gen_value.get();
    }
    
    void _set_last_gen_value(std::shared_ptr< V >  value) {
        m_last_gen_value = value;
    }

    void _set_last_gen_slot(KeyPattern pattern, size_t slot) {
        m_last_gen_slots[pattern].store(slot, std::memory_order_relaxed);
    }

    template < class Iterator >
    int32_t _get_next_slot(int32_t cur_slot, KeyPattern pattern, Iterator& it, bool* rotated) {
        *rotated = false;
        if (pattern == SEQUENTIAL) {
            ++it;
            if (it == m_data_set.end()) {
                it = m_data_set.begin();
                *rotated = true;
            }
            return (*it)->m_slot_num;
        } else {
            int32_t next_slot = m_alive_slots.find_next(cur_slot);
            if (next_slot == (int32_t)boost::dynamic_bitset<>::npos || next_slot == cur_slot) {
                next_slot = m_alive_slots.find_first();
                *rotated = true;
            }
            return next_slot;
        }
    }

    bool _can_use_for_get(int32_t slot) { return (m_alive_slots[slot] && !m_keys[slot]->is_exclusive()); }

    void _free_key(key_info< K, V >* ki) {
        assert(m_used_slots[ki->m_slot_num]);
        assert(m_alive_slots[ki->m_slot_num] == false); // must have been declared dead before hand
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
            m_keys[left_ind]->m_slot_num = left_ind; // update slot in key info
            _adjust_slot_num(right_ind, left_ind);

            // while moving state of slots used/alive must be same
            assert(m_used_slots[left_ind] == m_alive_slots[left_ind]);
            m_used_slots[right_ind] = false;
            m_used_slots[left_ind] = true;
            // moving alive state, right ind state could be dead or alive in reality
            m_alive_slots[left_ind] = m_alive_slots[right_ind];
            m_alive_slots[right_ind] = false;
            // LOGDEBUG("Marked dead slot: {}, moved to {}", right_ind, left_ind);
            left_ind++;
        }

        n_gcd = m_keys.size() - left_ind;
        if (n_gcd > 0) {
            // trim start for both slot vectors
            m_used_slots.resize(left_ind);
            m_alive_slots.resize(left_ind);
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

    bool cmp(std::shared_ptr< V > a, std::shared_ptr< V > b) { return a->compare(*b.get()); };

    struct compare_value {
    public:
        bool operator()(std::shared_ptr< V > const& v1, std::shared_ptr< V > const& v2) const {
            return (v1->compare(*v2.get()) < 0);
        }
    };

private:
    std::shared_mutex                                  m_rwlock;
    std::vector< std::unique_ptr< key_info< K, V > > > m_keys;
    boost::dynamic_bitset<> m_used_slots;  // can have slots mark freed but eventually freed
    boost::dynamic_bitset<> m_alive_slots; // will only have slots which are not mark freed
    std::set< key_info< K, V >*, compare_key_info< K, V > > m_data_set;
    std::set< std::shared_ptr< V >, compare_value >         m_value_set; // actual values
    int32_t                                                 m_ndirty = 0;
    std::shared_ptr< V >                                    m_last_gen_value = nullptr;

    key_info< K, V >                                           m_invalid_ki;
    std::array< std::atomic< int32_t >, KEY_PATTERN_SENTINEL > m_last_gen_slots;
    std::array< std::atomic< int32_t >, KEY_PATTERN_SENTINEL > m_next_read_slots;
};

template < typename K, typename V >
key_info_ptr< K, V >::~key_info_ptr() {
    bool need_to_free = (m_is_mutate ? m_ki->mutation_completed() : m_ki->read_completed());
    if (need_to_free) {
        m_registry->free_key(m_ki);
    }
}

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_KEYSET_HPP
