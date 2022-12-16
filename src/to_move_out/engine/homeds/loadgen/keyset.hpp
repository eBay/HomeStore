/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#ifndef HOMESTORE_KEYSET_HPP
#define HOMESTORE_KEYSET_HPP

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <memory>
#include <random>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <type_traits>
#include <vector>

#include <boost/circular_buffer.hpp>
#include <boost/dynamic_bitset.hpp>
#include <farmhash.h>
#include <folly/RWSpinLock.h>

#include "loadgen_common.hpp"

namespace homeds {
namespace loadgen {

//////////////////////////////////// SFINAE Hash Selection /////////////////////////////////

namespace keyset_detail {
constexpr size_t MAX_HASH_CODE_ENTRIES{10}; // Max hash codes to store in each keyinfo structure
constexpr uint64_t MAX_VALUE_RANGE{100000000};
constexpr uint64_t MAX_KEY_RANGE{100000000};

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
} // namespace keyset_detail

template < typename K, typename V >
struct key_info {
    mutable folly::RWSpinLock m_lock;
    K m_key;
    bool m_exclusive_access{true};
    bool m_free_pending{false};
    uint32_t m_mutate_count{0};
    uint32_t m_read_count{0};
    int32_t m_slot_num;
    mutable bool m_err{false};
    std::unique_ptr< boost::circular_buffer< uint64_t > > m_val_hash_codes;

    key_info(const K& key, const int32_t slot_num = -1) : m_key{key}, m_slot_num{slot_num} {}

    key_info(const K& key, const int32_t slot_num, const uint64_t val_hash_code) : key_info{key, slot_num} {
        add_hash_code(val_hash_code);
    }

    void set_error() { m_err = true; }

    bool is_error() const { return m_err; }

    void clear_error() const { m_err = false; }

    void mutation_started() {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        ++m_mutate_count;
    }

    void read_started() {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        ++m_read_count;
    }

    bool mutation_completed() {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        assert(m_mutate_count > 0);
        --m_mutate_count;
        if ((m_mutate_count == 0) && (m_read_count == 0)) m_exclusive_access = false;
        return should_free();
    }

    bool read_completed() {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        assert(m_read_count > 0);
        --m_read_count;
        if ((m_mutate_count == 0) && (m_read_count == 0)) m_exclusive_access = false;
        return should_free();
    }

    bool is_mutation_ongoing() const {
        folly::RWSpinLock::ReadHolder guard{m_lock};
        return (m_mutate_count != 0);
    }

    bool is_read_ongoing() const {
        folly::RWSpinLock::ReadHolder guard{m_lock};
        return (m_read_count != 0);
    }

    void mark_freed() {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        m_free_pending = true;
    }

    bool is_marked_free() const {
        folly::RWSpinLock::ReadHolder guard{m_lock};
        return (m_free_pending);
    }

    bool mark_exclusive() {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        if (m_exclusive_access == true) return false; // someone marked it exclusive already
        m_exclusive_access = true;
        return true;
    }

    bool is_exclusive() const {
        folly::RWSpinLock::ReadHolder guard{m_lock};
        return (m_exclusive_access);
    }

    void add_hash_code(const uint64_t hash_code) {
        folly::RWSpinLock::WriteHolder guard{m_lock};
        if (!m_val_hash_codes) {
            m_val_hash_codes =
                std::make_unique< boost::circular_buffer< uint64_t > >(keyset_detail::MAX_HASH_CODE_ENTRIES);
        }
        m_val_hash_codes->push_back(hash_code);
    }

    bool validate_hash_code(const uint64_t hash_code, const bool only_last) const {
        folly::RWSpinLock::ReadHolder guard{m_lock};
        if (only_last && !is_error()) { return (m_val_hash_codes->back() == hash_code); }
        for (const auto h : *m_val_hash_codes) {
            if (h == hash_code) {
                clear_error();
                m_val_hash_codes->push_back(hash_code);
                return true;
            }
        }

        return false;
    }

    uint64_t get_last_hash_code() const {
        folly::RWSpinLock::ReadHolder guard{m_lock};
        return (m_val_hash_codes->back());
    }

private:
    bool should_free() const { return (m_free_pending && !m_mutate_count && !m_read_count); }
};

template < typename charT, typename traits, typename K, typename V >
std::basic_ostream< charT, traits >& operator<<(std::basic_ostream< charT, traits >& outStream,
                                                const key_info< K, V >& ki) {
    // copy the stream formatting
    std::basic_ostringstream< charT, traits > outStringStream;
    outStringStream.copyfmt(outStream);

    // print the stream
    outStringStream << "KeyInfo: [Key=" << ki.m_key << " last_hash_code=" << ki.get_last_hash_code()
                    << " slot_num=" << ki.m_slot_num << " mutating_count=" << ki.m_mutate_count
                    << " read_count=" << ki.m_read_count << " exclusive_access?=" << ki.m_exclusive_access;
    outStream << outStringStream.str();

    return outStream;
}

template < typename K, typename V >
struct compare_key_info {
public:
    bool operator()(const key_info< K, V >* const& ki1, const key_info< K, V >* const& ki2) const {
        return (ki1->m_key.compare(&ki2->m_key) < 0);
    }
};

/*
template < typename K, typename V >
struct key_info_hash {
    size_t operator()(const key_info< K, V >*& ki) const {
        auto b = ki->m_key.get_blob();
        return util::Hash32((const char*)b.bytes, (size_t)b.size);
    }
};
*/

template < typename K, typename V >
class KeyRegistry;

template < typename K, typename V >
struct key_info_ptr {
    key_info_ptr(KeyRegistry< K, V >* const reg, key_info< K, V >* const ki, const bool is_mutate) :
            m_registry{reg}, m_ki{ki}, m_is_mutate{is_mutate} {
        is_mutate ? ki->mutation_started() : ki->read_started();
    }

    key_info_ptr(const key_info_ptr& p) : m_registry{p.m_registry}, m_ki{p.m_ki}, m_is_mutate{p.m_is_mutate} {
        // used for pushback in vector
        if (m_is_mutate)
            ++(m_ki->m_mutate_count);
        else
            ++(m_ki->m_read_count);
    }

    ~key_info_ptr() {
        const bool need_to_free{m_is_mutate ? m_ki->mutation_completed() : m_ki->read_completed()};
        if (need_to_free) { m_registry->free_key(m_ki); }
    }

    const key_info< K, V >& operator*() const { return *m_ki; }
    key_info< K, V >& operator*() { return *m_ki; }
    const key_info< K, V >* operator->() const { return m_ki; }
    key_info< K, V >* operator->() { return m_ki; }

    operator bool(void) const { return (m_ki == nullptr); }

    KeyRegistry< K, V >* m_registry;
    key_info< K, V >* m_ki;
    bool m_is_mutate;
};

template < typename K, typename V >
class KeyRegistry {
public:
    KeyRegistry() : m_invalid_ki{K::gen_key(KeyPattern::OUT_OF_BOUND, nullptr)} {

        for (size_t i{0}; i < static_cast< size_t >(KeyPattern::KEY_PATTERN_SENTINEL); ++i) {
            m_last_gen_slots[i].store(-1);
            m_next_read_slots[i].store(0);
        }
    }

    void set_max_keys(const uint64_t max_keys) {
        K::MAX_KEYS = max_keys;
        V::MAX_VALUES = 2 * max_keys;
    }

    virtual ~KeyRegistry() {
        auto itr{std::begin(m_keys)};
        while (itr != std::end(m_keys)) {
            const auto ki{std::move(*itr)};
            assert((ki->m_read_count == 0) && (ki->m_mutate_count == 0));
            ++itr;
        }
    };

    uint64_t get_keys_count() const { return m_data_set.size(); }

    void print_data_set() const {
        auto itr{std::cbegin(m_data_set)};
        std::ostringstream ss;
        while (itr != std::cend(m_data_set)) {
            ss << (*itr)->m_key.to_string() << "\n";
            ++itr;
        }
        LOGERROR("key set:{}", ss.str());
    }

    size_t update_contigious_kv(std::vector< key_info_ptr< K, V > >& kv, std::vector< std::shared_ptr< V > >& val_vec) {
        std::unique_lock l{m_rwlock};
        if (kv.size() == 0) return 0;

        std::shared_ptr< V > val{generate_value_impl(ValuePattern::RANDOM_BYTES)}; // GENERATE RANDOM NON-EXISTENT VALUE
        auto keyit{std::begin(kv)};
        size_t count{0};
        bool pregenerated{true};

        while (keyit != std::end(kv)) { // keys and values
            auto& kip{*keyit};

            if (pregenerated) {
                pregenerated = false;
            } else {
                /** GENERATE SEQ VALUE AND SEE IF IT ALREADY EXISTS **/
                std::shared_ptr< V > temp{V::gen_value(ValuePattern::SEQUENTIAL_VAL, val.get())};
                if (temp == nullptr) { return count; }
                val = temp;
            }

            /** LINK NEW VALUE TO EXISTING KEY */
            kip->add_hash_code(val->get_hash_code());
            val_vec.push_back(val);

            ++count;
            ++keyit;
        }
        return count;
    }

    std::shared_ptr< V > generate_value(const ValuePattern value_pattern) {
        std::unique_lock l{m_rwlock};
        return generate_value_impl(value_pattern);
    }

    key_info_ptr< K, V > generate_and_put_key(const KeyPattern gen_pattern) {
        std::unique_lock l{m_rwlock};
        auto kip{key_info_ptr{this, generate_key_impl(gen_pattern), true}};
        const auto result{m_data_set.insert(kip.m_ki)};
        if (result.second == false) {
            LOGERROR("generated key is not unique!");
            assert(false);
        }
        return kip;
    }

    key_info_ptr< K, V > generate_key(const KeyPattern gen_pattern) const {
        std::unique_lock l{m_rwlock};
        return key_info_ptr{this, generate_key_impl(gen_pattern), true};
    }

    std::vector< key_info_ptr< K, V > > generate_keys(const KeyPattern gen_pattern, const uint32_t n) const {
        std::vector< key_info_ptr< K, V > > gen_keys;
        gen_keys.reserve(n);

        std::unique_lock l{m_rwlock};
        for (uint32_t i{0}; i < n; ++i) {
            gen_keys.emplace_back(key_info_ptr(this, generate_key_impl(gen_pattern), true));
        }
        return gen_keys;
    }

    // Assume last key as invalid key always. NOTE: This will no longer be invalid in case it is actually
    // inserted into the store.
    key_info_ptr< K, V > generate_invalid_key() { return key_info_ptr{this, &m_invalid_ki, true}; }

    key_info_ptr< K, V > get_key(const KeyPattern pattern, const bool is_mutate, const bool exclusive_access) {
        key_info< K, V >* ki{nullptr};
        while (ki == nullptr) {           // relase locks and retry
            std::unique_lock l{m_rwlock}; // uniq lock needed since multiple threads can aquire next slot
            ki = get_key_impl(pattern, is_mutate, exclusive_access);
        }
        return key_info_ptr{this, ki, is_mutate};
    }

    key_info_ptr< K, V > get_key(const K& key, const bool is_mutate) {
        key_info< K, V >* const k{find_key(key)};
        assert(k != nullptr);
        return key_info_ptr{this, k, is_mutate};
    }

    // make sures contigious keys returned from data set is also consecutive
    std::vector< key_info_ptr< K, V > > get_consecutive_keys(const KeyPattern pattern, const bool exclusive_access,
                                                             const bool is_mutate, const uint32_t num_needed) {
        std::unique_lock l{m_rwlock};
        std::vector< key_info_ptr< K, V > > kips =
            get_contiguous_keys_impl(pattern, exclusive_access, is_mutate, num_needed);
        if (kips.size() <= 1) return kips;

        size_t count{1};

        for (size_t i{1}; i < kips.size(); ++i) {
            if (!kips[i - 1]->m_key.is_consecutive(kips[i]->m_key)) break;
            ++count;
        }

        if (count != kips.size()) { kips.erase(std::next(std::begin(kips), count), std::end(kips)); }
        assert(count == kips.size());
        return kips;
    }

    // returns keys contigious according to available dataset
    std::vector< key_info_ptr< K, V > > get_contiguous_keys(const KeyPattern pattern, const bool exclusive_access,
                                                            const bool is_mutate, const uint32_t num_needed) {
        std::unique_lock l{m_rwlock}; // uniq lock needed since multiple threads can aquire next slot
        return get_contiguous_keys_impl(pattern, exclusive_access, is_mutate, num_needed);
    }

    std::vector< V > get_contiguous_values(const ValuePattern pattern, const bool exclusive_access,
                                           const bool is_mutate, const uint32_t num_needed) {
        std::unique_lock l{m_rwlock}; // uniq lock needed since multiple threads can aquire next slot
        return get_contiguous_values_impl(pattern, exclusive_access, is_mutate, num_needed);
    }

    std::vector< key_info_ptr< K, V > > get_keys(const KeyPattern pattern, const uint32_t n, const bool is_mutate,
                                                 const bool exclusive_access) const {
        std::vector< key_info_ptr< K, V > > kis;
        kis.reserve(n);

        std::shared_lock l{m_rwlock};
        for (uint32_t i{0}; i < n; ++i) {
            kis.emplace_back(key_info_ptr{get_key_impl(pattern, exclusive_access), is_mutate});
        }
        return kis;
    }

    void put_key(key_info_ptr< K, V >& kip) {
        std::unique_lock l{m_rwlock};
        const auto result{m_data_set.insert(kip.m_ki)};
        if (result.second == false) {
            LOGERROR("generated key is not unique!");
            assert(false);
        }
        assert(result.second);
    }

    void remove_key(key_info_ptr< K, V >& kip) {
        std::unique_lock l{m_rwlock};
        LOGDEBUG("Erasing key:{}", kip.m_ki->m_key.to_string());
        const auto x{m_data_set.erase(kip.m_ki)};
        if (x == 0) {
            LOGERROR("Key not found!");
            assert(false);
        }
        kip->mark_freed();
        assert(m_alive_slots[kip.m_ki->m_slot_num] == true);
        // LOGDEBUG("Removed key {} , marked dead slot: {}",kip.m_ki->m_key,kip.m_ki->m_slot_num);
        m_alive_slots[kip.m_ki->m_slot_num] = false; // declare dead slot so as get_key do not pick it up
    }

    // no locking done here, client is expected to get lock
    key_info< K, V >* find_key(const K& key) {
        key_info< K, V > ki{key, 0};
        auto it{m_data_set.find(&ki)};
        if (it == std::end(m_data_set)) return nullptr;
        key_info< K, V >* const expected_ki{*it};
        if (expected_ki->m_key.compare(&key) != 0) return nullptr;
        return expected_ki;
    }

    // no locking done here, client is expected to get lock
    bool has_key(key_info< K, V >* const ki) const {
        const auto it{m_data_set.find(ki)};
        if (it == std::cend(m_data_set)) return false;
        const key_info< K, V >* const expected_ki{*it};
        if (expected_ki->m_key.compare(&ki->m_key) != 0) return false;
        return true;
    }

    friend struct key_info_ptr< K, V >;

    void reset_pattern(const KeyPattern pattern, const int32_t index = 0) {
        std::unique_lock l{m_rwlock};
        m_next_read_slots[static_cast< size_t >(pattern)].store(index, std::memory_order_relaxed);
    }

private:
    key_info< K, V >* generate_key_impl(K& key) {
        const int32_t slot_num{static_cast< uint32_t >(m_keys.size())};
        auto newKi{std::make_unique< key_info< K, V > >(key, slot_num)};
        assert(newKi->m_mutate_count < 1000000000);
        m_keys.emplace_back(std::move(newKi));
        m_used_slots.push_back(true);
        m_alive_slots.push_back(true);
        m_last_gen_slots[static_cast< size_t >(KeyPattern::UNI_RANDOM)].store(slot_num, std::memory_order_relaxed);
        LOGDEBUG("Generated key:{}", key.to_string());
        return m_keys.back().get();
    }

    void free_key(key_info< K, V >* const ki) {
        std::unique_lock l{m_rwlock};
        free_key_impl(ki);
    }

    std::shared_ptr< V > generate_value_impl(const ValuePattern value_pattern) {
        std::shared_ptr< V > nv{V::gen_value(value_pattern, get_last_gen_value_impl(value_pattern))};
        return nv;
    }

    key_info< K, V >* generate_key_impl(const KeyPattern gen_pattern) {
        int32_t slot_num{static_cast< int32_t >(m_keys.size())};
        std::unique_ptr< key_info< K, V > > newKi{};
        uint64_t trygen{0};
        do {
            if (trygen++ == keyset_detail::MAX_KEY_RANGE) {
                LOGERROR("Could not generate keys!!!");
                assert(false);
            }
            newKi = std::make_unique< key_info< K, V > >(K::gen_key(gen_pattern, get_last_gen_key_impl(gen_pattern)),
                                                         slot_num);
        } while (has_key(newKi.get()));

        // Generate a key and put in the key list and mark that slot as valid.
        LOGDEBUG("Generated key:{}", newKi->m_key.to_string());
        m_keys.emplace_back(std::move(newKi));
        m_used_slots.push_back(true);
        m_alive_slots.push_back(true);
        m_last_gen_slots[static_cast< size_t >(gen_pattern)].store(slot_num, std::memory_order_relaxed);
        return m_keys.back().get();
    }

    key_info< K, V >* get_key_impl(const KeyPattern pattern, const bool is_mutate, const bool exclusive_access) {
        assert((pattern == KeyPattern::SEQUENTIAL) || (pattern == KeyPattern::UNI_RANDOM) ||
               (pattern == KeyPattern::PSEUDO_RANDOM));

        int32_t start_slot{0};
        key_info< K, V >* ki{nullptr};
        assert(m_data_set.size() != 0);
        bool rotated{false}, temprotate{false};
        typename std::set< key_info< K, V >*, compare_key_info< K, V > >::iterator it;
        if (pattern == KeyPattern::SEQUENTIAL) {
            start_slot = m_next_read_slots[static_cast< size_t >(pattern)].load(std::memory_order_acquire);
            it = m_data_set.find(m_keys[start_slot].get());

            // remove punches holes, if it was last slot being punched, we have to start over
            if (it == std::end(m_data_set)) {
                start_slot = get_next_slot_impl(start_slot, pattern, it, &temprotate); // auto increments *it
            }
        } else if (pattern == KeyPattern::UNI_RANDOM) {
            static thread_local std::random_device rd{};
            static thread_local std::default_random_engine re{rd()};
            std::uniform_int_distribution< int32_t > rand_slot{0, static_cast< int32_t >(m_keys.size() - 1)};
            start_slot = rand_slot(re);
            if (!can_use_for_get_impl(start_slot, is_mutate)) {
                start_slot = get_next_slot_impl(start_slot, pattern, it, &temprotate);
            }
        }
        auto cur_slot{start_slot};
        while ((rotated == false) || (cur_slot != start_slot)) {
            const auto next_slot{get_next_slot_impl(cur_slot, pattern, it, &rotated)};
            if (can_use_for_get_impl(cur_slot, is_mutate)) {
                auto* const temp{m_keys[cur_slot].get()};
                if (exclusive_access && !temp->mark_exclusive()) {
                    cur_slot = next_slot; // try next as someone else took exclusive lock
                    continue;
                }
                ki = temp;
                m_next_read_slots[static_cast< size_t >(pattern)].store(next_slot, std::memory_order_release);
                break;
            }
            cur_slot = next_slot;
        }
        assert(ki->m_mutate_count < 1000000000);
        return ki;
    }

    std::vector< key_info_ptr< K, V > > get_contiguous_keys_impl(const KeyPattern first_key_pattern,
                                                                 const bool exclusive_access, const bool is_mutate,
                                                                 const uint32_t num_needed) {
        assert((first_key_pattern == KeyPattern::SEQUENTIAL) || (first_key_pattern == KeyPattern::UNI_RANDOM) ||
               (first_key_pattern == KeyPattern::PSEUDO_RANDOM));

        std::vector< key_info_ptr< K, V > > kis;
        kis.reserve(num_needed);

        // Get the first key based on the pattern
        auto* ki{get_key_impl(first_key_pattern, is_mutate, exclusive_access)};
        if (ki == nullptr) { return kis; }
        kis.push_back(key_info_ptr(this, ki, is_mutate));

        // Subsequent keys cannot use given pattern, but stricly based on the data_map sorted order
        auto it{m_data_set.find(ki)};
        assert(it != std::cend(m_data_set));
        ++it;

        while ((it != std::cend(m_data_set)) && (num_needed > kis.size())) {
            ki = *it;
            if (can_use_for_get_impl(ki->m_slot_num, is_mutate)) {
                if (exclusive_access) {
                    if (!ki->mark_exclusive()) { // contiquity broken due to non-exclsuive exceess
                        m_next_read_slots[static_cast< size_t >(first_key_pattern)].store(ki->m_slot_num,
                                                                                          std::memory_order_release);
                        return kis;
                    }
                }
                kis.push_back(key_info_ptr{this, ki, is_mutate});
            } else {
                // Unable to use for get, so it breaks contiguity.
                m_next_read_slots[static_cast< size_t >(first_key_pattern)].store(ki->m_slot_num,
                                                                                  std::memory_order_release);
                return kis;
            }
            ++it;
        }
        int32_t next_slot{-1};
        if (it == std::cend(m_data_set)) {
            it = std::cbegin(m_data_set);
            next_slot = (*it)->m_slot_num;
        } else {
            bool rotated{false};
            next_slot = get_next_slot_impl(ki->m_slot_num, first_key_pattern, it, &rotated);
        }
        m_next_read_slots[static_cast< size_t >(first_key_pattern)].store(next_slot, std::memory_order_release);
        return kis;
    }

    std::vector< V > get_contiguous_values_impl(const ValuePattern first_value_pattern, const bool exclusive_access,
                                                const bool is_mutate, const uint32_t num_needed) const {
        assert((first_value_pattern == ValuePattern::SEQUENTIAL_VAL) ||
               (first_value_pattern == ValuePattern::RANDOM_BYTES));

        assert(false); // TODO
    }

    K* get_last_gen_key_impl(const KeyPattern pattern) {
        const auto last_slot{m_last_gen_slots[static_cast< size_t >(pattern)].load(std::memory_order_relaxed)};
        if (last_slot == -1) { return nullptr; }
        return &(m_keys[last_slot]->m_key);
    }

    V* get_last_gen_value_impl(const ValuePattern pattern) { return m_last_gen_value.get(); }

    void set_last_gen_value_impl(std::shared_ptr< V > value) { m_last_gen_value = std::move(value); }

    void set_last_gen_slot_impl(const KeyPattern pattern, const int32_t slot) {
        m_last_gen_slots[static_cast< size_t >(pattern)].store(slot, std::memory_order_relaxed);
    }

    template < class Iterator >
    int32_t get_next_slot_impl(const int32_t cur_slot, const KeyPattern pattern, Iterator& it, bool* const rotated) {
        *rotated = false;
        if (pattern == KeyPattern::SEQUENTIAL) {
            ++it;
            if (it == std::end(m_data_set)) {
                it = std::begin(m_data_set);
                *rotated = true;
            }
            return (*it)->m_slot_num;
        } else {
            int32_t next_slot{static_cast< int32_t >(m_alive_slots.find_next(cur_slot))};
            if ((next_slot == static_cast< int32_t >(boost::dynamic_bitset<>::npos)) || (next_slot == cur_slot)) {
                next_slot = m_alive_slots.find_first();
                *rotated = true;
            }
            return next_slot;
        }
    }

    bool can_use_for_get_impl(const int32_t slot, const bool is_mutate) {
        return ((m_alive_slots[slot] && !m_keys[slot]->is_exclusive()) && (!is_mutate || !m_keys[slot]->is_error()));
    }

    void free_key_impl(key_info< K, V >* const ki) {
        assert(m_used_slots[ki->m_slot_num]);
        assert(m_alive_slots[ki->m_slot_num] == false); // must have been declared dead before hand
        m_used_slots[ki->m_slot_num] = false;

        if (++m_ndirty >= compact_trigger_limit()) { compact_impl(); }
    }

    uint32_t compact_impl() {
        uint32_t n_gcd{0};

        // Find the first free slot in the set, by doing a flip of bits and search for first 1.
        auto left_ind{(~m_used_slots).find_first()};
        if (left_ind == boost::dynamic_bitset<>::npos) {
            // All slots are valid, nothing to compact
            return 0;
        }

        auto right_ind{left_ind};
        while ((right_ind = m_used_slots.find_next(right_ind)) != boost::dynamic_bitset<>::npos) {
            m_keys[left_ind] = std::move(m_keys[right_ind]);
            m_keys[left_ind]->m_slot_num = left_ind; // update slot in key info
            adjust_slot_num_impl(right_ind, left_ind);

            // while moving state of slots used/alive must be same
            assert(m_used_slots[left_ind] == m_alive_slots[left_ind]);
            m_used_slots[right_ind] = false;
            m_used_slots[left_ind] = true;
            // moving alive state, right ind state could be dead or alive in reality
            m_alive_slots[left_ind] = m_alive_slots[right_ind];
            m_alive_slots[right_ind] = false;
            // LOGDEBUG("Marked dead slot: {}, moved to {}", right_ind, left_ind);
            ++left_ind;
        }

        n_gcd = m_keys.size() - left_ind;
        if (n_gcd > 0) {
            // trim start for both slot vectors
            m_used_slots.resize(left_ind);
            m_alive_slots.resize(left_ind);
            m_keys.resize(left_ind);

            assert(m_ndirty >= n_gcd);
            m_ndirty -= n_gcd;
        }

        // LOG(INFO) << "Sorted vector set: After compacting " << n_gcd << " entries: " << to_string();
        return n_gcd;
    }

    void adjust_slot_num_impl(const int32_t old_slot, const int32_t new_slot) {
        // NOTE: Because this is called under a lock from free_key it is probably ok but
        // since two slots are exchanged it is possible that they are not exchanged the same between the two
        // This should really be a double CAS operation to guarantee consistency
        int32_t expected_slot{old_slot};
        for (size_t i{0}; i < static_cast< size_t >(KeyPattern::KEY_PATTERN_SENTINEL); ++i) {
            m_last_gen_slots[i].compare_exchange_strong(expected_slot, new_slot, std::memory_order_relaxed);
            m_next_read_slots[i].compare_exchange_strong(expected_slot, new_slot, std::memory_order_relaxed);
        }
    }

    static constexpr uint32_t compact_trigger_limit() { return 100000; }

    bool cmp(const std::shared_ptr< V >& a, const std::shared_ptr< V >& b) const { return a->compare(*b.get()); };

    struct compare_value {
    public:
        bool operator()(std::shared_ptr< V > const& v1, std::shared_ptr< V > const& v2) const {
            return (v1->compare(*v2.get()) < 0);
        }
    };

private:
    mutable std::shared_mutex m_rwlock;
    std::vector< std::unique_ptr< key_info< K, V > > > m_keys;
    boost::dynamic_bitset<> m_used_slots;  // can have slots mark freed but eventually freed
    boost::dynamic_bitset<> m_alive_slots; // will only have slots which are not mark freed
    std::set< key_info< K, V >*, compare_key_info< K, V > > m_data_set;
    uint32_t m_ndirty{0};
    std::shared_ptr< V > m_last_gen_value{nullptr};

    key_info< K, V > m_invalid_ki;
    std::array< std::atomic< int32_t >,
                static_cast< std::underlying_type_t< KeyPattern > >(KeyPattern::KEY_PATTERN_SENTINEL) >
        m_last_gen_slots;
    std::array< std::atomic< int32_t >,
                static_cast< std::underlying_type_t< KeyPattern > >(KeyPattern::KEY_PATTERN_SENTINEL) >
        m_next_read_slots;
    bool m_unique_val{false}; // value generated needs to be unique
};

} // namespace loadgen
} // namespace homeds
#endif // HOMESTORE_KEYSET_HPP
