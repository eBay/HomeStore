//
// Created by Kadayam, Hari on 2/22/19.
//

#ifndef HOMESTORE_KEYSET_HPP
#define HOMESTORE_KEYSET_HPP

#include "loadgen_common.hpp"
#include <shared_mutex>


namespace homeds { namespace loadgen {
template < typename K >
class KeySet {
public:
    KeySet() : m_last_read_slot(0) {
        generate_keys(1); // Atleast generate 1 key for us to be ready for read
    }

    virtual ~KeySet() = default;

    std::vector< K* > generate_keys(KeyPattern gen_pattern, uint32_t n = 1) {
        std::vector< K* > gen_keys;
        gen_keys.reserve(n);

        std::unique_lock l(m_rwlock);
        for (auto i = 0u; i < n; i++) {
            m_keys.emplace_back(K::gen_key(gen_pattern, m_keys.size() ? &m_keys.back() : nullptr));
            gen_keys.push_back(&m_keys.back());
        }
        return gen_keys;
    }

    std::vector< K* > get_keys(KeyPattern read_pattern, uint32_t n = 1) {
        assert((read_pattern == SEQUENTIAL) || (read_pattern == UNI_RANDOM) || (read_pattern == PSEUDO_RANDOM));
        std::vector< K* > out_keys;
        out_keys.reserve(n);

        std::shared_lock l(m_rwlock);
        int32_t start_slot = 0;

        if (read_pattern == SEQUENTIAL) {
            start_slot = m_last_read_slot.load(std::memory_order_acquire);
        } else if (read_pattern == UNI_RANDOM) {
            start_slot = rand() % m_keys.size();
        }
        auto cur_slot = start_slot;

        for (auto i = 0u; i < n; i++) {
            cur_slot++;
            if (cur_slot == (int32_t)m_keys.size()) { cur_slot = 0; }
            if (cur_slot == start_slot) { // We came one full circle, gen partial
                goto done;
            }
            out_keys.push_back(&m_keys[cur_slot]);
        }

done:
        m_last_read_slot.store(cur_slot, std::memory_order_release);
        return out_keys;
    }

private:
    std::shared_mutex m_rwlock;
    std::vector< K > m_keys;
    std::atomic< int32_t > m_last_read_slot;
};
} } // namespace homeds::loadgen
#endif //HOMESTORE_KEYSET_HPP
