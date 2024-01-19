/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
/*
 * Homestore testing binaries shared common definitions, apis and data structures
 *
 */

#pragma once

#include <sisl/fds/bitset.hpp>
#include <cassert>

namespace homestore {
static std::pair< uint64_t, uint64_t > get_next_contiguous_set_bits(const sisl::Bitset& bm, uint64_t search_start_bit,
                                                                    uint64_t max_count) {
    uint64_t first_set_bit{sisl::Bitset::npos};
    uint64_t set_count{0};
    uint64_t b;
    while (((b = bm.get_next_set_bit(search_start_bit)) != sisl::Bitset::npos) && (set_count < max_count)) {
        if (first_set_bit == sisl::Bitset::npos) {
            first_set_bit = b;
        } else if (b > search_start_bit) {
            break;
        }
        ++set_count;
        search_start_bit = b + 1;
    }

    return std::pair(first_set_bit, set_count);
}

class RangeScheduler {
private:
    sisl::Bitset m_existing_keys;
    sisl::Bitset m_working_keys;
    std::uniform_int_distribution< uint32_t > m_rand_start_key_generator;
    std::random_device m_rd;

public:
    RangeScheduler(uint32_t num_keys) : m_existing_keys{num_keys}, m_working_keys{num_keys} {
        m_rand_start_key_generator = std::uniform_int_distribution< uint32_t >(0, num_keys - 1);
    }

    void remove_keys_from_working(uint32_t s, uint32_t e) { remove_from_working(s, e); }

    void put_key(uint32_t key) {
        add_to_existing(key);
        remove_from_working(key);
    }

    void put_keys(uint32_t start_key, uint32_t end_key) {
        add_to_existing(start_key, end_key);
        remove_from_working(start_key, end_key);
    }

    void remove_key(uint32_t key) {
        remove_from_existing(key);
        remove_from_working(key);
    }

    void remove_keys(uint32_t start_key, uint32_t end_key) {
        remove_from_existing(start_key, end_key);
        remove_from_working(start_key, end_key);
    }

    std::pair< uint32_t, uint32_t > pick_random_non_existing_keys(uint32_t max_keys) {
        std::pair< uint32_t, uint32_t > ret;
        auto max_tries = 10;
        do {
            ret = try_pick_random_non_existing_keys(max_keys);
            if (ret.first != UINT32_MAX) { break; }
        } while (--max_tries);

        return ret;
    }

    std::pair< uint32_t, uint32_t > pick_random_existing_keys(uint32_t max_keys) {
        std::pair< uint32_t, uint32_t > ret;
        auto max_tries = 10;
        do {
            ret = try_pick_random_existing_keys(max_keys);
            if (ret.first != UINT32_MAX) { break; }
        } while (--max_tries);

        return ret;
    }

    std::pair< uint32_t, uint32_t > pick_random_non_working_keys(uint32_t max_keys) {
        std::pair< uint32_t, uint32_t > ret;
        auto max_tries = 10;
        do {
            ret = try_pick_random_non_working_keys(max_keys);
            if (ret.first != UINT32_MAX) { break; }
        } while (--max_tries);

        return ret;
    }

private:
    std::pair< uint32_t, uint32_t > try_pick_random_non_existing_keys(uint32_t max_keys) {
        if ((m_existing_keys.size() - m_existing_keys.get_set_count()) == 0) {
            throw std::out_of_range("All keys are being worked on right now");
        }

        uint32_t const search_start = m_rand_start_key_generator(m_rd);
        auto bb = m_existing_keys.get_next_contiguous_n_reset_bits(search_start, max_keys);
        if (bb.nbits && m_working_keys.is_bits_reset(bb.start_bit, bb.nbits)) {
            uint32_t const start = uint32_cast(bb.start_bit);
            uint32_t const end = uint32_cast(bb.start_bit + bb.nbits - 1);
            add_to_working(start, end);
            return std::pair(start, end);
        } else {
            return std::pair(UINT32_MAX, UINT32_MAX);
        }
    }

    std::pair< uint32_t, uint32_t > try_pick_random_existing_keys(uint32_t max_keys) {
        if (m_existing_keys.get_set_count() == 0) {
            DEBUG_ASSERT(false, "Couldn't find one existing keys");
            throw std::out_of_range("Couldn't find one existing keys");
        }

        uint32_t const search_start = m_rand_start_key_generator(m_rd);
        auto [s, count] = get_next_contiguous_set_bits(m_existing_keys, search_start, max_keys);

        if (count && m_working_keys.is_bits_reset(s, count)) {
            uint32_t const start = uint32_cast(s);
            uint32_t const end = uint32_cast(s + count - 1);
            add_to_working(start, end);
            return std::pair(start, end);
        } else {
            return std::pair(UINT32_MAX, UINT32_MAX);
        }
    }

    std::pair< uint32_t, uint32_t > try_pick_random_non_working_keys(uint32_t max_keys) {
        uint32_t const search_start = m_rand_start_key_generator(m_rd);
        auto bb = m_working_keys.get_next_contiguous_n_reset_bits(search_start, max_keys);

        if (bb.nbits) {
            uint32_t const start = uint32_cast(bb.start_bit);
            uint32_t const end = uint32_cast(bb.start_bit + bb.nbits - 1);
            add_to_working(start, end);
            return std::pair(start, end);
        } else {
            return std::pair(UINT32_MAX, UINT32_MAX);
        }
    }

    void add_to_existing(uint32_t s) { add_to_existing(s, s); }

    void add_to_working(uint32_t s) { add_to_working(s, s); }

    void add_to_existing(uint32_t s, uint32_t e) { m_existing_keys.set_bits(s, e - s + 1); }

    void add_to_working(uint32_t s, uint32_t e) { m_working_keys.set_bits(s, e - s + 1); }

    void remove_from_existing(uint32_t s, uint32_t e) { m_existing_keys.reset_bits(s, e - s + 1); }

    void remove_from_existing(uint32_t s) { remove_from_existing(s, s); }

    void remove_from_working(uint32_t s) { remove_from_working(s, s); }

    void remove_from_working(uint32_t s, uint32_t e) { m_working_keys.reset_bits(s, e - s + 1); }

    bool is_working(uint32_t cur_key) const { return m_working_keys.is_bits_set(cur_key, 1); }

    bool is_existing(uint32_t cur_key) const { return m_existing_keys.is_bits_set(cur_key, 1); }
};
}; // namespace homestore
