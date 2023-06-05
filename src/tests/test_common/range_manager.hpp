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

#include <boost/icl/closed_interval.hpp>
#include <boost/icl/interval_set.hpp>
#include <boost/icl/separate_interval_set.hpp>
#include <boost/icl/split_interval_set.hpp>
#include <cassert>
namespace homestore {
using namespace boost::icl;
typedef interval_set< uint32_t > set_t;
typedef set_t::interval_type ival;

class RangeScheduler {
public:
    void add_to_existing(uint32_t s) { add_to_existing(s, s); }

    void add_to_working(uint32_t s) { add_to_working(s, s); }

    void add_to_existing(uint32_t s, uint32_t e) { m_existing_keys += ival::closed(s, e); }

    void add_to_working(uint32_t s, uint32_t e) { m_working_keys += ival::closed(s, e); }

    void remove_from_existing(uint32_t s, uint32_t e) { m_existing_keys -= ival::closed(s, e); }

    void remove_from_existing(uint32_t s) { remove_from_existing(s, s); }

    void remove_from_working(uint32_t s) { remove_from_working(s, s); }

    void remove_from_working(uint32_t s, uint32_t e) { m_working_keys -= ival::closed(s, e); }

    bool is_working(uint32_t cur_key) { return m_working_keys.find(cur_key) != m_working_keys.end(); }

    bool is_existing(uint32_t cur_key) { return m_existing_keys.find(cur_key) != m_existing_keys.end(); }

    void lock() { m_set_lock.lock(); }

    void unlock() { m_set_lock.unlock(); }

    int pick_random_non_existing_keys(uint32_t n_keys = 1, uint32_t max_range = 0) {
        uint32_t working_range = max_range <= 0 ? std::numeric_limits< uint32_t >::max() : max_range;
        uint32_t num_retry = 0;

        this->lock();
        auto num_intervals = static_cast< uint32_t >(m_existing_keys.iterative_size());
        std::uniform_int_distribution< uint32_t > s_rand_interval_generator{0, num_intervals - 1};
        uint32_t start_key = std::numeric_limits< uint32_t >::max();

        while (num_retry < max_retries) {
            // find a random interval
            uint32_t next_lower = working_range;
            uint32_t previous_upper = 0;
            auto it = m_existing_keys.begin();
            // if the selected interval is the last ... check size between this one and the working_range, rand n keys
            // in (previous_upper, working_range] = [previous_upper+1, working_range] choose the gap between this upper
            // and the next begin. and check the size! rand nkeys in [previous_upper, next_lower]
            if (num_intervals != 0) {
                uint32_t cur_interval_idx = s_rand_interval_generator(m_re);
                std::advance(it, cur_interval_idx);
                previous_upper = last(*it) + 1; // to be inclusivelast
                it++;
                if (it != m_existing_keys.end()) { next_lower = first(*it) - 1; }
            }
            if ((next_lower + 1) < (n_keys + previous_upper)) { // check < or <=
                num_retry++;
                continue;
            }

            // choose randomly n keys in [previous_upper, next_lower]
            std::uniform_int_distribution< uint32_t > rand_key_generator{
                previous_upper, next_lower - n_keys + 1}; // n_keys or n_keys +- (1)
            start_key = rand_key_generator(m_re);
            auto found = (m_working_keys & ival::closed(start_key, start_key + n_keys - 1));
            if (found.empty()) {
                auto validate = m_existing_keys & ival::closed(start_key, start_key + n_keys - 1);
                assert(validate.empty());
                break;
            }
            num_retry++;
            continue;
        }
        if (num_retry == max_retries) {
            this->unlock();
            return -1;
        }
        // add from working keys and return the start_key;
        this->add_to_working(start_key, start_key + n_keys - 1);
        assert(start_key + n_keys - 1 <= working_range);
        this->unlock();
        return static_cast< int >(start_key);
    }

    int pick_random_existing_keys(uint32_t n_keys = 1, uint32_t max_range = 0) {
        uint32_t working_range = max_range <= 0 ? std::numeric_limits< uint32_t >::max() : max_range;
        uint32_t num_retry = 0;

        this->lock();
        auto num_intervals = static_cast< uint32_t >(m_existing_keys.iterative_size());
        // empty keys
        if (num_intervals == 0) {
            this->unlock();
            return -1;
        }
        std::uniform_int_distribution< uint32_t > s_rand_interval_generator{0, num_intervals - 1};
        uint32_t start_key = std::numeric_limits< uint32_t >::max();

        while (num_retry < max_retries) {
            // find a random interval
            auto it = m_existing_keys.begin();
            uint32_t cur_interval_idx = s_rand_interval_generator(m_re);
            std::advance(it, cur_interval_idx);
            uint32_t upper = last(*it);
            uint32_t lower = first(*it);
            if ((upper + 1) < (n_keys + lower)) { // check < or <=
                num_retry++;
                continue;
            }
            // choose randomly n keys in [lower, upper]
            std::uniform_int_distribution< uint32_t > rand_key_generator{lower, upper - n_keys + 1};
            start_key = rand_key_generator(m_re);
            auto found = (m_working_keys & ival::closed(start_key, start_key + n_keys - 1));
            if (found.empty()) {
                auto validate = m_existing_keys & ival::closed(start_key, start_key + n_keys - 1);
                assert(!validate.empty());
                break;
            }
            num_retry++;
            continue;
        }
        if (num_retry == max_retries) {
            this->unlock();
            return -1;
        }
        // add from working keys and return the start_key;
        this->add_to_working(start_key, start_key + n_keys - 1);
        assert(start_key + n_keys - 1 <= working_range);
        this->unlock();
        return static_cast< int >(start_key);
    }

    int pick_random_non_working_keys(uint32_t n_keys = 1, uint32_t max_range = 0) {
        uint32_t working_range = max_range <= 0 ? std::numeric_limits< uint32_t >::max() : max_range;
        uint32_t num_retry = 0;

        this->lock();
        auto num_intervals = static_cast< uint32_t >(m_working_keys.iterative_size());
        // empty keys
        if (num_intervals == 0) {
            this->unlock();
            return -1;
        }
        std::uniform_int_distribution< uint32_t > s_rand_interval_generator{0, num_intervals - 1};
        uint32_t start_key = std::numeric_limits< uint32_t >::max();

        while (num_retry < max_retries) {
            // find a random interval
            uint32_t next_lower = working_range;
            uint32_t previous_upper = 0;
            auto it = m_working_keys.begin();
            if (num_intervals != 0) {
                uint32_t cur_interval_idx = s_rand_interval_generator(m_re);
                std::advance(it, cur_interval_idx);
                previous_upper = last(*it) + 1; // to be inclusivelast
                it++;
                if (it != m_working_keys.end()) { next_lower = first(*it) - 1; }
            }
            if ((next_lower + 1) < (n_keys + previous_upper)) { // check < or <=
                num_retry++;
                continue;
            }

            // choose randomly n keys in [previous_upper, next_lower]
            std::uniform_int_distribution< uint32_t > rand_key_generator{
                previous_upper, next_lower - n_keys + 1}; // n_keys or n_keys +- (1)
            start_key = rand_key_generator(m_re);
            break;
        }
        if (num_retry == max_retries) {
            //            std::cout<<fmt::format("A free sub-range of {} keys in range [0-{}] cannot be found after {}
            //            retries", n_keys, working_range, max_retries);
            this->unlock();
            return -1;
        }
        // add from working keys and return the start_key;
        this->add_to_working(start_key, start_key + n_keys - 1);
        assert(start_key + n_keys - 1 <= working_range);
        this->unlock();
        return static_cast< int >(start_key);
    }

private:
    set_t m_existing_keys;
    set_t m_working_keys;
    std::mutex m_set_lock;
    std::random_device m_rd{};
    std::default_random_engine m_re{m_rd()};
    const uint32_t max_retries = 5;
};
}; // namespace homestore
