//
// Created by Kadayam, Hari on 16/01/18.
//

#pragma once

#include "useful_defs.hpp"
#include <cassert>
#include <vector>
#include <folly/ThreadLocal.h>

namespace omds {
enum stats_type : uint8_t {
    COUNTER = 0,
    LATENCY,
    ERROR_COUNTER = 2
};

typedef uint32_t req_stats_index;

struct stats_key {
    uint32_t        index;
    stats_type      type;
    req_stats_index mean_of; // If stats cannot be added, but averaged out by some index
    const char      *name;
};

#define STATS_INVALID_INDEX    UINT32_MAX

class Stats {
public:
    Stats(std::vector<stats_key> &keys) :
            m_keys(keys) {
        m_values = new std::atomic<uint64_t>[keys.size()];
        for (auto i = 0; i < keys.size(); i++) {
            m_values[i].store(0, std::memory_order_relaxed);
        }
    }

    ~Stats() {
        delete(m_values);
    }

    void set_count(req_stats_index ind, uint64_t val) {
        assert(m_keys[ind].type == COUNTER);
        m_values[ind].store(val, std::memory_order_relaxed);
    }

    void inc_count(req_stats_index ind, uint64_t val = 1) {
        assert(m_keys[ind].type == COUNTER);
        m_values[ind].fetch_add(val, std::memory_order_relaxed);
    }

    void dec_count(req_stats_index ind, uint64_t val = 1) {
        assert(m_keys[ind].type == COUNTER);
        m_values[ind].fetch_sub(val, std::memory_order_relaxed);
    }

    void inc_time(req_stats_index ind, uint64_t t) {
        assert(m_keys[ind].type == LATENCY);
        m_values[ind].fetch_add(t, std::memory_order_relaxed);
    }

    void inc_elapsed_time(req_stats_index ind, Clock::time_point oldp) {
        assert(m_keys[ind].type == LATENCY);
        m_values[ind].fetch_add(get_elapsed_time_us(oldp), std::memory_order_relaxed);
    }

    void inc_time(req_stats_index ind, Clock::time_point t1, Clock::time_point t2) {
        assert(m_keys[ind].type == LATENCY);
        m_values[ind].fetch_add(get_elapsed_time_us(t1, t2), std::memory_order_relaxed);
    }

    uint64_t get(req_stats_index ind) const {
        return m_values[ind].load(std::memory_order_relaxed);
    }

    class iterator {
        friend class Stats;

    public:
        iterator(const Stats *stats) :
                m_stats(stats),
                m_cur_ind((req_stats_index)0) {}

        virtual void operator++() {
            // using IntType = typename std::underlying_type<req_stats_index>::type;
            m_cur_ind = static_cast<req_stats_index>(static_cast<uint32_t>(m_cur_ind) + 1);
            //((int)m_cur_ind)++;
        }

        virtual void operator++(int) {
            m_cur_ind = static_cast<req_stats_index>(static_cast<uint32_t>(m_cur_ind) + 1);
            //((int)m_cur_ind)++;
        }

        virtual std::pair< const char *, uint64_t > operator*() const {
            if (m_cur_ind == m_stats->m_keys.size()) {
                return std::make_pair("sentinel", 0);
            }

            uint64_t val = m_stats->get(m_cur_ind);
            if (m_stats->m_keys[m_cur_ind].mean_of != STATS_INVALID_INDEX) {
                uint64_t divide_by = m_stats->get(m_stats->m_keys[m_cur_ind].mean_of);
                val = (divide_by == 0) ? val : val / divide_by;
            }
            return std::make_pair(m_stats->m_keys[m_cur_ind].name, val);
        }

        bool operator==(const iterator &other) const {
            return (m_cur_ind == other.m_cur_ind);

        }

        bool operator!=(const iterator &other) const {
            return (m_cur_ind != other.m_cur_ind);
        }

    private:
        const Stats *m_stats;
        req_stats_index m_cur_ind;
    };

    iterator begin() const {
        iterator it(this);
        it.m_cur_ind = (req_stats_index) 0;
        return it;
    }

    iterator end() const {
        iterator it(this);
        it.m_cur_ind = m_keys.size();
        return it;
    }

    void print() const {
        std::cout << "---------------------------------" << "\n";
        for (auto it = begin(); it != end(); ++it) {
            std::cout << (*it).first << " " << (*it).second << "\n";
        }
        std::cout << "---------------------------------" << "\n";
    }

private:
    std::vector<stats_key> &m_keys;
    std::atomic<uint64_t>  *m_values;
};
}
