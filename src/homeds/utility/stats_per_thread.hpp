//
// Created by Kadayam, Hari on 16/01/18.
//

#pragma once

#include "useful_defs.hpp"
#include <cassert>
#include <vector>
#include <folly/ThreadLocal.h>

namespace homeds {
enum stats_type : uint8_t {
    COUNTER = 0,
    LATENCY,
    ERROR_COUNTER = 2
};

typedef uint32_t req_stats_index;

struct stats_key {
    stats_type      type;
    req_stats_index mean_of; // If stats cannot be added, but averaged out by some index
    const char      *name;
};

struct per_thread_stats {
    per_thread_stats(std::vector<stats_key> &keys) :
            m_keys(keys),
            m_values(keys.size(), 0) {
    }

    void set_count(req_stats_index ind, uint64_t val) {
        assert(m_keys[ind].type == COUNTER);
        m_values[ind] = val;
    }

    void inc_count(req_stats_index ind, uint64_t val = 1) {
        assert(m_keys[ind].type == COUNTER);
        m_values[ind] += val;
    }

    void inc_time(req_stats_index ind, uint64_t t) {
        assert(m_keys[ind].type == LATENCY);
        m_values[ind] += t;
    }

    void inc_elapsed_time(req_stats_index ind, Clock::time_point oldp) {
        assert(m_keys[ind].type == LATENCY);
        m_values[ind] += get_elapsed_time_us(oldp);
    }

    void inc_time(req_stats_index ind, Clock::time_point t1, Clock::time_point t2) {
        assert(m_keys[ind].type == LATENCY);
        m_values[ind] += get_elapsed_time_us(t1, t2);
    }

    uint64_t get(req_stats_index ind) const {
        assert(ind < m_values.size());
        return m_values[ind];
    }

    std::vector<stats_key> &m_keys;
    std::vector<uint64_t> m_values;
};

class Stats {
public:
    Stats(std::vector<stats_key> &keys) :
            m_keys(keys) {
        m_thr_stats.reset(nullptr);
    }

    ~Stats() {
        m_thr_stats.reset(nullptr);
    }

    void set_count(req_stats_index ind, uint64_t val) {
        init_if_needed();
        return (m_thr_stats->set_count(ind, val));
    }

    void inc_count(req_stats_index ind, uint64_t val = 1) {
        init_if_needed();
        return (m_thr_stats->inc_count(ind, val));
    }

    void inc_time(req_stats_index ind, uint64_t t) {
        init_if_needed();
        return (m_thr_stats->inc_time(ind, t));
    }

    void inc_elapsed_time(req_stats_index ind, Clock::time_point oldp) {
        init_if_needed();
        return (m_thr_stats->inc_elapsed_time(ind, oldp));
    }

    void inc_time(req_stats_index ind, Clock::time_point t1, Clock::time_point t2) {
        init_if_needed();
        m_thr_stats->inc_time(ind, t1, t2);
    }

    uint64_t get(req_stats_index ind) {
        uint64_t ret = 0;
        for (const auto& ts : m_thr_stats.accessAllThreads()) {
            ret += ts.get(ind);
        }
        return ret;
    }

    class iterator {
        friend class Stats;

    public:
        iterator(Stats *stats) :
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
            if (m_stats->m_keys[m_cur_ind].mean_of != m_stats->m_keys.size()) {
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
        Stats *m_stats;
        req_stats_index m_cur_ind;
    };

    iterator begin() {
        iterator it(this);
        it.m_cur_ind = (req_stats_index) 0;
        return it;
    }

    iterator end() {
        iterator it(this);
        it.m_cur_ind = m_keys.size();
        return it;
    }

private:
    void init_if_needed() {
        if (unlikely(m_thr_stats.get() == nullptr)) {
            m_thr_stats.reset(new per_thread_stats(m_keys));
        }
    }

private:
    class tlocal_tag;
    folly::ThreadLocalPtr< per_thread_stats, tlocal_tag> m_thr_stats;
    std::vector<stats_key> &m_keys;
};
}
