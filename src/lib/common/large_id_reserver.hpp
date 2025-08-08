#pragma once
#include <cstdint>
#include <boost/icl/split_interval_map.hpp>
#include <boost/icl/interval_map.hpp>
#include "common/homestore_assert.hpp"

namespace homestore {
class LargeIDReserver {
private:
    using IntervalSet = boost::icl::interval_set< uint32_t >;
    using Interval = IntervalSet::interval_type;

    IntervalSet m_iset;
    uint64_t m_max;

public:
    LargeIDReserver(uint32_t max_count) : m_max{max_count} {}
    ~LargeIDReserver() = default;

    static constexpr uint64_t out_of_bounds = std::numeric_limits< uint64_t >::max();
    uint64_t reserve() {
        uint64_t id = find_next();
        if (id >= m_max) { return out_of_bounds; }
        m_iset.insert(Interval::right_open(id, id + 1));
        return id;
    }

    void reserve(uint64_t id) {
        HS_DBG_ASSERT(!is_reserved(id), "Reserving an already reserved id={}", id);
        m_iset.insert(Interval::right_open(id, id + 1));
    }

    void unreserve(uint64_t id) {
        HS_DBG_ASSERT_LT(id, m_max, "Unreserving an id which was out of bounds");
        m_iset.erase(Interval::right_open(id, id + 1));
    }

    bool is_reserved(uint64_t id) const { return (m_iset.find(id) != m_iset.end()); }

private:
    uint64_t find_next() const {
        uint64_t next = 0;
        auto it = m_iset.begin();
        while (it != m_iset.end()) {
            if (it->lower() != 0) {
                next = it->lower() - 1;
                break;
            } else {
                next = it->upper();
                ++it;
            }
        }
        return next;
    }
};
} // namespace homestore