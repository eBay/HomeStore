#pragma once
#include <functional>

#include <folly/small_vector.h>
#include <sisl/cache/simple_hashmap.hpp>
#include <sisl/metrics/metrics.hpp>

#include "../blkalloc/blk.h"

namespace homestore {
typedef std::function< void(void) > after_remove_cb_t;

struct blk_track_waiter {
    blk_track_waiter(after_remove_cb_t&& cb) : m_cb{std::move(cb)} {}

    ~blk_track_waiter() { m_cb(); }
    after_remove_cb_t m_cb;
};

struct blk_sub_range_record {
    blk_sub_range_record(const BlkId& bid, int64_t ref) : sub_range{bid}, ref_count{ref} {}

    BlkId sub_range;
    int64_t ref_count{0};
    std::shared_ptr< blk_track_waiter > waiter;
};

struct BlkTrackRecord {
    BlkId m_key;
    int64_t m_total_refcount{0};
    folly::small_vector< blk_sub_range_record, 8 > m_sub_record;
};

class BlkReadTrackerMetrics : public sisl::MetricsGroup {
public:
    explicit BlkReadTrackerMetrics() : sisl::MetricsGroupWrapper("BlkReadTracker", "DataSvc") {
        REGISTER_COUNTER(blktrack_pending_blk_read_map_sz, "Size of pending blk read map",
                         sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blktrack_erase_blk_rescheduled, "Erase blk rescheduled due to concurrent rw");
        register_me_to_farm();
    }

    ~BlkReadTrackerMetrics() { deregister_me_from_farm(); }
};

class BlkReadTracker {
    static constexpr uint32_t expected_num_records = 1000;
    static constexpr uint32_t entries_per_record = 64;

    sisl::SimpleCache< BlkId, BlkTrackRecord > m_pending_reads_map;
    BlkReadTrackerMetrics m_metrics;

public:
    BlkReadTracker();

    // Insert the blkid into read tracker. If entry already exists, it will increment the reference count of the blkid
    // It symbolises that this blkid is being read right now
    void insert(const BlkId& blkid);

    // Decrement the reference count of the BlkId in this read tracker. If refcount is It symbolises that this blkid is
    // no-longer being read right now
    void remove(const BlkId& blkid);

    // Check if the reference count of the blkid is 0 or entry itself doesn't exists. It will optionally callback when
    // the reference count becomes 0 and the entry is removed
    bool ensure_no_record(const BlkId& blkid, after_remove_cb_t&& after_remove_cb);

    uint64_t get_size() const { return m_pending_reads_map.get_size(); }

private:
    void merge(const BlkId& blkid, int64_t new_ref_count, const std::shared_ptr< blk_track_waiter >& waiters);
};
} // namespace homestore