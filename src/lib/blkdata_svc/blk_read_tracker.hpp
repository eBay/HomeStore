/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#pragma once
#include <functional>

#include <folly/small_vector.h>
#include <sisl/cache/simple_hashmap.hpp>
#include <sisl/fds/utils.hpp>
#include <sisl/metrics/metrics.hpp>
#include "homestore/blk.h"

namespace homestore {
typedef std::function< void(void) > after_remove_cb_t;

struct blk_track_waiter {
    blk_track_waiter(after_remove_cb_t&& cb) : m_cb{std::move(cb)} {
#ifdef _PRERELEASE
        m_start_time = Clock::now();
#endif
    }

    ~blk_track_waiter() {
#ifdef _PRERELEASE
        // TODO: enable this after data service is ready;
        // HISTOGRAM_OBSERVE(get_data_service().get_blk_read_tracker_inst().get_metrics(),
        // blktrack_erase_blk_rescheduled_latency, get_elapsed_time_us(m_start_time, CLock::now()));
#endif
        m_cb();
    }

    after_remove_cb_t m_cb;

#ifdef _PRERELEASE
    Clock::time_point m_start_time;
#endif
};

typedef std::shared_ptr< blk_track_waiter > blk_track_waiter_ptr;

//
// clang-format off
//
//  A read can never overlap a unfinished free-blk id;
//  A read can overlap a pending read;
//
//  Say alignment is 16;
//  1. read-1: {17, 32, 0}
//  2. free blk: {8, 32, 0}
//  3. read-2: {0, 4, 0}  // <<< this read will also create track record on {0, 16, 0}, it is fine though as we don't
//  create any record under {0, 16, 0} on free;
//

//
// When ref_cnt drops to zero (read completes), remove every waiter from the vector in this Record;
// same waiter can be attached to multple BlkTrackRecord's vector and whom ever is the last to dereference the
// shared_ptr of a waiter, triggers waiter's destrctor which sends the callback;
//
//
//  Chunk_id: 0 (alignment: 16)
//   ---------------------------------------------------------------
//  | 1, 2, ... 15, 16 | 17, 18, ..., 31, 32 | 33, 34, ..., 47, 48 |  Blk Number (unique within same chunk)
//   ---------------------------------------------------------------
//     BlkTrackRecord-1    BlkTrackRecord-2             Record-1 and Record-2 could belongs to two different read (or one read); 
//                                                      Record-1/2 could be referenced by multiple reads fall through on same base ids;
//      [ ],  [ ],  [ ]     [ ], [ ], [ ]               m_waiters: vector of shared_ptr
//       |     |      \     /     |    |
//       |     |       \   /      |    |
//       |     |         |        |    |
//      ( )   ( )       ( )      ( )  ( )                waiter's instance
//
//  clang-format on
//
struct BlkTrackRecord {
    BlkId m_key; // aligned key
    int64_t m_ref_cnt{0};
    folly::small_vector< blk_track_waiter_ptr, 8 > m_waiters; // multiple waiters can wait on same record
};

class BlkReadTrackerMetrics : public sisl::MetricsGroup {
public:
    explicit BlkReadTrackerMetrics() : sisl::MetricsGroupWrapper("BlkReadTracker", "DataSvc") {
#ifdef _PRERELEASE
        REGISTER_COUNTER(blktrack_pending_blk_read_map_sz, "Size of pending blk read map", sisl::_publish_as::publish_as_gauge);
        REGISTER_COUNTER(blktrack_erase_blk_rescheduled, "Erase blk rescheduled due to concurrent rw");
        REGISTER_HISTOGRAM(blktrack_erase_blk_rescheduled_latency, "Erase blk rescheduled latency");
#endif
        register_me_to_farm();
    }

    BlkReadTrackerMetrics(const BlkReadTrackerMetrics&) = delete;
    BlkReadTrackerMetrics& operator=(const BlkReadTrackerMetrics&) = delete;
    BlkReadTrackerMetrics(BlkReadTrackerMetrics&&) noexcept = delete;
    BlkReadTrackerMetrics& operator=(BlkReadTrackerMetrics&&) noexcept = delete;

    ~BlkReadTrackerMetrics() { deregister_me_from_farm(); }
};

class BlkReadTracker {
    static constexpr uint32_t s_expected_num_records = 1000;
    static constexpr uint16_t s_entries_per_record = 8; // this number could be candidate to tune perf;

private:
    sisl::SimpleHashMap< BlkId, BlkTrackRecord > m_pending_reads_map;
    BlkReadTrackerMetrics m_metrics;
    uint32_t m_entries_per_record{s_entries_per_record};

public:
    BlkReadTracker();
    ~BlkReadTracker();

    BlkReadTracker(const BlkReadTracker&) = delete;
    BlkReadTracker& operator=(const BlkReadTracker&) = delete;
    BlkReadTracker(BlkReadTracker&&) noexcept = delete;
    BlkReadTracker& operator=(BlkReadTracker&&) noexcept = delete;

    uint16_t entries_per_record() const;
    void set_entries_per_record(uint16_t num_entries);

    /**
     * @brief :  Insert the blkid into read tracker. If entry already exists, it will increment the reference count of
     * the blkid It symbolises that this blkid is being read right now.
     *
     * @param blkid : the blkid that is being added for reference;
     */
    void insert(const BlkId& blkid);

    /**
     * @brief : decrease the reference count of the BlkId by 1 in this read tracker.
     * If the ref count drops to zero, it means no read is pending on this blkid and if there is a waiter on this blkid,
     * callback should be trigggered and all entries associated with this blkid (there could be more than one
     * sub_ranges) should be removed.
     *
     * @param blkid : blkid that is being dereferneced;
     */
    void remove(const BlkId& blkid);

    /**
     * @brief : Check if the reference count of the blkid is 0 or entry itself doesn't exists.
     * It will do the callback if the ref count is zero or the blkid entry doesn't exsit;
     *
     * @param blkid : blkid that caller wants to wait on for pending read;
     * @param after_remove_cb : the callback to be sent after read on this blkid are all completed;
     */
    void wait_on(const BlkId& blkid, after_remove_cb_t&& after_remove_cb);

    /**
     * @brief : get size of the pending map;
     *
     * @return : size of the pending map;
     */
    // uint64_t get_size() const { return m_pending_reads_map.get_size(); }

private:
    /**
     * @brief
     *
     * @param blkid
     * @param new_ref_count
     * @param waiters
     */
    void merge(const BlkId& blkid, int64_t new_ref_count, const std::shared_ptr< blk_track_waiter >& waiters);
};
} // namespace homestore
