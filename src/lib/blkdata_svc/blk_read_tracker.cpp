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
#include "blk_read_tracker.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {
static BlkId extract_key(const BlkTrackRecord& rec) { return rec.m_key; }

BlkReadTracker::BlkReadTracker() : m_pending_reads_map(s_expected_num_records, extract_key, nullptr /* access_cb */) {}

BlkReadTracker::~BlkReadTracker() = default;

// BlkReadTrackerMetrics& BlkReadTracker::get_metrics() { return m_metrics; }

void BlkReadTracker::merge(const BlkId& blkid, int64_t new_ref_count,
                           const std::shared_ptr< blk_track_waiter >& waiter) {
    HS_DBG_ASSERT(new_ref_count ? waiter == nullptr : waiter != nullptr, "Invalid waiter");

    auto cur_base_blk_num = s_cast< blk_num_t >(sisl::round_down(blkid.blk_num(), entries_per_record()));
    auto last_base_blk_num =
        s_cast< blk_num_t >(sisl::round_down(blkid.blk_num() + blkid.blk_count() - 1, entries_per_record()));

    [[maybe_unused]] bool waiter_rescheduled{false};
    // everything is aligned after this point, so we don't need to handle sub_range in a base blkid;
    while (cur_base_blk_num <= last_base_blk_num) {
        BlkId base_blkid{cur_base_blk_num, entries_per_record(), blkid.chunk_num()};

        if (new_ref_count > 0) {
            // This is an insert operation
            m_pending_reads_map.upsert_or_delete(base_blkid,
                                                 [&base_blkid, new_ref_count](BlkTrackRecord& rec, bool existing) {
                                                     if (!existing) { rec.m_key = base_blkid; }
                                                     rec.m_ref_cnt += new_ref_count;
                                                     return false;
                                                 });
        } else if (new_ref_count < 0) {
            // This is a remove operation
            m_pending_reads_map.upsert_or_delete(base_blkid, [new_ref_count](BlkTrackRecord& rec, bool existing) {
                HS_DBG_ASSERT_EQ(existing, true, "Decrement a ref count which does not exist in map");
                rec.m_ref_cnt += new_ref_count;
                return (rec.m_ref_cnt == 0);
            });
        } else {
            // this is wait_on operation
            m_pending_reads_map.update(base_blkid, [&waiter_rescheduled, &waiter](BlkTrackRecord& rec) {
                rec.m_waiters.push_back(waiter);
                waiter_rescheduled = true;
            });
        }
        cur_base_blk_num += entries_per_record();
    }

#ifdef _PRERELEASE
    if (waiter_rescheduled) { COUNTER_INCREMENT(m_metrics, blktrack_erase_blk_rescheduled, 1); }
#endif

    // if no record is found for a wait-on operation, it means no one is holding reference for this waiter and cb will
    // be called automatically when this function exits (waiter's destrctor will be called);
}

void BlkReadTracker::insert(const BlkId& blkid) { merge(blkid, 1, nullptr); }
void BlkReadTracker::remove(const BlkId& blkid) { merge(blkid, -1, nullptr); }

void BlkReadTracker::wait_on(MultiBlkId const& blkids, after_remove_cb_t&& after_remove_cb) {
    if (blkids.num_pieces() == 1) {
        merge(blkids, 0, std::make_shared< blk_track_waiter >(std::move(after_remove_cb)));
    } else {
        auto waiter = std::make_shared< blk_track_waiter >(std::move(after_remove_cb));
        auto it = blkids.iterate();
        while (auto const b = it.next()) {
            merge(*b, 0, waiter);
        }
    }
}

uint16_t BlkReadTracker::entries_per_record() const {
    // TODO: read from config;
    return m_entries_per_record;
}

void BlkReadTracker::set_entries_per_record(uint16_t num_entries) { m_entries_per_record = num_entries; }

} // namespace homestore
