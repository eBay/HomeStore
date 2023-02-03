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

BlkReadTracker::~BlkReadTracker() {}

// BlkReadTrackerMetrics& BlkReadTracker::get_metrics() { return m_metrics; }

void BlkReadTracker::merge(const BlkId& blkid, int64_t new_ref_count,
                           const std::shared_ptr< blk_track_waiter >& waiter) {
    HS_DBG_ASSERT(new_ref_count ? waiter == nullptr : waiter != nullptr, "Invalid waiter");

    //
    // Don't move alignment handling outside of this function, because the nblks between (first and last blk num after
    // alignment) could be larger than 255 which exceeds a BlkId can hold;
    //
    auto cur_blk_num_aligned = s_cast< blk_num_t >(sisl::round_down(blkid.get_blk_num(), entries_per_record()));
    auto last_blk_num_aligned_up = s_cast< blk_num_t >(sisl::round_up(blkid.get_last_blk_num(), entries_per_record()) -
                                                       1); //  -1 so that it does not cover next base id;
    if (blkid.get_last_blk_num() % entries_per_record() == 0) {
        // if last blk num happens to be aligned, it actually belongs to next base id, so add 1 back;
        last_blk_num_aligned_up += 1;
    }

    [[maybe_unused]] bool waiter_rescheduled { false };
    // everything is aligned after this point, so we don't need to handle sub_range in a base blkid;
    while (cur_blk_num_aligned <= last_blk_num_aligned_up) {
        BlkId base_blkid{cur_blk_num_aligned, entries_per_record(), blkid.get_chunk_num()};

        BlkTrackRecord rec;
        const auto rec_found = m_pending_reads_map.get(base_blkid, rec);

        if (new_ref_count != 0) {
            // this is insert/remove operations
            if (rec_found) {
                // if some read is already happening on this record, just update the ref_cnt;
                rec.m_ref_cnt += new_ref_count;
            } else {
                // if no record found, no read is happening on this record;
                rec.m_key = base_blkid;
                rec.m_ref_cnt = new_ref_count;
            }

            // in either case, ref_cnt can not drop below zero;
            HS_DBG_ASSERT_GE(rec.m_ref_cnt, 0);

            if (rec.m_ref_cnt > 0) {
                m_pending_reads_map.upsert(base_blkid, rec);
            } else {
                // ref_cnt drops to zero, clear all the references held by this record;
                HS_DBG_ASSERT_EQ(rec_found, true);
                rec.m_waiters.clear();
                BlkTrackRecord dummy_rec;
                m_pending_reads_map.erase(base_blkid, dummy_rec);
            }
        } else {
            // this is wait_on operation
            if (rec_found) {
                // apply waiter to this record;
                rec.m_waiters.push_back(waiter);
                // overwirte existing record;
                m_pending_reads_map.upsert(base_blkid, rec);
                waiter_rescheduled = true;
            }

            // not found, nothing needs to be done; fall through and visit remaining records;
        }

        cur_blk_num_aligned += entries_per_record();
    }

#ifdef _PRERELEASE
    if (waiter_rescheduled) { COUNTER_INCREMENT(m_metrics, blktrack_erase_blk_rescheduled, 1); }
#endif

    // if no record is found for a wait-on operation, it means no one is holding reference for this waiter and cb will
    // be called automatically when this function exits (waiter's destrctor will be called);
}

void BlkReadTracker::insert(const BlkId& blkid) { merge(blkid, 1, nullptr); }
void BlkReadTracker::remove(const BlkId& blkid) { merge(blkid, -1, nullptr); }

void BlkReadTracker::wait_on(const BlkId& blkid, after_remove_cb_t&& after_remove_cb) {
    merge(blkid, 0, std::make_shared< blk_track_waiter >(std::move(after_remove_cb)));
}

uint16_t BlkReadTracker::entries_per_record() const {
    // TODO: read from config;
    return m_entries_per_record;
}

void BlkReadTracker::set_entries_per_record(uint16_t num_entries) { m_entries_per_record = num_entries; }

} // namespace homestore
