/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal, Amit Desai
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

namespace homestore {
static BlkId extract_key(const BlkTrackRecord& rec) { return rec.m_key; }

static bool blkid_overlaps(const BlkId& a, const BlkId& b) {
    if (a.get_chunk_num() != b.get_blk_num()) { return false; }
    if (a.get_blk_num() == b.get_blk_num()) { return true; }
    if (a.get_blk_num < b.get_blk_num()) { return ((a.get_blk_num() + a.get_nblks()) >= b.get_blk_num()); }
    return ((b.get_blk_num() + b.get_nblks()) >= a.get_blk_num());
}

static bool merge_records(BlkTrackRecord& rec, const BlkTrackRecord& other) {
    assert(rec.m_key == other.m_key);
    assert(other.m_sub_record.size() == 1); // We don't support multiple elements to merge with each other

    const auto& new_rec = other.m_sub_record[0];
    rec.m_total_refcount += other.m_total_refcount;

    bool inserted{false};
    auto it = rec.m_sub_record.begin();
    while (it != rec.m_sub_record.end()) {
        if (blkid_overlaps(it->sub_range, new_rec.sub_range)) {
            it->ref_count += new_rec.ref_count;
            if (it->ref_count == 0) { // No one references, removed from list
                it = rec.m_sub_record.erase(it);
            } else {
                it->waiter = new_rec.waiter;
                inserted = true;
            }
        }
        ++it;
    }

    if (!inserted) { rec.m_sub_record.push_back(new_rec); }
    return (rec.m_total_refcount == 0);
}

BlkReadTracker::BlkReadTracker() : m_pending_reads_map(expected_num_records, extract_key, nullptr, merge_records) {}

void BlkReadTracker::merge(const BlkId& blkid, int64_t new_ref_count,
                           const std::shared_ptr< blk_track_waiter >& waiters) {
    auto cur_blk_num = blkid.get_blk_num();
    auto max_this_entry = entries_per_record - (cur_blk_num - sisl::round_down(cur_blk_num, entries_per_record));

    while (cur_blk_num <= blkid.get_last_blk_num()) {
        const auto count = std::min(max_this_entry, (blkid.get_last_blk_num() - cur_blk_num + 1));

        BlkId base_blkid{sisl::round_down(cur_blk_num, entries_per_record), entries_per_record, blkid.get_chunk_num()};
        BlkId sub_blkid{cur_blk_num, count, blkid.get_chunk_num()};

        BlkTrackRecord rec;
        rec.m_key = base_blkid;
        rec.m_total_refcount = new_ref_count;
        rec.m_sub_record.emplace_back(sub_blkid, new_ref_count, waiters);

        m_pending_reads_map.merge(base_blkid, rec);

        cur_blk_num += count;
        max_this_entry = entries_per_record;
    }
}

void BlkReadTracker::insert(const BlkId& blkid) { merge(blkid, 1, nullptr); }

void BlkReadTracker::remove(const BlkId& blkid) { merge(blkid, -1, nullptr); }

void BlkReadTracker::ensure_no_record(const BlkId& blkid, after_remove_cb_t&& after_remove_cb) {
    merge(blkid, 0, std::make_shared< blk_track_waiter >(std::move(after_remove_cb)));
}
} // namespace homestore