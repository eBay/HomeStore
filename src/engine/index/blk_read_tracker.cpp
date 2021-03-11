//
// Created by Amit Desai on 07/15/19.
//

#include <chrono>
#include <cstdint>
#include <thread>

#include <sds_logging/logging.h>

#include "engine/common/homestore_flip.hpp"

#include "blk_read_tracker.hpp"
#include "indx_mgr.hpp"

SDS_LOGGING_DECL(indx_mgr)

namespace homestore {

void Blk_Read_Tracker::insert(Free_Blk_Entry& fbe) {
    const uint64_t hash_code{static_cast<uint64_t>(std::hash< BlkId >()(fbe.m_blkId))};
    BlkEvictionRecord* ber = BlkEvictionRecord::make_object(fbe.m_blkId);
    BlkEvictionRecord* outber = nullptr;
    // insert into pending read map and set ref of value to 2(one for hashmap and one for client)
    // If value already present , insert() will just increase ref count of value by 1.
    bool inserted = m_pending_reads_map.insert(fbe.m_blkId, *ber, &outber, hash_code, NULL_LAMBDA);
    if (inserted) {
        COUNTER_INCREMENT(m_metrics, blktrack_pending_blk_read_map_sz, 1);
    } else { // record exists already, some other read happened
        sisl::ObjectAllocator< BlkEvictionRecord >::deallocate(ber);
    }
    //    THIS_VOL_LOG(TRACE, indx_mgr, , "Marked read pending Bid:{},{}", fbe.m_blkId, inserted);
}

void Blk_Read_Tracker::remove(Free_Blk_Entry& fbe) {
    const uint64_t hash_code{static_cast< uint64_t >(std::hash< BlkId >()(fbe.m_blkId))};

#ifdef _PRERELEASE
    if (auto flip_ret = homestore_flip->get_test_flip< int >("vol_delay_read_us"))
    {
        std::this_thread::sleep_for(std::chrono::microseconds{flip_ret.get()});
    }
#endif
    bool is_removed = m_pending_reads_map.check_and_remove(
        fbe.m_blkId, hash_code,
        [this](BlkEvictionRecord* ber) {
            // no more ref left
            if (ber->can_free()) {
                for (auto& fbe : *ber->get_free_list()) {
                    m_remove_cb(fbe);
                }
            }
        },
        true /* dec additional ref corresponding to insert by pending_read_blk_cb*/);
    if (is_removed) { COUNTER_DECREMENT(m_metrics, blktrack_pending_blk_read_map_sz, 1); }
    //    THIS_VOL_LOG(TRACE, indx_mgr, , "UnMarked Read pending Bid:{},status:{}", fbe.blk_id(), is_removed);
}

void Blk_Read_Tracker::safe_free_blks(Free_Blk_Entry& fbe) {
    BlkId bid{fbe.m_blkId};
    const uint64_t hash_code{static_cast< uint64_t >(std::hash< BlkId >()(bid))};
    BlkEvictionRecord* outber = nullptr;
    bool found = m_pending_reads_map.get(bid, &outber, hash_code); // get increases ref if found
    if (!found) {                                                  // no read pending
        m_remove_cb(fbe);
    } else if (found) {                // there is read pending
        outber->add_to_free_list(fbe); // thread safe addition
        outber->set_free_state();      // mark for removal

        // check_and_remove - If ref count becomes 1, it will be removed as only hashmap is holding the ref.
        bool is_removed = m_pending_reads_map.check_and_remove(
            bid, hash_code,
            [this](BlkEvictionRecord* ber) {
                // no more ref left
                for (auto& fbe : *ber->get_free_list()) {
                    m_remove_cb(fbe);
                }
            },
            true /* dec additional ref corresponding to get above*/);
        if (is_removed) {
            COUNTER_DECREMENT(m_metrics, blktrack_pending_blk_read_map_sz, 1);
        } else {
            COUNTER_INCREMENT(m_metrics, blktrack_erase_blk_rescheduled, 1);
        }
        //       THIS_VOL_LOG(TRACE, indx_mgr, , "Marked erase write Bid:{},offset:{},nlbas:{},status:{}", bid,
        //       fbe.blk_offset(),
        //                  fbe.blks_to_free(), is_removed);
    }
}
} // namespace homestore
