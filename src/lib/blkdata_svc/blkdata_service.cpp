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
#include <homestore/blkdata_service.hpp>
#include <homestore/homestore.hpp>
#include "device/virtual_dev.hpp"
#include "device/physical_dev.hpp"     // vdev_info_block
#include "common/homestore_config.hpp" // is_data_drive_hdd
#include "common/error.h"
#include "blk_read_tracker.hpp"

namespace homestore {

BlkDataService::BlkDataService() { m_blk_read_tracker = std::make_unique< BlkReadTracker >(); }
BlkDataService::~BlkDataService() {}

// recovery path
void BlkDataService::open_vdev(vdev_info_block* vb) {
    m_vdev = std::make_unique< VirtualDev >(hs()->device_mgr(), "DataVDev", vb, PhysicalDevGroup::DATA,
                                            blk_allocator_type_t::varsize, vb->is_failed(), true /* auto_recovery */);

    m_page_size = vb->blk_size;

    if (vb->is_failed()) {
        LOGINFO("Data vdev is in failed state");
        throw std::runtime_error("data vdev in failed state");
    }
}

void BlkDataService::async_free_blk(const BlkId bid, const io_completion_cb_t& cb) {
    // create blk read waiter instance;
    m_blk_read_tracker->wait_on(bid, [this, bid, cb]() {
        m_vdev->free_blk(bid);
        cb(no_error);
    });
}

// first-time boot path
void BlkDataService::create_vdev(uint64_t size) {
    struct blkstore_blob blob;
    blob.type = blkstore_type::DATA_STORE;
    m_page_size = hs()->device_mgr()->phys_page_size({PhysicalDevGroup::DATA});
    m_vdev = std::make_unique< VirtualDev >(hs()->device_mgr(), "DataVDev", PhysicalDevGroup::DATA,
                                            blk_allocator_type_t::varsize, size, 0, true /* is_stripe */, m_page_size,
                                            (char*)&blob, sizeof(blkstore_blob), true /* auto_recovery */);
}

void BlkDataService::async_read(const BlkId& bid, sisl::sg_list& sgs, uint32_t size, const io_completion_cb_t& cb,
                                bool part_of_batch) {

    m_blk_read_tracker->insert(bid);

    auto as_info = sisl::ObjectAllocator< async_info >::make_object();
    as_info->cb = cb;
    as_info->is_read = true;
    as_info->bid = bid;

    HS_DBG_ASSERT_EQ(sgs.iovs.size(), 1, "Expecting iov size to be 1 since reading on one blk.");

    as_info->outstanding_io_cnt.increment(1);

    m_vdev->async_readv(sgs.iovs.data(), sgs.iovs.size(), size, bid, BlkDataService::process_data_completion,
                        reinterpret_cast< const void* >(as_info) /* cookie */, part_of_batch);
}

void BlkDataService::process_data_completion(std::error_condition ec, void* cookie) {
    auto as_info = reinterpret_cast< async_info* >(cookie);

    if (as_info->outstanding_io_cnt.decrement_testz(1)) {

        if (as_info->is_read) {
            // this will trigger any pending free_blk on this read to complete;
            hs()->data_service().read_blk_tracker()->remove(as_info->bid);
        }

        // send callback to caller;
        as_info->cb(ec);
        sisl::ObjectAllocator< async_info >::deallocate(as_info);
    }
}

void BlkDataService::async_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                                 std::vector< BlkId >& out_blkids, const io_completion_cb_t& cb, bool part_of_batch) {
    out_blkids.clear();
    const auto status = alloc_blks(sgs.size, hints, out_blkids);
    if (status != BlkAllocStatus::SUCCESS) {
        cb(std::make_error_condition(std::errc::resource_unavailable_try_again));
        return;
    }

    auto as_info = sisl::ObjectAllocator< async_info >::make_object();
    as_info->cb = cb;

    if (out_blkids.size() == 1) {
        // Shortcut to most common case
        as_info->outstanding_io_cnt.increment(1);
        m_vdev->async_writev(sgs.iovs.data(), sgs.iovs.size(), out_blkids[0], BlkDataService::process_data_completion,
                             reinterpret_cast< const void* >(as_info) /* cookie */, part_of_batch);
    } else {
        sisl::sg_iterator sg_it{sgs.iovs};
        for (const auto& bid : out_blkids) {
            const auto iovs = sg_it.next_iovs(bid.get_nblks() * m_page_size);
            as_info->outstanding_io_cnt.increment(1);
            m_vdev->async_writev(iovs.data(), iovs.size(), bid, BlkDataService::process_data_completion,
                                 reinterpret_cast< const void* >(as_info) /* cookie */, part_of_batch);
        }
    }
}

BlkAllocStatus BlkDataService::alloc_blks(uint32_t size, const blk_alloc_hints& hints,
                                          std::vector< BlkId >& out_blkids) {
    HS_DBG_ASSERT_EQ(size % m_page_size, 0, "Non aligned size requested");
    blk_count_t nblks = static_cast< blk_count_t >(size / m_page_size);

    return m_vdev->alloc_blk(nblks, hints, out_blkids);

#if 0 // already done by vdev layer
        if (nblks <= BlkId::max_blks_in_op()) {
        return (m_vdev.alloc_blk(nblks, hints, out_blkid));
    }
    else {
        while (nblks != 0) {
            static thread_local std::vector< BlkId > result_blkid{};
            result_blkid.clear();

            const blk_count_t nblks_op = std::min(static_cast< blk_count_t >(BlkId::max_blks_in_op()), nblks);
            const auto ret = m_vdev.alloc_blk(nblks_op, hints, result_blkid);
            if (ret != BlkAllocStatus::SUCCESS) { return ret; }

            out_blkid.insert(std::end(out_blkid), std::make_move_iterator(std::begin(result_blkid)),
                             std::make_move_iterator(std::end(result_blkid)));
            nblks -= nblks_op;
        }
        return BlkAllocStatus::SUCCESS;
    }
#endif
}

void BlkDataService::commit_blk(const BlkId& bid) { m_vdev->commit_blk(bid); }

blk_list_t BlkDataService::alloc_blks(uint32_t size) {
    blk_alloc_hints hints; // default hints
    std::vector< BlkId > out_blkids;
    const auto status = alloc_blks(size, hints, out_blkids);

    blk_list_t blk_list;
    if (status != BlkAllocStatus::SUCCESS) {
        LOGERROR("Resouce unavailable!");
        return blk_list;
    }

    // convert BlkId to blklist;
    for (auto i = 0ul; i < out_blkids.size(); ++i) {
        blk_list.emplace_back(out_blkids[i].to_integer());
    }

    return blk_list;
}

stream_info_t BlkDataService::alloc_stream(const uint64_t size) { return m_vdev->alloc_stream(size); }

stream_info_t BlkDataService::reserve_stream(const stream_id_t* id_list, const uint32_t num_streams) {
    return m_vdev->reserve_stream(id_list, num_streams);
}

void BlkDataService::free_stream(const stream_info_t& stream_info) { m_vdev->free_stream(stream_info); }

} // namespace homestore
