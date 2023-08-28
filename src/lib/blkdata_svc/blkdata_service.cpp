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
#include "device/physical_dev.hpp" // vdev_info_block
#include "device/chunk.h"
#include "common/homestore_config.hpp" // is_data_drive_hdd
#include "common/homestore_assert.hpp"
#include "common/error.h"
#include "blk_read_tracker.hpp"

namespace homestore {

BlkDataService& data_service() { return hs()->data_service(); }

BlkDataService::BlkDataService() { m_blk_read_tracker = std::make_unique< BlkReadTracker >(); }
BlkDataService::~BlkDataService() = default;

// first-time boot path
void BlkDataService::create_vdev(uint64_t size, blk_allocator_type_t) {
    const auto phys_page_size = hs()->device_mgr()->optimal_page_size(HSDevType::Fast);

    hs_vdev_context vdev_ctx;
    vdev_ctx.type = hs_vdev_type_t::DATA_VDEV;

    m_vdev =
        hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = "blkdata",
                                                        .vdev_size = size,
                                                        .num_chunks = 1,
                                                        .blk_size = phys_page_size,
                                                        .dev_type = HSDevType::Data,
                                                        .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                        .context_data = vdev_ctx.to_blob()});
}

// both first_time_boot and recovery path will come here
shared< VirtualDev > BlkDataService::open_vdev(const vdev_info& vinfo, bool load_existing) {
    auto chunk_sel_type{chunk_selector_type_t::round_robin};

    if (vinfo.alloc_type == blk_allocator_type_t::append) {
        // TODO: enalbe it after chunksel is ready;
        // chunk_sel_type = chunk_selector_type_t::heap;
        chunk_sel_type = chunk_selector_type_t::ROUND_ROBIN;
    }

    m_vdev = std::make_shared< VirtualDev >(*(hs()->device_mgr()), vinfo, vinfo.alloc_type, chunk_sel_type, nullptr,
                                            true /* auto_recovery */);
    m_page_size = vinfo.blk_size;
    return m_vdev;
}

folly::Future< bool > BlkDataService::async_read(const BlkId& bid, sisl::sg_list& sgs, uint32_t size,
                                                 bool part_of_batch) {
    m_blk_read_tracker->insert(bid);
    HS_DBG_ASSERT_EQ(sgs.iovs.size(), 1, "Expecting iov size to be 1 since reading on one blk.");

    return m_vdev->async_readv(sgs.iovs.data(), sgs.iovs.size(), size, bid, part_of_batch)
        .thenValue([this, bid](auto&&) {
            m_blk_read_tracker->remove(bid);
            return folly::makeFuture< bool >(true);
        });
}

folly::Future< bool > BlkDataService::async_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                                                  const std::vector< BlkId >& blkids, bool part_of_batch) {
    if (blkids.size() == 1) {
        // Shortcut to most common case
        return m_vdev->async_writev(sgs.iovs.data(), sgs.iovs.size(), blkids[0], part_of_batch);
    } else {
        static thread_local std::vector< folly::Future< bool > > s_futs;
        s_futs.clear();
        sisl::sg_iterator sg_it{sgs.iovs};
        for (const auto& bid : blkids) {
            const auto iovs = sg_it.next_iovs(bid.get_nblks() * m_page_size);
            s_futs.emplace_back(m_vdev->async_writev(iovs.data(), iovs.size(), bid, part_of_batch));
        }
        return folly::collectAllUnsafe(s_futs).thenTry([](auto&&) { return folly::makeFuture< bool >(true); });
    }
}

folly::Future< bool > BlkDataService::async_alloc_write(const sisl::sg_list& sgs, const blk_alloc_hints& hints,
                                                        std::vector< BlkId >& out_blkids, bool part_of_batch) {
    out_blkids.clear();
    const auto status = alloc_blks(sgs.size, hints, out_blkids);
    if (status != BlkAllocStatus::SUCCESS) {
        return folly::makeFuture< bool >(
            std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again)));
    }
    return async_write(sgs, hints, out_blkids, part_of_batch);
}

BlkAllocStatus BlkDataService::alloc_blks(uint32_t size, const blk_alloc_hints& hints,
                                          std::vector< BlkId >& out_blkids) {
    HS_DBG_ASSERT_EQ(size % m_page_size, 0, "Non aligned size requested");
    blk_count_t nblks = static_cast< blk_count_t >(size / m_page_size);

    return m_vdev->alloc_blk(nblks, hints, out_blkids);
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

folly::Future< bool > BlkDataService::async_free_blk(const BlkId bid) {
    // create blk read waiter instance;
    folly::Promise< bool > promise;
    auto f = promise.getFuture();

    m_blk_read_tracker->wait_on(bid, [this, bid, p = std::move(promise)]() mutable {
        m_vdev->free_blk(bid);
        p.setValue(true);
    });
    return f;
}

void BlkDataService::start() {
    // Register to CP for flush dirty buffers underlying virtual device layer;
    hs()->cp_mgr().register_consumer(cp_consumer_t::BLK_DATA_SVC,
                                     std::move(std::make_unique< VDevCPCallbacks >(m_vdev)));
}

} // namespace homestore
