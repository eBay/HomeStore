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
#include <homestore/chunk_selector.h>

#include "device/chunk.h"
#include "device/virtual_dev.hpp"
#include "device/physical_dev.hpp"     // vdev_info_block
#include "common/homestore_config.hpp" // is_data_drive_hdd
#include "common/homestore_assert.hpp"
#include "common/error.h"
#include "blk_read_tracker.hpp"
#include "data_svc_cp.hpp"

namespace homestore {

BlkDataService& data_service() { return hs()->data_service(); }

BlkDataService::BlkDataService(shared< ChunkSelector > chunk_selector) :
        m_custom_chunk_selector{std::move(chunk_selector)} {
    m_blk_read_tracker = std::make_unique< BlkReadTracker >();
}
BlkDataService::~BlkDataService() = default;

// first-time boot path
void BlkDataService::create_vdev(uint64_t size, uint32_t blk_size, blk_allocator_type_t alloc_type,
                                 chunk_selector_type_t chunk_sel_type, uint32_t num_chunks) {
    hs_vdev_context vdev_ctx;
    vdev_ctx.type = hs_vdev_type_t::DATA_VDEV;

    if (blk_size == 0) { blk_size = hs()->device_mgr()->optimal_page_size(HSDevType::Data); }
    m_vdev =
        hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = "blkdata",
                                                        .vdev_size = size,
                                                        .num_chunks = num_chunks,
                                                        .blk_size = blk_size,
                                                        .dev_type = HSDevType::Data,
                                                        .alloc_type = alloc_type,
                                                        .chunk_sel_type = chunk_sel_type,
                                                        .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                        .context_data = vdev_ctx.to_blob()});
}

// both first_time_boot and recovery path will come here
shared< VirtualDev > BlkDataService::open_vdev(const vdev_info& vinfo, bool load_existing) {
    m_vdev = std::make_shared< VirtualDev >(*(hs()->device_mgr()), vinfo, nullptr, true /* auto_recovery */,
                                            std::move(m_custom_chunk_selector));
    m_blk_size = vinfo.blk_size;
    return m_vdev;
}

static auto collect_all_futures(std::vector< folly::Future< std::error_code > >& futs) {
    return folly::collectAllUnsafe(futs).thenValue([](auto&& vf) {
        for (auto const& err_c : vf) {
            if (sisl_unlikely(err_c.value())) {
                auto ec = err_c.value();
                return folly::makeFuture< std::error_code >(std::move(ec));
            }
        }
        return folly::makeFuture< std::error_code >(std::error_code{});
    });
}

folly::Future< std::error_code > BlkDataService::async_read(MultiBlkId const& blkid, uint8_t* buf, uint32_t size,
                                                            bool part_of_batch) {
    auto do_read = [this](BlkId const& bid, uint8_t* buf, uint32_t size, bool part_of_batch) {
        m_blk_read_tracker->insert(bid);

        return m_vdev->async_read(r_cast< char* >(buf), size, bid, part_of_batch).thenValue([this, bid](auto&& ec) {
            m_blk_read_tracker->remove(bid);
            return folly::makeFuture< std::error_code >(std::move(ec));
        });
    };

    if (blkid.num_pieces() == 1) {
        return do_read(blkid.to_single_blkid(), buf, size, part_of_batch);
    } else {
        static thread_local std::vector< folly::Future< std::error_code > > s_futs;
        s_futs.clear();

        auto it = blkid.iterate();
        while (auto const bid = it.next()) {
            uint32_t sz = bid->blk_count() * m_blk_size;
            s_futs.emplace_back(do_read(*bid, buf, sz, part_of_batch));
            buf += sz;
        }

        return collect_all_futures(s_futs);
    }
}

folly::Future< std::error_code > BlkDataService::async_read(MultiBlkId const& blkid, sisl::sg_list& sgs, uint32_t size,
                                                            bool part_of_batch) {
    // TODO: sg_iovs_t should not be passed by value. We need it pass it as const&, but that is failing because
    // iovs.data() will then return "const iovec*", but unfortunately all the way down to iomgr, we take iovec*
    // instead it can easily take "const iovec*". Until we change this is made as copy by value
    auto do_read = [this](BlkId const& bid, sisl::sg_iovs_t iovs, uint32_t size, bool part_of_batch) {
        m_blk_read_tracker->insert(bid);

        return m_vdev->async_readv(iovs.data(), iovs.size(), size, bid, part_of_batch)
            .thenValue([this, bid](auto&& ec) {
                m_blk_read_tracker->remove(bid);
                return folly::makeFuture< std::error_code >(std::move(ec));
            });
    };

    if (blkid.num_pieces() == 1) {
        return do_read(blkid.to_single_blkid(), sgs.iovs, size, part_of_batch);
    } else {
        static thread_local std::vector< folly::Future< std::error_code > > s_futs;
        s_futs.clear();

        sisl::sg_iterator sg_it{sgs.iovs};
        auto blkid_it = blkid.iterate();
        while (auto const bid = blkid_it.next()) {
            uint32_t const sz = bid->blk_count() * m_blk_size;
            s_futs.emplace_back(do_read(*bid, sg_it.next_iovs(sz), sz, part_of_batch));
        }

        return collect_all_futures(s_futs);
    }
}

folly::Future< std::error_code > BlkDataService::async_alloc_write(const sisl::sg_list& sgs,
                                                                   const blk_alloc_hints& hints, MultiBlkId& out_blkids,
                                                                   bool part_of_batch) {
    const auto status = alloc_blks(sgs.size, hints, out_blkids);
    if (status != BlkAllocStatus::SUCCESS) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    return async_write(sgs, out_blkids, part_of_batch);
}

folly::Future< std::error_code > BlkDataService::async_write(const char* buf, uint32_t size, MultiBlkId const& blkid,
                                                             bool part_of_batch) {
    if (blkid.num_pieces() == 1) {
        // Shortcut to most common case
        return m_vdev->async_write(buf, size, blkid.to_single_blkid(), part_of_batch);
    } else {
        static thread_local std::vector< folly::Future< std::error_code > > s_futs;
        s_futs.clear();

        const char* ptr = buf;
        auto blkid_it = blkid.iterate();
        while (auto const bid = blkid_it.next()) {
            uint32_t sz = bid->blk_count() * m_blk_size;
            s_futs.emplace_back(m_vdev->async_write(ptr, sz, *bid, part_of_batch));
            ptr += sz;
        }
        return collect_all_futures(s_futs);
    }
}

folly::Future< std::error_code > BlkDataService::async_write(sisl::sg_list const& sgs, MultiBlkId const& blkid,
                                                             bool part_of_batch) {
    // TODO: Async write should pass this by value the sgs.size parameter as well, currently vdev write routine
    // walks through again all the iovs and then getting the len to pass it down to iomgr. This defeats the purpose of
    // taking size parameters (which was done exactly done to avoid this walk through)
    if (blkid.num_pieces() == 1) {
        // Shortcut to most common case
        return m_vdev->async_writev(sgs.iovs.data(), sgs.iovs.size(), blkid.to_single_blkid(), part_of_batch);
    } else {
        static thread_local std::vector< folly::Future< std::error_code > > s_futs;
        s_futs.clear();
        sisl::sg_iterator sg_it{sgs.iovs};

        auto blkid_it = blkid.iterate();
        while (auto const bid = blkid_it.next()) {
            const auto iovs = sg_it.next_iovs(bid->blk_count() * m_blk_size);
            s_futs.emplace_back(m_vdev->async_writev(iovs.data(), iovs.size(), *bid, part_of_batch));
        }
        return collect_all_futures(s_futs);
    }
}

BlkAllocStatus BlkDataService::alloc_blks(uint32_t size, const blk_alloc_hints& hints, MultiBlkId& out_blkids) {
    HS_DBG_ASSERT_EQ(size % m_blk_size, 0, "Non aligned size requested");
    blk_count_t nblks = static_cast< blk_count_t >(size / m_blk_size);

    return m_vdev->alloc_blks(nblks, hints, out_blkids);
}

void BlkDataService::commit_blk(MultiBlkId const& blkid) {
    if (blkid.num_pieces() == 1) {
        // Shortcut to most common case
        m_vdev->commit_blk(blkid);
    } else {
        auto it = blkid.iterate();
        while (auto const bid = it.next()) {
            m_vdev->commit_blk(*bid);
        }
    }
}

folly::Future< std::error_code > BlkDataService::async_free_blk(MultiBlkId const& bids) {
    // create blk read waiter instance;
    folly::Promise< std::error_code > promise;
    auto f = promise.getFuture();

    m_blk_read_tracker->wait_on(bids, [this, bids, p = std::move(promise)]() mutable {
        m_vdev->free_blk(bids);
        p.setValue(std::error_code{});
    });
    return f;
}

void BlkDataService::start() {
    // Register to CP for flush dirty buffers underlying virtual device layer;
    hs()->cp_mgr().register_consumer(cp_consumer_t::BLK_DATA_SVC,
                                     std::move(std::make_unique< DataSvcCPCallbacks >(m_vdev)));
}

uint64_t BlkDataService::get_total_capacity() const { return m_vdev->size(); }

uint64_t BlkDataService::get_used_capacity() const { return m_vdev->used_size(); }

} // namespace homestore
