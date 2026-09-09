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
#include <homestore/chunk_selector.hpp>

#include "device/chunk.h"
#include "device/virtual_dev.hpp"
#include "device/physical_dev.hpp"        // vdev_info_block
#include <sisl/async/when_all.hpp>        // sisl::async::when_all (collectAllUnsafe replacement)
#include <sisl/async/value_awaitable.hpp> // sisl::async::value_awaitable
#include "common/homestore_config.hpp"    // is_data_drive_hdd
#include "common/homestore_assert.hpp"
#include "common/error.h"
#include "blk_read_tracker.hpp"
#include "data_svc_cp.hpp"

namespace homestore {

blk_data_service& data_service() { return hs()->data_service(); }

blk_data_service::blk_data_service(shared< ChunkSelector > chunk_selector) :
        m_custom_chunk_selector{std::move(chunk_selector)} {
    m_blk_read_tracker = std::make_unique< BlkReadTracker >();
}

blk_data_service::~blk_data_service() = default;

// first-time boot path
void blk_data_service::create_vdev(uint64_t size, HSDevType devType, uint32_t blk_size, blk_allocator_type_t alloc_type,
                                   chunk_selector_type_t chunk_sel_type, uint32_t num_chunks, uint32_t chunk_size) {
    hs_vdev_context vdev_ctx;
    vdev_ctx.type = hs_vdev_type_t::DATA_VDEV;

    if (blk_size == 0) { blk_size = hs()->device_mgr()->optimal_page_size(devType); }
    m_vdev =
        hs()->device_mgr()->create_vdev(vdev_parameters{.vdev_name = "blkdata",
                                                        .vdev_size = size,
                                                        .num_chunks = num_chunks,
                                                        .blk_size = blk_size,
                                                        .chunk_size = chunk_size,
                                                        .dev_type = devType,
                                                        .alloc_type = alloc_type,
                                                        .chunk_sel_type = chunk_sel_type,
                                                        .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                        .context_data = vdev_ctx.to_blob()});
}

// both first_time_boot and recovery path will come here
shared< VirtualDev > blk_data_service::open_vdev(const vdev_info& vinfo, bool load_existing) {
    if (m_vdev) return m_vdev;
    m_vdev = std::make_shared< VirtualDev >(*(hs()->device_mgr()), vinfo, nullptr, true /* auto_recovery */,
                                            std::move(m_custom_chunk_selector));
    m_blk_size = vinfo.blk_size;
    return m_vdev;
}

// Run all the per-piece tasks concurrently; the first failing piece wins (mirrors collectAllUnsafe + scan).
// Takes the vector by value so the (move-only) tasks are owned here for the duration of the fan-out.
static sisl::async::task< iomgr::io_result > collect_all(std::vector< sisl::async::task< iomgr::io_result > > futs) {
    for (auto const& r : co_await sisl::async::when_all(std::move(futs))) {
        if (sisl_unlikely(!r)) { co_return r; }
    }
    co_return iomgr::io_result{0};
}

// One read piece, bracketed in the read tracker. `bid` is taken by value (copied into the coroutine frame) so it
// outlives the suspend at the device read -- a captured-by-reference coroutine lambda would dangle once the
// enclosing method returned the (lazy) task.
sisl::async::task< iomgr::io_result > blk_data_service::do_read_blk(blk_id bid, uint8_t* buf, uint32_t size,
                                                                    bool part_of_batch) {
    m_blk_read_tracker->insert(bid);
    auto const r = co_await m_vdev->async_read(r_cast< char* >(buf), size, bid, part_of_batch);
    m_blk_read_tracker->remove(bid);
    co_return r;
}

sisl::async::task< iomgr::io_result > blk_data_service::do_readv_blk(blk_id bid, sisl::sg_iovs_t iovs, uint32_t size,
                                                                     bool part_of_batch) {
    m_blk_read_tracker->insert(bid);
    auto const r = co_await m_vdev->async_readv(iovs.data(), iovs.size(), size, bid, part_of_batch);
    m_blk_read_tracker->remove(bid);
    co_return r;
}

sisl::async::task< iomgr::io_result > blk_data_service::async_read(multi_blk_id const& blkid, uint8_t* buf,
                                                                   uint32_t size, io_batch* batch) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    bool const part_of_batch = (batch != nullptr);
    if (blkid.num_pieces() == 1) {
        decr_pending_request_num();
        co_return co_await do_read_blk(blkid.to_single_blkid(), buf, size, part_of_batch);
    }

    std::vector< sisl::async::task< iomgr::io_result > > futs;
    auto it = blkid.iterate();
    while (auto const bid = it.next()) {
        uint32_t sz = bid->blk_count() * m_blk_size;
        futs.emplace_back(do_read_blk(*bid, buf, sz, part_of_batch));
        buf += sz;
    }
    decr_pending_request_num();
    co_return co_await collect_all(std::move(futs));
}

sisl::async::task< iomgr::io_result > blk_data_service::async_read(multi_blk_id const& blkid, sisl::sg_list& sgs,
                                                                   uint32_t size, io_batch* batch) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    bool const part_of_batch = (batch != nullptr);
    if (blkid.num_pieces() == 1) {
        decr_pending_request_num();
        co_return co_await do_readv_blk(blkid.to_single_blkid(), sgs.iovs, size, part_of_batch);
    }

    std::vector< sisl::async::task< iomgr::io_result > > futs;
    sisl::sg_iterator sg_it{sgs.iovs};
    auto blkid_it = blkid.iterate();
    while (auto const bid = blkid_it.next()) {
        uint32_t const sz = bid->blk_count() * m_blk_size;
        futs.emplace_back(do_readv_blk(*bid, sg_it.next_iovs(sz), sz, part_of_batch));
    }
    decr_pending_request_num();
    co_return co_await collect_all(std::move(futs));
}

sisl::async::task< iomgr::io_result > blk_data_service::async_alloc_write(const sisl::sg_list& sgs,
                                                                          const blk_alloc_hints& hints,
                                                                          multi_blk_id& out_blkids, io_batch* batch) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    auto blk_result = alloc_blks(sgs.size, hints);
    if (!blk_result) {
        decr_pending_request_num();
        co_return std::unexpected(blk_result.error());
    }
    out_blkids = std::move(blk_result.value());
    // Construct the write task before decr (matches the old decr-before-completion ordering); out_blkids/sgs stay
    // alive across the await since they are this coroutine's by-reference params.
    auto wtask = async_write(sgs, out_blkids, batch);
    decr_pending_request_num();
    co_return co_await std::move(wtask);
}

sisl::async::task< iomgr::io_result > blk_data_service::async_write(const char* buf, uint32_t size,
                                                                    multi_blk_id const& blkid, io_batch* batch) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    bool const part_of_batch = (batch != nullptr);
    if (blkid.num_pieces() == 1) {
        // Shortcut to most common case
        decr_pending_request_num();
        co_return co_await m_vdev->async_write(buf, size, blkid.to_single_blkid(), part_of_batch);
    }

    std::vector< sisl::async::task< iomgr::io_result > > futs;
    const char* ptr = buf;
    auto blkid_it = blkid.iterate();
    while (auto const bid = blkid_it.next()) {
        uint32_t sz = bid->blk_count() * m_blk_size;
        futs.emplace_back(m_vdev->async_write(ptr, sz, *bid, part_of_batch));
        ptr += sz;
    }
    decr_pending_request_num();
    co_return co_await collect_all(std::move(futs));
}

sisl::async::task< iomgr::io_result > blk_data_service::async_write(sisl::sg_list const& sgs, multi_blk_id const& blkid,
                                                                    io_batch* batch) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    bool const part_of_batch = (batch != nullptr);
    // TODO: Async write should pass this by value the sgs.size parameter as well, currently vdev write routine
    // walks through again all the iovs and then getting the len to pass it down to iomgr. This defeats the purpose of
    // taking size parameters (which was done exactly done to avoid this walk through)
    if (blkid.num_pieces() == 1) {
        // Shortcut to most common case
        decr_pending_request_num();
        co_return co_await m_vdev->async_writev(sgs.iovs.data(), sgs.iovs.size(), blkid.to_single_blkid(),
                                                part_of_batch);
    }

    std::vector< sisl::async::task< iomgr::io_result > > futs;
    sisl::sg_iterator sg_it{sgs.iovs};
    auto blkid_it = blkid.iterate();
    while (auto const bid = blkid_it.next()) {
        const auto iovs = sg_it.next_iovs(bid->blk_count() * m_blk_size);
        futs.emplace_back(m_vdev->async_writev(iovs.data(), iovs.size(), *bid, part_of_batch));
    }
    decr_pending_request_num();
    co_return co_await collect_all(std::move(futs));
}

sisl::async::task< iomgr::io_result >
blk_data_service::async_write(sisl::sg_list const& sgs, std::vector< multi_blk_id > const& blkids, io_batch* batch) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    // The per-piece sg_lists must outlive the (lazy) async_write tasks, which only read them when the fan-out
    // starts -- after this loop. Hold them in a frame-local vector (reserved so the by-reference tasks never see a
    // reallocation) that lives until the co_await below completes.
    std::vector< sisl::sg_list > piece_sgs;
    piece_sgs.reserve(blkids.size());
    std::vector< sisl::async::task< iomgr::io_result > > futs;
    futs.reserve(blkids.size());
    sisl::sg_iterator sg_it{sgs.iovs};
    for (const auto& blkid : blkids) {
        auto sgs_size = blkid.blk_count() * data_service().get_blk_size();
        const auto iovs = sg_it.next_iovs(sgs_size);
        piece_sgs.push_back(sisl::sg_list{sgs_size, iovs});
        futs.emplace_back(async_write(piece_sgs.back(), blkid, batch));
    }
    decr_pending_request_num();
    co_return co_await collect_all(std::move(futs));
}

void blk_data_service::submit_io_batch() { m_vdev->submit_batch(); }

io_batch::~io_batch() {
    if (m_svc) { m_svc->submit_io_batch(); }
}

io_batch& io_batch::operator=(io_batch&& o) noexcept {
    if (this != &o) {
        if (m_svc) { m_svc->submit_io_batch(); }
        m_svc = o.m_svc;
        o.m_svc = nullptr;
    }
    return *this;
}

// Map a BlkAllocStatus failure to the unified std::error_condition. SUCCESS never reaches here -- the value path
// returns the allocated blkids -- so anything else is a failure. BlkAllocStatus stays the allocator's internal
// currency; only the public blk_data_service boundary speaks error_condition.
static std::error_condition to_error_condition(BlkAllocStatus s) {
    switch (s) {
    case BlkAllocStatus::SPACE_FULL:
        return std::make_error_condition(std::errc::no_space_on_device);
    case BlkAllocStatus::INVALID_INPUT:
        return std::make_error_condition(std::errc::invalid_argument);
    case BlkAllocStatus::INVALID_DEV:
        return std::make_error_condition(std::errc::no_such_device);
    case BlkAllocStatus::INVALID_THREAD:
        return std::make_error_condition(std::errc::operation_not_permitted);
    case BlkAllocStatus::TOO_MANY_PIECES:
        return std::make_error_condition(std::errc::argument_list_too_long);
    default:
        return std::make_error_condition(std::errc::io_error); // FAILED, REQ_MORE, PARTIAL, ...
    }
}

result< multi_blk_id > blk_data_service::alloc_blks(uint32_t size, const blk_alloc_hints& hints) {
    if (is_stopping()) return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    HS_DBG_ASSERT_EQ(size % m_blk_size, 0, "Non aligned size requested size={} blk_size={}", size, m_blk_size);
    blk_count_t nblks = static_cast< blk_count_t >(size / m_blk_size);

    multi_blk_id out_blkids;
    auto const ret = m_vdev->alloc_blks(nblks, hints, out_blkids);
    decr_pending_request_num();
    if (ret != BlkAllocStatus::SUCCESS) { return std::unexpected(to_error_condition(ret)); }
    return out_blkids;
}

result< std::vector< blk_id > > blk_data_service::alloc_blk_list(uint32_t size, const blk_alloc_hints& hints) {
    if (is_stopping()) return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();
    HS_DBG_ASSERT_EQ(size % m_blk_size, 0, "Non aligned size requested size={} blk_size={}", size, m_blk_size);
    blk_count_t nblks = static_cast< blk_count_t >(size / m_blk_size);

    std::vector< blk_id > out_blkids;
    auto const ret = m_vdev->alloc_blks(nblks, hints, out_blkids);
    decr_pending_request_num();
    if (ret != BlkAllocStatus::SUCCESS) { return std::unexpected(to_error_condition(ret)); }
    return out_blkids;
}

status blk_data_service::commit_blk(multi_blk_id const& blkid, bool recommit) {
    if (is_stopping()) return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();

    BlkAllocStatus ret = BlkAllocStatus::SUCCESS;
    if (blkid.num_pieces() == 1) {
        ret = m_vdev->commit_blk(blkid, recommit); // shortcut for the most common case
    } else {
        auto it = blkid.iterate();
        while (auto const bid = it.next()) {
            ret = m_vdev->commit_blk(*bid, recommit);
            if (ret != BlkAllocStatus::SUCCESS) { break; }
        }
    }
    decr_pending_request_num();
    if (ret != BlkAllocStatus::SUCCESS) { return std::unexpected(to_error_condition(ret)); }
    return ok();
}

sisl::async::task< iomgr::io_result > blk_data_service::async_free_blk(multi_blk_id const& bids) {
    if (is_stopping()) co_return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();

    if (!m_vdev->is_blk_exist(bids)) {
        decr_pending_request_num();
        co_return std::unexpected(std::make_error_condition(std::errc::resource_unavailable_try_again));
    }

    // The free can only happen once all pending reads on these blks drain; wait_on fires the callback then
    // (possibly on another thread). Hand the result back through a value_awaitable kept alive by both the callback
    // capture and this coroutine frame
    auto aw = std::make_shared< sisl::async::value_awaitable< iomgr::io_result > >();
    m_blk_read_tracker->wait_on(bids, [this, bids, aw]() mutable {
        {
            auto cpg = hs()->cp_mgr().cp_guard();
            m_vdev->free_blk(bids, s_cast< VDevCPContext* >(cpg.context(cp_consumer_t::BLK_DATA_SVC)));
        }
        aw->complete(iomgr::io_result{0});
    });
    decr_pending_request_num();
    co_return co_await *aw;
}

status blk_data_service::free_blk_now(multi_blk_id const& bids) {
    if (is_stopping()) return std::unexpected(std::make_error_condition(std::errc::operation_canceled));
    incr_pending_request_num();

    if (!m_vdev->is_blk_exist(bids)) {
        decr_pending_request_num();
        return std::unexpected(std::make_error_condition(std::errc::resource_unavailable_try_again));
    } else {
        auto cpg = hs()->cp_mgr().cp_guard();
        m_vdev->free_blk(bids, s_cast< VDevCPContext* >(cpg.context(cp_consumer_t::BLK_DATA_SVC)), true /* free_now */);
    }
    decr_pending_request_num();
    return ok();
}

bool blk_data_service::is_blk_alloced(blk_id const& blkid) const { return m_vdev->is_blk_alloced(blkid); }

void blk_data_service::start() {
    // Register to CP for flush dirty buffers underlying virtual device layer;
    hs()->cp_mgr().register_consumer(cp_consumer_t::BLK_DATA_SVC,
                                     std::move(std::make_unique< DataSvcCPCallbacks >(m_vdev)));
}

void blk_data_service::stop() {
    start_stopping();
    // we have no way to track the completion of each async io in detail which should be done in iomanager level, so
    // we just wait for 3 seconds, and we expect each io will be completed within this time.

    // TODO: find a better solution to track the completion of these aysnc calls
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
    while (true) {
        if (!get_pending_request_num()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

uint64_t blk_data_service::get_total_capacity() const { return m_vdev->size(); }

uint64_t blk_data_service::get_used_capacity() const { return m_vdev->used_size(); }

HSDevType blk_data_service::get_dev_type() const { return static_cast< HSDevType >(m_vdev->get_dev_type()); }

uint32_t blk_data_service::get_align_size() const { return m_vdev->align_size(); }

} // namespace homestore
