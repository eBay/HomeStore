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
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iterator>
#include <limits>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <sisl/utility/atomic_counter.hpp>
#include <iomgr/iomgr_flip.hpp>
#include <homestore/homestore_decl.hpp>

#include "device/chunk.h"
#include "device/physical_dev.hpp"
#include "device/device.h"
#include "device/virtual_dev.hpp"
#include "common/error.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"
#include "common/crash_simulator.hpp"
#include "blkalloc/varsize_blk_allocator.h"
#include "device/round_robin_chunk_selector.h"
#include "blkalloc/append_blk_allocator.h"
#include "blkalloc/fixed_blk_allocator.h"

SISL_LOGGING_DECL(device)

namespace homestore {

static std::shared_ptr< BlkAllocator > create_blk_allocator(blk_allocator_type_t btype, uint32_t vblock_size,
                                                            uint32_t ppage_sz, uint32_t align_sz, uint64_t size,
                                                            bool is_auto_recovery, uint32_t unique_id, bool is_init,
                                                            bool use_slab_in_blk_allocator) {
    switch (btype) {
    case blk_allocator_type_t::fixed: {
        BlkAllocConfig cfg{vblock_size, align_sz, size, is_auto_recovery,
                           std::string{"fixed_chunk_"} + std::to_string(unique_id)};
        return std::make_shared< FixedBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::varsize: {
        VarsizeBlkAllocConfig cfg{vblock_size,
                                  ppage_sz,
                                  align_sz,
                                  size,
                                  is_auto_recovery,
                                  std::string("varsize_chunk_") + std::to_string(unique_id),
                                  !is_data_drive_hdd() && use_slab_in_blk_allocator /* use_slabs */};
        // HS_DBG_ASSERT_EQ((size % MIN_DATA_CHUNK_SIZE(ppage_sz)), 0);
        return std::make_shared< VarsizeBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::append: {
        BlkAllocConfig cfg{vblock_size, align_sz, size, false,
                           std::string("append_chunk_") + std::to_string(unique_id)};
        return std::make_shared< AppendBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::none:
    default:
        return nullptr;
    }
}

VirtualDev::VirtualDev(DeviceManager& dmgr, vdev_info const& vinfo, vdev_event_cb_t event_cb, bool is_auto_recovery,
                       shared< ChunkSelector > custom_chunk_selector) :
        m_vdev_info{vinfo},
        m_dmgr{dmgr},
        m_name{vinfo.name},
        m_event_cb{std::move(event_cb)},
        m_metrics{vinfo.name},
        m_allocator_type{vinfo.alloc_type},
        m_chunk_selector_type{vinfo.chunk_sel_type},
        m_auto_recovery{is_auto_recovery},
        m_use_slab_in_blk_allocator{vinfo.use_slab_allocator ? true : false} {
    switch (m_chunk_selector_type) {
    case chunk_selector_type_t::ROUND_ROBIN: {
        m_chunk_selector = std::make_shared< RoundRobinChunkSelector >(false /* dynamically add chunk */);
        break;
    }
    case chunk_selector_type_t::CUSTOM: {
        HS_REL_ASSERT(custom_chunk_selector, "Expected custom chunk selector to be passed with selector_type=CUSTOM");
        m_chunk_selector = std::move(custom_chunk_selector);
        break;
    }
    case chunk_selector_type_t::NONE: {
        break;
    }
    default:
        HS_DBG_ASSERT(false, "Chunk selector type {} not supported yet", m_chunk_selector_type);
    }
}

// TODO: Have an additional parameter for vdev to check if dynamic add chunk. If so, we need to take do an rcu for
// m_all_chunks.
void VirtualDev::add_chunk(cshared< Chunk >& chunk, bool is_fresh_chunk) {
    std::unique_lock lg{m_mgmt_mutex};
    auto ba = create_blk_allocator(m_allocator_type, block_size(), chunk->physical_dev()->optimal_page_size(),
                                   chunk->physical_dev()->align_size(), chunk->size(), m_auto_recovery,
                                   chunk->chunk_id(), is_fresh_chunk, m_use_slab_in_blk_allocator);
    chunk->set_block_allocator(std::move(ba));
    // TODO: when vdev_ordinal is  used, revisit here to make sure it is set correctly;
    chunk->set_vdev_ordinal(m_total_chunk_num++);
    m_pdevs.insert(chunk->physical_dev_mutable());
    m_all_chunks[chunk->chunk_id()] = chunk;
    m_chunk_selector->add_chunk(chunk);
}

void VirtualDev::remove_chunk(cshared< Chunk >& chunk) {
    std::unique_lock lg{m_mgmt_mutex};
    m_all_chunks.erase(chunk->chunk_id());
    m_total_chunk_num--;
    m_chunk_selector->remove_chunk(chunk);
}

folly::Future< std::error_code > VirtualDev::async_format() {
    static thread_local std::vector< folly::Future< std::error_code > > s_futs;
    s_futs.clear();

    for (auto& [_, chunk] : m_all_chunks) {
        auto* pdev = chunk->physical_dev_mutable();
        LOGINFO("writing zero for chunk: {}, size: {}, offset: {}", chunk->chunk_id(), in_bytes(chunk->size()),
                chunk->start_offset());
        s_futs.emplace_back(pdev->async_write_zero(chunk->size(), chunk->start_offset()));
    }
    return folly::collectAllUnsafe(s_futs).thenTry([](auto&& t) {
        for (const auto& err_c : t.value()) {
            if (sisl_unlikely(err_c.value())) { return folly::makeFuture< std::error_code >(err_c); }
        }
        return folly::makeFuture< std::error_code >(std::error_code{});
    });
}

bool VirtualDev::is_blk_alloced(BlkId const& blkid) const {
    return m_dmgr.get_chunk(blkid.chunk_num())->blk_allocator()->is_blk_alloced(blkid, true /* lock */);
}

BlkAllocStatus VirtualDev::commit_blk(BlkId const& blkid) {
    Chunk* chunk = m_dmgr.get_chunk_mutable(blkid.chunk_num());
    // if we start with missing drive, we will have no chunk for this blkid;
    if (!chunk) {
        HS_LOG(ERROR, device, "fail to commit_blk: bid {}", blkid.to_string());
        return BlkAllocStatus::INVALID_DEV;
    }
    HS_LOG(DEBUG, device, "commit_blk: bid {}", blkid.to_string());
    auto const recovering = homestore::hs()->is_initializing();
    if (!recovering) {
        // in non-recovery mode, if a blk is committed without allocating, it will cause data corruption
        HS_REL_ASSERT(is_blk_alloced(blkid), "commiting blkid {} is not allocated in non-recovery mode",
                      blkid.to_string());
    } else {
        chunk->blk_allocator_mutable()->reserve_on_cache(blkid);
    }
    return chunk->blk_allocator_mutable()->reserve_on_disk(blkid);
}

BlkAllocStatus VirtualDev::alloc_contiguous_blks(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) {
    BlkAllocStatus ret;
    try {
        MultiBlkId mbid;
        if (!hints.is_contiguous) {
            HS_DBG_ASSERT(false, "Expected alloc_contiguous_blk call to be with hints.is_contiguous=true");
            blk_alloc_hints adjusted_hints = hints;
            adjusted_hints.is_contiguous = true;
            ret = alloc_blks(nblks, adjusted_hints, mbid);
        } else {
            ret = alloc_blks(nblks, hints, mbid);
        }

        if (ret == BlkAllocStatus::SUCCESS || (ret == BlkAllocStatus::PARTIAL && hints.partial_alloc_ok)) {
            HS_REL_ASSERT_EQ(mbid.num_pieces(), 1, "out blkid more than 1 entries will lead to blk leak!");
            out_blkid = mbid.to_single_blkid();
        }

        // for failure case, fall through and return the status to caller;
    } catch (const std::exception& e) {
        ret = BlkAllocStatus::FAILED;
        HS_DBG_ASSERT(0, "{}", e.what());
    }
    return ret;
}

BlkAllocStatus VirtualDev::alloc_n_contiguous_blks(blk_count_t nblks, blk_alloc_hints hints, MultiBlkId& out_blkid) {
    BlkAllocStatus ret;
    try {
        MultiBlkId mbid;
        if (!hints.is_contiguous) {
            HS_DBG_ASSERT(false, "Expected alloc_contiguous_blk call to be with hints.is_contiguous=true");
            hints.is_contiguous = true;
        }
        ret = alloc_blks(nblks, hints, mbid);

        if (ret == BlkAllocStatus::SUCCESS || (ret == BlkAllocStatus::PARTIAL && hints.partial_alloc_ok)) {
            out_blkid = mbid;
        }

        // for failure case, fall through and return the status to caller;
    } catch (const std::exception& e) {
        ret = BlkAllocStatus::FAILED;
        HS_DBG_ASSERT(0, "{}", e.what());
    }
    return ret;
}

BlkAllocStatus VirtualDev::alloc_blks(blk_count_t nblks, blk_alloc_hints const& hints, MultiBlkId& out_blkid) {
    try {
        // First select a chunk to allocate it from
        BlkAllocStatus status;
        Chunk* chunk;
        size_t attempt{0};
        if (hints.chunk_id_hint) {
            // this is a target-chunk allocation;
            chunk = m_dmgr.get_chunk_mutable(*(hints.chunk_id_hint));
            if (!chunk) return BlkAllocStatus::INVALID_DEV;
            status = alloc_blks_from_chunk(nblks, hints, out_blkid, chunk);
            // don't look for other chunks because user wants allocation on chunk_id_hint only;
        } else {
            do {
                chunk = m_chunk_selector->select_chunk(nblks, hints).get();
                if (chunk == nullptr) {
                    status = BlkAllocStatus::SPACE_FULL;
                    break;
                }

                status = alloc_blks_from_chunk(nblks, hints, out_blkid, chunk);
                if ((status == BlkAllocStatus::SUCCESS) || !hints.can_look_for_other_chunk ||
                    (status == BlkAllocStatus::PARTIAL && hints.partial_alloc_ok)) {
                    break;
                }
            } while (++attempt < m_total_chunk_num);
        }

        if ((status != BlkAllocStatus::SUCCESS) && !((status == BlkAllocStatus::PARTIAL) && hints.partial_alloc_ok)) {
            LOGERROR("nblks={} failed to alloc after trying to alloc on every chunks and devices", nblks);
            COUNTER_INCREMENT(m_metrics, vdev_num_alloc_failure, 1);
        }

        return status;
    } catch (const std::exception& e) {
        LOGERROR("exception happened {}", e.what());
        assert(false);
        return BlkAllocStatus::FAILED;
    }
}

BlkAllocStatus VirtualDev::alloc_blks(blk_count_t nblks, blk_alloc_hints const& hints,
                                      std::vector< BlkId >& out_blkids) {
    // Regular alloc blks will allocate in MultiBlkId, but there is an upper limit on how many it can accomodate in a
    // single MultiBlkId, if caller is ok to generate multiple MultiBlkids, this method is called.
    auto h = hints;
    h.partial_alloc_ok = true;
    h.is_contiguous = true;
    blk_count_t nblks_remain = nblks;
    BlkAllocStatus status;

    do {
        MultiBlkId mbid;
        status = alloc_n_contiguous_blks(nblks_remain, h, mbid);
        if (status != BlkAllocStatus::SUCCESS && status != BlkAllocStatus::PARTIAL) {
            out_blkids.pop_back();
            // all chunks has been tried, but still failed to allocate;
            // break out and return status to caller;
            break;
        }

        blk_count_t nblks_this_iter = 0;
        auto it = mbid.iterate();
        while (auto const b = it.next()) {
            nblks_this_iter += (*b).blk_count();
            out_blkids.emplace_back(*b);
        }

        nblks_remain = (nblks_remain < nblks_this_iter) ? 0 : (nblks_remain - nblks_this_iter);

    } while (nblks_remain);

    return status;
}

BlkAllocStatus VirtualDev::alloc_blks_from_chunk(blk_count_t nblks, blk_alloc_hints const& hints, MultiBlkId& out_blkid,
                                                 Chunk* chunk) {
#ifdef _PRERELEASE
    if (auto const fake_status =
            iomgr_flip::instance()->get_test_flip< uint32_t >("blk_allocation_flip", nblks, chunk->vdev_id())) {
        return static_cast< BlkAllocStatus >(fake_status.get());
    }
#endif
    auto status = chunk->blk_allocator_mutable()->alloc(nblks, hints, out_blkid);
    if ((status == BlkAllocStatus::PARTIAL) && (!hints.partial_alloc_ok)) {
        chunk->blk_allocator_mutable()->free(out_blkid);
        out_blkid = MultiBlkId{};
        status = BlkAllocStatus::FAILED;
    } else if (status == BlkAllocStatus::SUCCESS || status == BlkAllocStatus::PARTIAL) {
        blk_count_t nblks_alloc = 0;
        auto it = out_blkid.iterate();
        while (auto const b = it.next()) {
            nblks_alloc += (*b).blk_count();
        }
        // Inform chunk selector on the number of blks alloced
        m_chunk_selector->on_alloc_blk(chunk->chunk_id(), nblks_alloc);
    }

    return status;
}

void VirtualDev::free_blk(BlkId const& bid, VDevCPContext* vctx) {
    auto do_free_action = [this](auto const& b, VDevCPContext* vctx) {
        if (vctx && (m_allocator_type != blk_allocator_type_t::append)) {
            // We don't want to accumulate here for append blk allocator.
            vctx->m_free_blkid_list.push_back(b);
        } else {
            auto chunk = m_dmgr.get_chunk_mutable(b.chunk_num());
            // try to free a blk in a missing chunk, crash if it happens;
            if (!chunk) HS_DBG_ASSERT(false, "chunk is missing for blkid {}", b.to_string());
            BlkAllocator* allocator = chunk->blk_allocator_mutable();
            allocator->free(b);
            // Inform chunk selector on the number of blks freed
            m_chunk_selector->on_free_blk(chunk->chunk_id(), b.blk_count());
        }
    };

    if (bid.is_multi()) {
        MultiBlkId const& mbid = r_cast< MultiBlkId const& >(bid);
        auto it = mbid.iterate();
        while (auto const b = it.next()) {
            do_free_action(*b, vctx);
        }
    } else {
        do_free_action(bid, vctx);
    }
}

uint64_t VirtualDev::get_len(const iovec* iov, int iovcnt) {
    uint64_t len{0};
    for (int i{0}; i < iovcnt; ++i) {
        len += iov[i].iov_len;
    }
    return len;
}

// for all writes functions, we don't expect to get invalid dev_offset, since we will never allocate blkid from missing
// chunk(missing pdev);
////////////////////////// async write section //////////////////////////////////
folly::Future< std::error_code > VirtualDev::async_write(const char* buf, uint32_t size, BlkId const& bid,
                                                         bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_write needs individual pieces of blkid - not MultiBlkid");

#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return folly::makeFuture< std::error_code >(std::error_code()); }
#endif

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        // TODO: define a new error code for missing pdev case;
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}, size ={}", pdev->pdev_id(), dev_offset, size);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_write(buf, size, dev_offset, part_of_batch);
}

folly::Future< std::error_code > VirtualDev::async_write(const char* buf, uint32_t size, cshared< Chunk >& chunk,
                                                         uint64_t offset_in_chunk) {
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return folly::makeFuture< std::error_code >(std::error_code()); }
#endif

    if (sisl_unlikely(!is_chunk_available(chunk))) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    auto const dev_offset = chunk->start_offset() + offset_in_chunk;
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->pdev_id(), dev_offset);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_write(buf, size, dev_offset, false /* part_of_batch */);
}

folly::Future< std::error_code > VirtualDev::async_writev(const iovec* iov, const int iovcnt, BlkId const& bid,
                                                          bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_writev needs individual pieces of blkid - not MultiBlkid");
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return folly::makeFuture< std::error_code >(std::error_code()); }
#endif

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->pdev_id(), dev_offset);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_writev(iov, iovcnt, size, dev_offset, part_of_batch);
}

folly::Future< std::error_code > VirtualDev::async_writev(const iovec* iov, const int iovcnt, cshared< Chunk >& chunk,
                                                          uint64_t offset_in_chunk) {
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return folly::makeFuture< std::error_code >(std::error_code()); }
#endif

    if (sisl_unlikely(!is_chunk_available(chunk))) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    auto const dev_offset = chunk->start_offset() + offset_in_chunk;
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->pdev_id(), dev_offset);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_writev(iov, iovcnt, size, dev_offset, false /* part_of_batch */);
}

////////////////////////// sync write section //////////////////////////////////
std::error_code VirtualDev::sync_write(const char* buf, uint32_t size, BlkId const& bid) {
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return std::error_code{}; }
#endif

    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_write needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    HS_LOG(TRACE, device, "Writing sync in device: {}, offset = {}", chunk->physical_dev_mutable()->pdev_id(),
           dev_offset);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    return chunk->physical_dev_mutable()->sync_write(buf, size, dev_offset);
}

std::error_code VirtualDev::sync_write(const char* buf, uint32_t size, cshared< Chunk >& chunk,
                                       uint64_t offset_in_chunk) {
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return std::error_code{}; }
#endif

    HS_LOG(TRACE, device, "Writing sync in device: {}, offset = {}", chunk->physical_dev_mutable()->pdev_id(),
           chunk->start_offset() + offset_in_chunk);

    if (sisl_unlikely(!is_chunk_available(chunk))) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    return chunk->physical_dev_mutable()->sync_write(buf, size, chunk->start_offset() + offset_in_chunk);
}

std::error_code VirtualDev::sync_writev(const iovec* iov, int iovcnt, BlkId const& bid) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_writev needs individual pieces of blkid - not MultiBlkid");

#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return std::error_code{}; }
#endif

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing sync in device: {}, offset = {}", pdev->pdev_id(), dev_offset);

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_writev(iov, iovcnt, size, dev_offset);
}

std::error_code VirtualDev::sync_writev(const iovec* iov, int iovcnt, cshared< Chunk >& chunk,
                                        uint64_t offset_in_chunk) {
#ifdef _PRERELEASE
    if (hs()->crash_simulator().is_crashed()) { return std::error_code{}; }
#endif

    if (sisl_unlikely(!is_chunk_available(chunk))) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }

    uint64_t const dev_offset = chunk->start_offset() + offset_in_chunk;
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing sync in device: {}, offset = {}", pdev->pdev_id(), dev_offset);

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_writev(iov, iovcnt, size, dev_offset);
}

// for read, chunk might be missing in case of pdev is gone(for example , breakfix), so we need to check if chunk is
// loaded before proceeding with read;
////////////////////////////////// async read section ///////////////////////////////////////////////
folly::Future< std::error_code > VirtualDev::async_read(char* buf, uint64_t size, BlkId const& bid,
                                                        bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_read needs individual pieces of blkid - not MultiBlkid");

    Chunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    return pchunk->physical_dev_mutable()->async_read(buf, size, dev_offset, part_of_batch);
}

folly::Future< std::error_code > VirtualDev::async_readv(iovec* iovs, int iovcnt, uint64_t size, BlkId const& bid,
                                                         bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_readv needs individual pieces of blkid - not MultiBlkid");

    Chunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    return pchunk->physical_dev_mutable()->async_readv(iovs, iovcnt, size, dev_offset, part_of_batch);
}

////////////////////////////////////////// sync read section ////////////////////////////////////////////
std::error_code VirtualDev::sync_read(char* buf, uint32_t size, BlkId const& bid) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_read needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    return chunk->physical_dev_mutable()->sync_read(buf, size, dev_offset);
}

std::error_code VirtualDev::sync_read(char* buf, uint32_t size, cshared< Chunk >& chunk, uint64_t offset_in_chunk) {
    if (sisl_unlikely(!is_chunk_available(chunk))) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    return chunk->physical_dev_mutable()->sync_read(buf, size, chunk->start_offset() + offset_in_chunk);
}

std::error_code VirtualDev::sync_readv(iovec* iov, int iovcnt, BlkId const& bid) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_readv needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    if (sisl_unlikely(dev_offset == INVALID_DEV_OFFSET)) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_readv(iov, iovcnt, size, dev_offset);
}

std::error_code VirtualDev::sync_readv(iovec* iov, int iovcnt, cshared< Chunk >& chunk, uint64_t offset_in_chunk) {
    if (sisl_unlikely(!is_chunk_available(chunk))) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    uint64_t const dev_offset = chunk->start_offset() + offset_in_chunk;
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_readv(iov, iovcnt, size, dev_offset);
}

folly::Future< std::error_code > VirtualDev::queue_fsync_pdevs() {
    HS_DBG_ASSERT_EQ(HS_DYNAMIC_CONFIG(device->direct_io_mode), false, "Not expect to do fsync in DIRECT_IO_MODE.");

    assert(m_pdevs.size() > 0);
    if (m_pdevs.size() == 1) {
        auto* pdev = *(m_pdevs.begin());
        HS_LOG(TRACE, device, "Flushing pdev {}", pdev->get_devname());
        return pdev->queue_fsync();
    } else {
        static thread_local std::vector< folly::Future< std::error_code > > s_futs;
        s_futs.clear();
        for (auto* pdev : m_pdevs) {
            HS_LOG(TRACE, device, "Flushing pdev {}", pdev->get_devname());
            s_futs.emplace_back(pdev->queue_fsync());
        }
        return folly::collectAllUnsafe(s_futs).thenTry([](auto&& t) {
            for (const auto& err_c : t.value()) {
                if (sisl_unlikely(err_c.value())) { return folly::makeFuture< std::error_code >(err_c); }
            }
            return folly::makeFuture< std::error_code >(std::error_code{});
        });
    }
}

void VirtualDev::submit_batch() {
    // It is enough to submit batch on first pdev, since all pdevs are expected to be under same drive interfaces
    auto* pdev = *(m_pdevs.begin());
    return pdev->submit_batch();
}

uint64_t VirtualDev::available_blks() const {
    uint64_t avl_blks{0};
    for (auto& [_, chunk] : m_all_chunks) {
        avl_blks += chunk->blk_allocator()->available_blks();
    }
    return avl_blks;
}

uint64_t VirtualDev::used_size() const {
    uint64_t alloc_cnt{0};
    for (auto& [_, chunk] : m_all_chunks) {
        alloc_cnt += chunk->blk_allocator()->get_used_blks();
    }
    return (alloc_cnt * block_size());
}

std::map< uint16_t, shared< Chunk > > VirtualDev::get_chunks() const { return m_all_chunks; }

bool VirtualDev::is_blk_exist(MultiBlkId const& b) const {
    auto chunk_num = b.chunk_num();
    return m_all_chunks.contains(chunk_num);
}

/* Get status for all chunks */
nlohmann::json VirtualDev::get_status(int log_level) const {
    nlohmann::json j;

    try {
        for (auto& [_, chunk] : m_all_chunks) {
            nlohmann::json chunk_j;
            chunk_j["ChunkInfo"] = chunk->get_status(log_level);
            if (chunk->blk_allocator() != nullptr) {
                chunk_j["BlkallocInfo"] = chunk->blk_allocator()->get_status(log_level);
            }
            j[std::to_string(chunk->chunk_id())] = chunk_j;
        }
    } catch (const std::exception& e) { LOGERROR("exception happened {}", e.what()); }
    return j;
}

uint32_t VirtualDev::align_size() const { return m_dmgr.align_size(static_cast< HSDevType >(m_vdev_info.hs_dev_type)); }
uint32_t VirtualDev::optimal_page_size() const {
    return m_dmgr.optimal_page_size(static_cast< HSDevType >(m_vdev_info.hs_dev_type));
}
uint32_t VirtualDev::atomic_page_size() const {
    return m_dmgr.atomic_page_size(static_cast< HSDevType >(m_vdev_info.hs_dev_type));
}

std::string VirtualDev::to_string() const { return ""; }

shared< Chunk > VirtualDev::get_next_chunk(cshared< Chunk >& chunk) {
    return m_all_chunks[(chunk->chunk_id() + 1) % m_all_chunks.size()];
}

void VirtualDev::update_vdev_private(const sisl::blob& private_data) {
    std::unique_lock lg{m_mgmt_mutex};
    m_vdev_info.set_user_private(private_data);
    m_vdev_info.compute_checksum();

    auto buf = hs_utils::iobuf_alloc(vdev_info::size, sisl::buftag::superblk, align_size());
    auto vinfo = new (buf) vdev_info();
    *vinfo = m_vdev_info;

    // Locate and write the vdev info in the super blk area of all pdevs this vdev will be created on
    for (auto& pdev : m_pdevs) {
        uint64_t offset = hs_super_blk::vdev_sb_offset() + (vinfo->vdev_id * vdev_info::size);
        pdev->write_super_block(buf, vdev_info::size, offset);
    }

    vinfo->~vdev_info();
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);
}

///////////////////////// VirtualDev Checkpoint methods /////////////////////////////
VDevCPContext::VDevCPContext(CP* cp) : CPContext(cp) {}

std::unique_ptr< CPContext > VirtualDev::create_cp_context(CP* cp) { return std::make_unique< VDevCPContext >(cp); }

void VirtualDev::cp_flush(VDevCPContext* v_cp_ctx) {
    CP* cp = v_cp_ctx->cp();

    // pass down cp so that underlying components can get their customized CP context if needed;
    m_chunk_selector->foreach_chunks(
        [this, cp](cshared< Chunk >& chunk) { chunk->blk_allocator_mutable()->cp_flush(cp); });

    // All of the blkids which were captured in the current vdev cp context will now be freed and hence available for
    // allocation on the new CP dirty collection session which is ongoing
    for (auto const& b : v_cp_ctx->m_free_blkid_list) {
        auto chunk = m_dmgr.get_chunk_mutable(b.chunk_num());
        // try to free a blk in a missing chunk, crash if it happens;
        if (!chunk) HS_DBG_ASSERT(false, "chunk is missing for blkid {}", b.to_string());
        BlkAllocator* allocator = chunk->blk_allocator_mutable();
        allocator->free(b);
    }
}

// sync-ops during cp_flush, so return 100;
int VirtualDev::cp_progress_percent() { return 100; }

void VirtualDev::recovery_completed() {
    if (m_allocator_type != blk_allocator_type_t::append) {
        m_chunk_selector->foreach_chunks(
            [this](cshared< Chunk >& chunk) { chunk->blk_allocator_mutable()->recovery_completed(); });
    }
}

///////////////////////// VirtualDev Private Methods /////////////////////////////
uint64_t VirtualDev::to_dev_offset(BlkId const& b, Chunk** chunk) const {
    *chunk = m_dmgr.get_chunk_mutable(b.chunk_num());
    if (!(*chunk)) return INVALID_DEV_OFFSET;
    return uint64_cast(b.blk_num()) * block_size() + uint64_cast((*chunk)->start_offset());
}

bool VirtualDev::is_chunk_available(cshared< Chunk >& chunk) const {
    return m_dmgr.get_chunk(chunk->chunk_id()) != nullptr;
}

} // namespace homestore
