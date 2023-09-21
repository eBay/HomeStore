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

#include "device/chunk.h"
#include "device/physical_dev.hpp"
#include "device/device.h"
#include "device/virtual_dev.hpp"
#include "common/error.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"
#include "blkalloc/varsize_blk_allocator.h"
#include "device/round_robin_chunk_selector.h"
#include "blkalloc/append_blk_allocator.h"

SISL_LOGGING_DECL(device)

namespace homestore {

static std::shared_ptr< BlkAllocator > create_blk_allocator(blk_allocator_type_t btype, uint32_t vblock_size,
                                                            uint32_t ppage_sz, uint32_t align_sz, uint64_t size,
                                                            bool is_auto_recovery, uint32_t unique_id, bool is_init) {
    switch (btype) {
    case blk_allocator_type_t::fixed: {
        BlkAllocConfig cfg{vblock_size, align_sz, size, std::string{"fixed_chunk_"} + std::to_string(unique_id)};
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< FixedBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::varsize: {
        VarsizeBlkAllocConfig cfg{vblock_size,
                                  ppage_sz,
                                  align_sz,
                                  size,
                                  std::string("varsize_chunk_") + std::to_string(unique_id),
                                  true /* realtime_bitmap */,
                                  is_data_drive_hdd() ? false : true /* use_slabs */};
        // HS_DBG_ASSERT_EQ((size % MIN_DATA_CHUNK_SIZE(ppage_sz)), 0);
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< VarsizeBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::append: {
        BlkAllocConfig cfg{vblock_size, align_sz, size, std::string("append_chunk_") + std::to_string(unique_id)};
        cfg.set_auto_recovery(is_auto_recovery);
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
        m_auto_recovery{is_auto_recovery} {
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
                                   chunk->chunk_id(), is_fresh_chunk);
    chunk->set_block_allocator(std::move(ba));
    chunk->set_vdev_ordinal(m_all_chunks.size());
    m_pdevs.insert(chunk->physical_dev_mutable());
    m_all_chunks.push_back(chunk);
    m_chunk_selector->add_chunk(chunk);
}

folly::Future< std::error_code > VirtualDev::async_format() {
    static thread_local std::vector< folly::Future< std::error_code > > s_futs;
    s_futs.clear();

    for (auto& chunk : m_all_chunks) {
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

/*std::shared_ptr< blkalloc_cp > VirtualDev::attach_prepare_cp(const std::shared_ptr< blkalloc_cp >& cur_ba_cp) {
    return (Chunk::attach_prepare_cp(cur_ba_cp));
}*/

bool VirtualDev::is_blk_alloced(BlkId const& blkid) const {
    return m_dmgr.get_chunk(blkid.chunk_num())->blk_allocator()->is_blk_alloced(blkid);
}

BlkAllocStatus VirtualDev::commit_blk(BlkId const& blkid) {
    Chunk* chunk = m_dmgr.get_chunk_mutable(blkid.chunk_num());
    HS_LOG(DEBUG, device, "commit_blk: bid {}", blkid.to_string());
    return chunk->blk_allocator_mutable()->alloc_on_disk(blkid);
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
        HS_REL_ASSERT_EQ(mbid.num_pieces(), 1, "out blkid more than 1 entries will lead to blk leak!");
        out_blkid = mbid.to_single_blkid();
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
            } while (++attempt < m_all_chunks.size());
        }

        if ((status != BlkAllocStatus::SUCCESS) && !((status == BlkAllocStatus::PARTIAL) && hints.partial_alloc_ok)) {
            LOGERROR("nblks={} failed to alloc after trying to alloc on every chunks {} and devices {}.", nblks);
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
        out_blkids.emplace_back(); // Put an empty MultiBlkId and use that for allocating them
        BlkId& out_bid = out_blkids.back();
        status = alloc_contiguous_blks(nblks_remain, h, out_bid);

        auto nblks_this_iter = out_bid.blk_count();
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
        // free partial result
        auto it = out_blkid.iterate();
        while (auto const b = it.next()) {
            auto const ret = chunk->blk_allocator_mutable()->free_on_realtime(*b);
            HS_REL_ASSERT(ret, "failed to free on realtime");
        }
        chunk->blk_allocator_mutable()->free(out_blkid);
        out_blkid = MultiBlkId{};
        status = BlkAllocStatus::FAILED;
    }

    return status;
}

/*bool VirtualDev::free_on_realtime(BlkId const& b) {
    Chunk* chunk = m_dmgr.get_chunk_mutable(b.chunk_num());
    return chunk->blk_allocator_mutable()->free_on_realtime(b);
}*/

void VirtualDev::free_blk(BlkId const& b) {
    if (b.is_multi()) {
        MultiBlkId const& mb = r_cast< MultiBlkId const& >(b);
        Chunk* chunk = m_dmgr.get_chunk_mutable(mb.chunk_num());
        chunk->blk_allocator_mutable()->free(mb);
    } else {
        Chunk* chunk = m_dmgr.get_chunk_mutable(b.chunk_num());
        chunk->blk_allocator_mutable()->free(b);
    }
}

void VirtualDev::recovery_done() {
    DEBUG_ASSERT_EQ(m_auto_recovery, false, "recovery done (manual recovery completion) called on auto recovery vdev");
    for (auto& chunk : m_all_chunks) {
        chunk->blk_allocator_mutable()->inited();
    }
}

uint64_t VirtualDev::get_len(const iovec* iov, int iovcnt) {
    uint64_t len{0};
    for (int i{0}; i < iovcnt; ++i) {
        len += iov[i].iov_len;
    }
    return len;
}

////////////////////////// async write section //////////////////////////////////
folly::Future< std::error_code > VirtualDev::async_write(const char* buf, uint32_t size, BlkId const& bid,
                                                         bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_write needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    auto* pdev = chunk->physical_dev_mutable();

    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->pdev_id(), dev_offset);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_write(buf, size, dev_offset, part_of_batch);
}

folly::Future< std::error_code > VirtualDev::async_write(const char* buf, uint32_t size, cshared< Chunk >& chunk,
                                                         uint64_t offset_in_chunk) {
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

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
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
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_write needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    return chunk->physical_dev_mutable()->sync_write(buf, size, dev_offset);
}

std::error_code VirtualDev::sync_write(const char* buf, uint32_t size, cshared< Chunk >& chunk,
                                       uint64_t offset_in_chunk) {
    return chunk->physical_dev_mutable()->sync_write(buf, size, chunk->start_offset() + offset_in_chunk);
}

std::error_code VirtualDev::sync_writev(const iovec* iov, int iovcnt, BlkId const& bid) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_writev needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_writev(iov, iovcnt, size, dev_offset);
}

std::error_code VirtualDev::sync_writev(const iovec* iov, int iovcnt, cshared< Chunk >& chunk,
                                        uint64_t offset_in_chunk) {
    uint64_t const dev_offset = chunk->start_offset() + offset_in_chunk;
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_writev(iov, iovcnt, size, dev_offset);
}

////////////////////////////////// async read section ///////////////////////////////////////////////
folly::Future< std::error_code > VirtualDev::async_read(char* buf, uint64_t size, BlkId const& bid,
                                                        bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_read needs individual pieces of blkid - not MultiBlkid");

    Chunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    return pchunk->physical_dev_mutable()->async_read(buf, size, dev_offset, part_of_batch);
}

folly::Future< std::error_code > VirtualDev::async_readv(iovec* iovs, int iovcnt, uint64_t size, BlkId const& bid,
                                                         bool part_of_batch) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "async_readv needs individual pieces of blkid - not MultiBlkid");

    Chunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    return pchunk->physical_dev_mutable()->async_readv(iovs, iovcnt, size, dev_offset, part_of_batch);
}

////////////////////////////////////////// sync read section ////////////////////////////////////////////
std::error_code VirtualDev::sync_read(char* buf, uint32_t size, BlkId const& bid) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_read needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    return chunk->physical_dev_mutable()->sync_read(buf, size, dev_offset);
}

std::error_code VirtualDev::sync_read(char* buf, uint32_t size, cshared< Chunk >& chunk, uint64_t offset_in_chunk) {
    return chunk->physical_dev_mutable()->sync_read(buf, size, chunk->start_offset() + offset_in_chunk);
}

std::error_code VirtualDev::sync_readv(iovec* iov, int iovcnt, BlkId const& bid) {
    HS_DBG_ASSERT_EQ(bid.is_multi(), false, "sync_readv needs individual pieces of blkid - not MultiBlkid");

    Chunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    return pdev->sync_readv(iov, iovcnt, size, dev_offset);
}

std::error_code VirtualDev::sync_readv(iovec* iov, int iovcnt, cshared< Chunk >& chunk, uint64_t offset_in_chunk) {
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
    for (auto& chunk : m_all_chunks) {
        avl_blks += chunk->blk_allocator()->available_blks();
    }
    return avl_blks;
}

uint64_t VirtualDev::used_size() const {
    uint64_t alloc_cnt{0};
    for (auto& chunk : m_all_chunks) {
        alloc_cnt += chunk->blk_allocator()->get_used_blks();
    }
    return (alloc_cnt * block_size());
}

std::vector< shared< Chunk > > VirtualDev::get_chunks() const { return m_all_chunks; }

/*void VirtualDev::blkalloc_cp_start(const std::shared_ptr< blkalloc_cp >& ba_cp) {
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (size_t chunk_indx{0}; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            auto* chunk = m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx];
            chunk->cp_start(ba_cp);
        }
    }
}*/

/* Get status for all chunks */
nlohmann::json VirtualDev::get_status(int log_level) const {
    nlohmann::json j;

    try {
        for (auto& chunk : m_all_chunks) {
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

uint32_t VirtualDev::align_size() const {
    auto* pdev = *(m_pdevs.begin());
    return pdev->align_size();
}
uint32_t VirtualDev::optimal_page_size() const {
    auto* pdev = *(m_pdevs.begin());
    return pdev->optimal_page_size();
}
uint32_t VirtualDev::atomic_page_size() const {
    auto* pdev = *(m_pdevs.begin());
    return pdev->atomic_page_size();
}

std::string VirtualDev::to_string() const { return ""; }

shared< Chunk > VirtualDev::get_next_chunk(cshared< Chunk >& chunk) const {
    return m_all_chunks[(chunk->vdev_ordinal() + 1) % m_all_chunks.size()];
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

VDevCPContext::VDevCPContext(cp_id_t cp_id) : CPContext(cp_id) {}

std::unique_ptr< CPContext > VirtualDev::create_cp_context(cp_id_t cp_id) {
    return std::make_unique< VDevCPContext >(cp_id);
}

void VirtualDev::cp_flush(CP* cp) {
    // pass down cp so that underlying componnents can get their customized CP context if needed;
    m_chunk_selector->foreach_chunks([this, cp](cshared< Chunk >& chunk) { chunk->cp_flush(cp); });
}

// sync-ops during cp_flush, so return 100;
int VirtualDev::cp_progress_percent() { return 100; }

void VirtualDev::cp_cleanup(CP*) {
    // no-op;
}

///////////////////////// VirtualDev Private Methods /////////////////////////////
uint64_t VirtualDev::to_dev_offset(BlkId const& b, Chunk** chunk) const {
    *chunk = m_dmgr.get_chunk_mutable(b.chunk_num());
    return uint64_cast(b.blk_num()) * block_size() + uint64_cast((*chunk)->start_offset());
}

} // namespace homestore
