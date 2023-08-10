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

#include <boost/range/irange.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/metrics/metrics.hpp>
#include <sisl/logging/logging.h>
#include <sisl/utility/atomic_counter.hpp>
#include <iomgr/drive_interface.hpp>
#include <iomgr/iomgr_flip.hpp>

#include <homestore/homestore.hpp>
#include "physical_dev.hpp"
#include "device.h"
#include "virtual_dev.hpp"
#include "blkalloc/blk_allocator.h"
#include "blkalloc/varsize_blk_allocator.h"
#include "common/error.h"
#include "common/homestore_assert.hpp"

SISL_LOGGING_DECL(device)

namespace homestore {

uint32_t VirtualDev::s_num_chunks_created{0};

uint64_t VirtualDev::get_len(const iovec* iov, const int iovcnt) {
    uint64_t len{0};
    for (int i{0}; i < iovcnt; ++i) {
        len += iov[i].iov_len;
    }
    return len;
}

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
        HS_DBG_ASSERT_EQ((size % MIN_DATA_CHUNK_SIZE(ppage_sz)), 0);
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< VarsizeBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::none:
    default:
        return nullptr;
    }
}

void VirtualDev::init(DeviceManager* mgr, vdev_info_block* vb, uint32_t blk_size, bool auto_recovery,
                      vdev_high_watermark_cb_t hwm_cb) {
    m_mgr = mgr;
    m_vb = vb;
    m_chunk_size = 0;
    m_num_chunks = 0;
    m_blk_size = blk_size;
    m_selector = std::make_unique< RoundRobinDeviceSelector >();
    m_recovery_init = false;
    m_auto_recovery = auto_recovery;
    m_hwm_cb = std::move(hwm_cb);
}

/* Create a new virtual dev for these parameters */
VirtualDev::VirtualDev(DeviceManager* mgr, const char* name, PhysicalDevGroup pdev_group,
                       blk_allocator_type_t allocator_type, uint64_t size_in, uint32_t nmirror, bool is_stripe,
                       uint32_t blk_size, char* context, uint64_t context_size, bool auto_recovery,
                       vdev_high_watermark_cb_t hwm_cb) :
        m_name{name}, m_allocator_type{allocator_type}, m_metrics{name}, m_pdev_group{pdev_group} {
    init(mgr, nullptr, blk_size, auto_recovery, std::move(hwm_cb));

    auto const pdev_list = m_mgr->get_devices(pdev_group);
    // Prepare primary chunks in a physical device for future inserts.
    m_primary_pdev_chunks_list.reserve(pdev_list.size());
    uint64_t mapped_stream_size = 0;
    const bool is_hdd = pdev_list.front()->is_hdd();
    m_drive_iface = pdev_list.front()->drive_iface();
    for (const auto& pdev : pdev_list) {
        pdev_chunk_map mp;
        mp.pdev = pdev;
        mp.chunks_in_pdev.reserve(1);
        m_primary_pdev_chunks_list.push_back(std::move(mp));
        // homestore doesn't support heterogeneous devices in same device group;
        HS_REL_ASSERT((mapped_stream_size == 0 || mapped_stream_size == pdev->raw_stream_size()), "stream size {}",
                      pdev->raw_stream_size());
        mapped_stream_size = pdev->raw_stream_size();
    }

    // check that all pdevs valid and of same type
    HS_DBG_ASSERT_EQ(m_primary_pdev_chunks_list.size(), pdev_list.size());
    auto size = size_in;
    auto const num_pdevs = m_primary_pdev_chunks_list.size();
    // Now its time to allocate chunks as needed
    HS_LOG_ASSERT_LT(nmirror, num_pdevs); // Mirrors should be at least 1 less than device list

    auto const max_chunk_size = MAX_DATA_CHUNK_SIZE(m_blk_size);
    auto const min_sys_chunk_size = MIN_DATA_CHUNK_SIZE(std::max(m_blk_size, phys_page_size()));

    // stream size is (device_size / num_streams)
    LOGINFO("min_sys_chunk_size: {}, max_chunk_size: {}, is_hdd: {}, pdev_group: {}", in_bytes(min_sys_chunk_size),
            in_bytes(max_chunk_size), is_hdd, pdev_group);

    auto const max_num_chunks = HDD_MAX_CHUNKS;
    if (pdev_group == PhysicalDevGroup::DATA && is_hdd) {
        // Only Data blkstore will come here, and it will use up all the remaining chunks if device's reported stream
        // number is larger than system supported maximm;
        auto const remaining_num_chunks = max_num_chunks - s_num_chunks_created - m_mgr->num_sys_chunks();
        auto const max_number_of_streams = num_pdevs * m_primary_pdev_chunks_list[0].pdev->num_streams();
        m_num_chunks = std::min(static_cast< long unsigned int >(remaining_num_chunks), max_number_of_streams);
        m_num_chunks = sisl::round_down(m_num_chunks, num_pdevs);
        m_chunk_size = sisl::round_down(size / m_num_chunks, min_sys_chunk_size);
        LOGINFO("max_number_of_streams: {}, m_num_chunks: {}, m_chunk_size:{}", max_number_of_streams, m_num_chunks,
                m_chunk_size);

        HS_REL_ASSERT_LE(m_chunk_size, max_chunk_size);
    } else {
        if (is_stripe) {
            m_num_chunks = static_cast< uint32_t >(num_pdevs);
            uint32_t cnt{1};

            do {
                m_num_chunks = cnt * m_num_chunks;
                m_chunk_size = size / m_num_chunks;
                ++cnt;
            } while (m_chunk_size > max_chunk_size);
        } else {
            m_chunk_size = size;
            m_num_chunks = 1;
        }

        if (m_chunk_size % min_sys_chunk_size > 0) {
            m_chunk_size = sisl::round_up(m_chunk_size, min_sys_chunk_size);
            HS_LOG(INFO, device, "size of a chunk is resized to {}", in_bytes(m_chunk_size));
        }
    }

    // keep track of how many chunks has been created by non-HDD blkstore;
    s_num_chunks_created += m_num_chunks;

    HS_REL_ASSERT_LE(s_num_chunks_created, max_num_chunks, "num chunks should not exceed maximum supported!");

    LOGINFO("size of a chunk is {} is_stripe {} num chunks {}", in_bytes(m_chunk_size), is_stripe, m_num_chunks);
    if (m_chunk_size > max_chunk_size) {
        throw homestore::homestore_exception("invalid chunk size in init", homestore_error::invalid_chunk_size);
    }

    /* make size multiple of chunk size */
    size = m_chunk_size * m_num_chunks;
    // Create a new vdev in persistent area and get the block of it
    m_vb = mgr->alloc_vdev(context_size, nmirror, blk_size, m_num_chunks, context, size);

    for (auto i : boost::irange< uint32_t >(0, m_num_chunks)) {
        auto const pdev_ind = i % num_pdevs;

        // Create a chunk on selected physical device and add it to chunks in physdev list
        auto* chunk = create_dev_chunk(pdev_ind, nullptr, INVALID_CHUNK_ID);
        if (chunk == nullptr) {
            LOGINFO("could not allocate all the chunks. total chunk allocated {}, total space alloated is {}. and "
                    "requested size is {}",
                    i, in_bytes(i * m_chunk_size), in_bytes(size_in));
            HS_REL_ASSERT(0, "chunk can not be allocated");
            m_num_chunks = i;
            break;
        }

        // set the default chunk. It is used for HDD when volume can not allocate blkid from its stream
        if (!m_default_chunk || (m_default_chunk->chunk_id() > chunk->chunk_id())) { m_default_chunk = chunk; }

        LOGINFO("vdev name {}, chunk id {} chunk start offset {}, chunk size {}, pdev_ind: {} ", m_name,
                chunk->chunk_id(), chunk->start_offset(), in_bytes(chunk->size()), pdev_ind);

        m_free_streams.push_back(chunk);
        std::shared_ptr< BlkAllocator > ba =
            create_blk_allocator(allocator_type, m_blk_size, phys_page_size(), align_size(), m_chunk_size,
                                 m_auto_recovery, chunk->chunk_id(), true /* init */);

        // set initial value of "end of chunk offset";
        chunk->update_end_of_chunk(m_chunk_size);

        chunk->set_blk_allocator((nmirror > 0) ? ba : std::move(ba));
        m_primary_pdev_chunks_list[pdev_ind].chunks_in_pdev.push_back(chunk);

        // If we have mirror, create a map between chunk and its mirrored chunks
        if (nmirror > 0) {
            size_t next_ind = i;
            std::vector< PhysicalDevChunk* > vec;
            vec.reserve(nmirror);
            for (auto j : boost::irange< uint32_t >(0, nmirror)) {
                if ((++next_ind) == num_pdevs) { next_ind = 0; }
                auto* mchunk = create_dev_chunk(next_ind, ba, chunk->chunk_id());
                vec.push_back(mchunk);
            }
            m_mirror_chunks.emplace(std::make_pair(chunk, vec));
        }
    }

    for (const auto& pdev_chunk : m_primary_pdev_chunks_list) {
        m_selector->add_pdev(pdev_chunk.pdev);
    }
    reserve_stream(m_default_chunk->chunk_id());
}

/* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
VirtualDev::VirtualDev(DeviceManager* mgr, const char* name, vdev_info_block* vb, PhysicalDevGroup pdev_group,
                       blk_allocator_type_t allocator_type, bool recovery_init, bool auto_recovery,
                       vdev_high_watermark_cb_t hwm_cb) :
        m_name{name}, m_allocator_type{allocator_type}, m_metrics{name}, m_pdev_group{pdev_group} {
    init(mgr, vb, vb->blk_size, auto_recovery, std::move(hwm_cb));

    m_recovery_init = recovery_init;
    m_mgr->add_chunks(vb->vdev_id, [this](PhysicalDevChunk* chunk) {
        if (m_drive_iface == nullptr) { m_drive_iface = chunk->physical_dev_mutable()->drive_iface(); }
        add_chunk(chunk);
    });

    HS_LOG_ASSERT_EQ(vb->num_primary_chunks * (vb->num_mirrors + 1),
                     m_num_chunks); // Mirrors should be at least one less than device list.
    HS_LOG_ASSERT_EQ(vb->get_size(), vb->num_primary_chunks * m_chunk_size);
    reserve_stream(m_default_chunk->chunk_id());
}

void VirtualDev::reset_failed_state() {
    m_vb->set_failed(false);
    m_mgr->write_info_blocks();
}

void VirtualDev::add_chunk(PhysicalDevChunk* chunk) {
    HS_LOG(INFO, device, "vdev name {} Adding chunk {} from vdev id {} from pdev id = {}", m_name, chunk->chunk_id(),
           chunk->vdev_id(), chunk->physical_dev()->dev_id());
    std::lock_guard< decltype(m_mgmt_mutex) > lock{m_mgmt_mutex};

    if (chunk->primary_chunk()) {
        add_mirror_chunk(chunk);
    } else {
        ++m_num_chunks;
        add_primary_chunk(chunk);
    }
}

PhysicalDevChunk* VirtualDev::get_next_chunk(uint32_t dev_id, uint32_t chunk_id) {
    if ((chunk_id + 1) < m_primary_pdev_chunks_list[dev_id].chunks_in_pdev.size()) {
        // next chunk is within same dev;
        ++chunk_id;
    } else {
        // move next dev
        dev_id = ((dev_id + 1) % m_primary_pdev_chunks_list.size());
        chunk_id = 0;
    }
    return m_primary_pdev_chunks_list[dev_id].chunks_in_pdev[chunk_id];
}

folly::Future< bool > VirtualDev::async_format() {
    static thread_local std::vector< folly::Future< bool > > s_futs;
    s_futs.clear();

    for (size_t dev_ind{0}; dev_ind < m_primary_pdev_chunks_list.size(); ++dev_ind) {
        for (auto* pchunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
            auto* pdev = pchunk->physical_dev_mutable();
            LOGINFO("writing zero for chunk: {}, size: {}, offset: {}", pchunk->chunk_id(), in_bytes(pchunk->size()),
                    pchunk->start_offset());
            s_futs.emplace_back(pdev->async_write_zero(pchunk->size(), pchunk->start_offset()));

            auto mchunks_list = m_mirror_chunks[pchunk];
            for (auto& mchunk : mchunks_list) {
                auto* m_pdev = mchunk->physical_dev_mutable();
                LOGINFO("writing zero for mirror chunk: {}, size: {}, offset: {}", mchunk->chunk_id(),
                        in_bytes(mchunk->size()), mchunk->start_offset());
                s_futs.emplace_back(m_pdev->async_write_zero(mchunk->size(), mchunk->start_offset()));
            }
        }
    }
    return folly::collectAllUnsafe(s_futs).thenTry([](auto&&) { return folly::makeFuture< bool >(true); });
}

stream_info_t VirtualDev::alloc_stream(uint64_t size) {
    std::unique_lock< std::mutex > lk(m_free_streams_lk);
    stream_info_t stream_info;
    while (!m_free_streams.empty() && (size > 0)) {
        auto* chunk = m_free_streams.back();
        m_free_streams.pop_back();
        ++stream_info.num_streams;
        stream_info.chunk_list.push_back(reinterpret_cast< void* >(chunk));
        stream_info.stream_id.push_back(chunk->chunk_id());
        // either size becomes 0 or keep finding next chunk to get enough space;
        size -= std::min(size, stream_size());
    }
    return stream_info;
}

void VirtualDev::free_stream(const stream_info_t& stream_info) {
    std::unique_lock< std::mutex > lk(m_free_streams_lk);
    for (auto* chunk_ptr : stream_info.chunk_list) {
        m_free_streams.push_back(reinterpret_cast< PhysicalDevChunk* >(chunk_ptr));
    }
}

stream_info_t VirtualDev::reserve_stream(const stream_id_t* id_list, uint32_t nstreams) {
    stream_info_t stream_info;
    if (nstreams == 0) { return stream_info; }
    std::unique_lock< std::mutex > lk(m_free_streams_lk);
    for (uint32_t i{0}; i < nstreams; ++i) {
        auto const id = id_list[i];
        for (auto it = std::begin(m_free_streams); it != std::end(m_free_streams);) {
            if ((*it)->chunk_id() == id) {
                ++stream_info.num_streams;
                stream_info.stream_id.push_back(id);
                stream_info.chunk_list.push_back(reinterpret_cast< void* >(*it));
                it = m_free_streams.erase(it);
                break;
            } else {
                ++it;
            }
        }
    }

    HS_REL_ASSERT_EQ(nstreams, stream_info.stream_id.size(), "could not find stream with this id");
    return stream_info;
}

void VirtualDev::reserve_stream(stream_id_t id) {
    for (auto it = m_free_streams.begin(); it != m_free_streams.end();) {
        if ((*it)->chunk_id() == id) {
            it = m_free_streams.erase(it);
            break;
        } else {
            ++it;
        }
    }
}

uint32_t VirtualDev::num_streams() const { return num_chunks(); }

uint64_t VirtualDev::stream_size() const { return chunk_size(); }

/*std::shared_ptr< blkalloc_cp > VirtualDev::attach_prepare_cp(const std::shared_ptr< blkalloc_cp >& cur_ba_cp) {
    return (PhysicalDevChunk::attach_prepare_cp(cur_ba_cp));
}*/

bool VirtualDev::is_blk_alloced(const BlkId& blkid) const {
    const PhysicalDevChunk* primary_chunk = m_mgr->get_chunk(blkid.get_chunk_num());
    return (primary_chunk->blk_allocator()->is_blk_alloced(blkid));
}

BlkAllocStatus VirtualDev::commit_blk(const BlkId& blkid) {
    PhysicalDevChunk* primary_chunk = m_mgr->get_chunk_mutable(blkid.get_chunk_num());
    HS_LOG(DEBUG, device, "alloc_on_disk: bid {}", blkid.to_string());
    return primary_chunk->blk_allocator_mutable()->alloc_on_disk(blkid);
}

BlkAllocStatus VirtualDev::alloc_contiguous_blk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                                BlkId* out_blkid) {
    BlkAllocStatus ret;
    try {
        static thread_local std::vector< BlkId > blkid{};
        blkid.clear();
        HS_DBG_ASSERT_EQ(hints.is_contiguous, true);
        ret = alloc_blk(nblks, hints, blkid);
        if (ret == BlkAllocStatus::SUCCESS) {
            HS_REL_ASSERT_EQ(blkid.size(), 1, "out blkid more than 1 entries({}) will lead to blk leak!", blkid.size());
            *out_blkid = std::move(blkid.front());
        } else {
            HS_DBG_ASSERT_EQ(blkid.size(), 0);
        }
    } catch (const std::exception& e) {
        ret = BlkAllocStatus::FAILED;
        HS_DBG_ASSERT(0, "{}", e.what());
    }
    return ret;
}

BlkAllocStatus VirtualDev::alloc_blk(uint32_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) {
    size_t start_idx = out_blkid.size();
    while (nblks != 0) {
        const blk_count_t nblks_op = std::min(BlkId::max_blks_in_op(), s_cast< blk_count_t >(nblks));
        const auto ret = do_alloc_blk(nblks_op, hints, out_blkid);
        if (ret != BlkAllocStatus::SUCCESS) {
            for (auto i = start_idx; i < out_blkid.size(); ++i) {
                free_blk(out_blkid[i]);
                out_blkid.erase(out_blkid.begin() + start_idx, out_blkid.end());
            }
            return ret;
        }
        nblks -= nblks_op;
    }
    return BlkAllocStatus::SUCCESS;
}

BlkAllocStatus VirtualDev::do_alloc_blk(blk_count_t nblks, const blk_alloc_hints& hints,
                                        std::vector< BlkId >& out_blkid) {
    try {
        PhysicalDevChunk* preferred_chunk = nullptr;
        auto* stream_info = (stream_info_t*)(hints.stream_info);
        uint32_t try_streams = 0;
        if (stream_info && (stream_info->num_streams != 0)) { try_streams = stream_info->num_streams; }

        BlkAllocStatus status = BlkAllocStatus::FAILED;

        while (try_streams != 0) {
            preferred_chunk = reinterpret_cast< PhysicalDevChunk* >(stream_info->chunk_list[stream_info->stream_cur]);
            if (preferred_chunk) {
                // try to allocate from the preferred chunk
                status = alloc_blk_from_chunk(nblks, hints, out_blkid, preferred_chunk);
                if (status == BlkAllocStatus::SUCCESS) { return status; };
            }
            stream_info->stream_cur = (stream_info->stream_cur + 1) % stream_info->num_streams;
            --try_streams;
        }

        if (stream_info) {
            // try to allocate from the default chunk
            status = alloc_blk_from_chunk(nblks, hints, out_blkid, m_default_chunk);
            if (status == BlkAllocStatus::SUCCESS) {
                COUNTER_INCREMENT(m_metrics, default_chunk_allocation_cnt, 1);
                return status;
            }
        }

        if (m_pdev_group == PhysicalDevGroup::DATA) { COUNTER_INCREMENT(m_metrics, random_chunk_allocation_cnt, 1); }

        // try to allocate from the other chunks now
        // First select a device to allocate from
        uint32_t chunk_num, start_chunk_num;
        uint32_t dev_ind{0};
        dev_ind = (hints.dev_id_hint == INVALID_DEV_ID) ? m_selector->select(hints) : uint32_cast(hints.dev_id_hint);

        // Pick a physical chunk based on physDevId.
        // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple
        // chunks. In that case just using physDevId as chunk number is not right strategy.
        uint32_t start_dev_ind = dev_ind;
        do {
            for (auto& chunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
                status = alloc_blk_from_chunk(nblks, hints, out_blkid, chunk);
                if (status == BlkAllocStatus::SUCCESS || !hints.can_look_for_other_chunk) { break; }
            }

            if (status == BlkAllocStatus::SUCCESS || !hints.can_look_for_other_chunk) { break; }
            dev_ind = uint32_cast((dev_ind + 1) % m_primary_pdev_chunks_list.size());
        } while (dev_ind != start_dev_ind);

        if (status != BlkAllocStatus::SUCCESS) {
            LOGERROR("nblks={} failed to alloc after trying to allo on every chunks {} and devices {}.", nblks);
            COUNTER_INCREMENT(m_metrics, vdev_num_alloc_failure, 1);
        }

        return status;
    } catch (const std::exception& e) {
        LOGERROR("exception happened {}", e.what());
        assert(false);
        return BlkAllocStatus::FAILED;
    }
}

BlkAllocStatus VirtualDev::alloc_blk_from_chunk(blk_count_t nblks, const blk_alloc_hints& hints,
                                                std::vector< BlkId >& out_blkid, PhysicalDevChunk* chunk) {
#ifdef _PRERELEASE
    if (auto const fake_status =
            iomgr_flip::instance()->get_test_flip< uint32_t >("blk_allocation_flip", nblks, chunk->vdev_id())) {
        return static_cast< BlkAllocStatus >(fake_status.get());
    }
#endif
    static thread_local std::vector< BlkId > chunk_blkid{};
    chunk_blkid.clear();
    auto status = chunk->blk_allocator_mutable()->alloc(nblks, hints, chunk_blkid);
    if (status == BlkAllocStatus::PARTIAL) {
        // free partial result
        for (auto const b : chunk_blkid) {
            auto const ret = chunk->blk_allocator_mutable()->free_on_realtime(b);
            HS_REL_ASSERT(ret, "failed to free on realtime");
        }
        chunk->blk_allocator_mutable()->free(chunk_blkid);
        status = BlkAllocStatus::FAILED;
    } else if (status == BlkAllocStatus::SUCCESS) {
        // append chunk blocks to out blocks
        out_blkid.insert(std::end(out_blkid), std::make_move_iterator(std::begin(chunk_blkid)),
                         std::make_move_iterator(std::end(chunk_blkid)));
    }
    return status;
}

bool VirtualDev::free_on_realtime(const BlkId& b) {
    PhysicalDevChunk* chunk = m_mgr->get_chunk_mutable(b.get_chunk_num());
    return chunk->blk_allocator_mutable()->free_on_realtime(b);
}

void VirtualDev::free_blk(const BlkId& b) {
    PhysicalDevChunk* chunk = m_mgr->get_chunk_mutable(b.get_chunk_num());
    chunk->blk_allocator_mutable()->free(b);
}

void VirtualDev::recovery_done() {
    for (auto& pcm : m_primary_pdev_chunks_list) {
        for (auto& pchunk : pcm.chunks_in_pdev) {
            pchunk->blk_allocator_mutable()->inited();
            auto mchunks_list = m_mirror_chunks[pchunk];
            for (auto& mchunk : mchunks_list) {
                mchunk->blk_allocator_mutable()->inited();
            }
        }
    }
}

////////////////////////// async write section //////////////////////////////////
folly::Future< bool > VirtualDev::async_write(const char* buf, uint32_t size, const BlkId& bid, bool part_of_batch) {
    PhysicalDevChunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    return async_write_internal(buf, size, chunk->physical_dev_mutable(), chunk, dev_offset, part_of_batch);
}

folly::Future< bool > VirtualDev::async_writev(const iovec* iov, const int iovcnt, const BlkId& bid,
                                               bool part_of_batch) {
    PhysicalDevChunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    auto const size = get_len(iov, iovcnt);
    return async_writev_internal(iov, iovcnt, size, chunk->physical_dev_mutable(), chunk, dev_offset, part_of_batch);
}

folly::Future< bool > VirtualDev::async_write_internal(const char* buf, uint32_t size, PhysicalDev* pdev,
                                                       PhysicalDevChunk* pchunk, uint64_t dev_offset,
                                                       bool part_of_batch) {
    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->dev_id(), dev_offset);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_write(buf, size, dev_offset, part_of_batch);
}

folly::Future< bool > VirtualDev::async_writev_internal(const iovec* iov, int iovcnt, uint64_t size, PhysicalDev* pdev,
                                                        PhysicalDevChunk* pchunk, uint64_t dev_offset,
                                                        bool part_of_batch) {
    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->dev_id(), dev_offset);
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }
    return pdev->async_writev(iov, iovcnt, size, dev_offset, part_of_batch);
}

////////////////////////// sync write section //////////////////////////////////
void VirtualDev::sync_write(const char* buf, uint32_t size, const BlkId& bid) {
    PhysicalDevChunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    chunk->physical_dev_mutable()->sync_write(buf, size, dev_offset);
    if (num_mirrors()) { write_nmirror(buf, size, chunk, dev_offset); }
}

void VirtualDev::sync_writev(const iovec* iov, int iovcnt, const BlkId& bid) {
    PhysicalDevChunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    pdev->sync_writev(iov, iovcnt, size, dev_offset);
    if (num_mirrors()) { writev_nmirror(iov, iovcnt, size, chunk, dev_offset); }
}

void VirtualDev::sync_write_internal(const char* buf, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                     uint64_t dev_offset) {
    pdev->sync_write(buf, size, dev_offset);
    if (num_mirrors()) { write_nmirror(buf, size, pchunk, dev_offset); }
}

void VirtualDev::sync_writev_internal(const iovec* iov, int iovcnt, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                      uint64_t dev_offset) {
    auto const size = get_len(iov, iovcnt);
    pdev->sync_writev(iov, iovcnt, size, dev_offset);
    if (num_mirrors()) { writev_nmirror(iov, iovcnt, size, pchunk, dev_offset); }
}

////////////////////////////////// async read section ///////////////////////////////////////////////
folly::Future< bool > VirtualDev::async_read(char* buf, uint64_t size, const BlkId& bid, bool part_of_batch) {
    PhysicalDevChunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    return pchunk->physical_dev_mutable()->async_read(buf, size, dev_offset, part_of_batch);
}

folly::Future< bool > VirtualDev::async_readv(iovec* iovs, int iovcnt, uint64_t size, const BlkId& bid,
                                              bool part_of_batch) {
    PhysicalDevChunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    return pchunk->physical_dev_mutable()->async_readv(iovs, iovcnt, size, dev_offset, part_of_batch);
}

////////////////////////////////////////// sync read section ////////////////////////////////////////////
void VirtualDev::sync_read(char* buf, uint32_t size, const BlkId& bid) {
    PhysicalDevChunk* pchunk;
    uint64_t const dev_offset = to_dev_offset(bid, &pchunk);
    sync_read_internal(buf, size, pchunk->physical_dev_mutable(), pchunk, dev_offset);
}

void VirtualDev::sync_readv(iovec* iov, int iovcnt, const BlkId& bid) {
    PhysicalDevChunk* chunk;
    uint64_t const dev_offset = to_dev_offset(bid, &chunk);
    auto const size = get_len(iov, iovcnt);
    auto* pdev = chunk->physical_dev_mutable();

    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(dev_offset, pdev->align_size()))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    sync_readv_internal(iov, iovcnt, size, pdev, chunk, dev_offset);
}

void VirtualDev::sync_read_internal(char* buf, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                    uint64_t dev_offset) {
    try {
        pdev->sync_read(buf, size, dev_offset);
    } catch (std::exception& e) {
        if (num_mirrors()) {
            sync_read_mirrors(buf, size, pchunk, dev_offset);
        } else {
            throw e;
        }
    }
}

void VirtualDev::sync_readv_internal(iovec* iov, int iovcnt, uint32_t size, PhysicalDev* pdev, PhysicalDevChunk* pchunk,
                                     uint64_t dev_offset) {
    try {
        pdev->sync_readv(iov, iovcnt, size, dev_offset);
    } catch (std::exception& e) {
        if (num_mirrors()) {
            sync_readv_mirrors(iov, iovcnt, size, pchunk, dev_offset);
        } else {
            throw e;
        }
    }
}

void VirtualDev::sync_read_mirrors(char* buf, uint32_t size, PhysicalDevChunk* pchunk, uint64_t dev_offset) {
    uint64_t const primary_chunk_offset = dev_offset - pchunk->start_offset();
    const auto& chunks = m_mirror_chunks.find(pchunk)->second;
    for (auto* mchunk : chunks) {
        const uint64_t dev_offset = mchunk->start_offset() + primary_chunk_offset;
        auto* pdev = mchunk->physical_dev_mutable();

        try {
            pdev->sync_read(buf, size, dev_offset);
            break;
        } catch (std::exception& e) {
            if (mchunk == chunks.back()) {
                throw e;
            } else {
                continue; /* Read from other device */
            }
        }
    }
}

void VirtualDev::sync_readv_mirrors(iovec* iov, int iovcnt, uint32_t size, PhysicalDevChunk* pchunk,
                                    uint64_t dev_offset) {
    uint64_t const primary_chunk_offset = dev_offset - pchunk->start_offset();
    const auto& chunks = m_mirror_chunks.find(pchunk)->second;
    for (auto* mchunk : chunks) {
        const uint64_t dev_offset = mchunk->start_offset() + primary_chunk_offset;
        auto* pdev = mchunk->physical_dev_mutable();

        try {
            pdev->sync_readv(iov, iovcnt, size, dev_offset);
            break;
        } catch (std::exception& e) {
            if (mchunk == chunks.back()) {
                throw e;
            } else {
                continue; /* Read from other device */
            }
        }
    }
}

folly::Future< bool > VirtualDev::queue_fsync_pdevs() {
    HS_DBG_ASSERT_EQ(DeviceManager::is_hdd_direct_io_mode(), false, "Not expect to do fsync in DIRECT_IO_MODE.");

    assert(!m_primary_pdev_chunks_list.empty());
    if (m_primary_pdev_chunks_list.size() == 1) {
        auto* pdev = m_primary_pdev_chunks_list[0].pdev;
        HS_LOG(TRACE, device, "Flushing pdev {}", pdev->get_devname());
        return pdev->queue_fsync();
    } else {
        static thread_local std::vector< folly::Future< bool > > s_futs;
        s_futs.clear();
        for (auto& pdev_chunk : m_primary_pdev_chunks_list) {
            auto* pdev = pdev_chunk.pdev;
            HS_LOG(TRACE, device, "Flushing pdev {}", pdev->get_devname());
            s_futs.emplace_back(pdev->queue_fsync());
        }
        return folly::collectAllUnsafe(s_futs).thenTry([](auto&&) { return folly::makeFuture< bool >(true); });
    }
}

void VirtualDev::submit_batch() { m_drive_iface->submit_batch(); }

void VirtualDev::get_vb_context(const sisl::blob& ctx_data) const { m_mgr->get_vb_context(m_vb->vdev_id, ctx_data); }

void VirtualDev::update_vb_context(const sisl::blob& ctx_data) { m_mgr->update_vb_context(m_vb->vdev_id, ctx_data); }

uint64_t VirtualDev::available_blks() const {
    uint64_t avl_blks{0};
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (uint32_t chunk_indx = 0; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            const auto* chunk = m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx];
            avl_blks += chunk->blk_allocator()->available_blks();
        }
    }
    return avl_blks;
}

uint64_t VirtualDev::used_size() const {
    uint64_t alloc_cnt{0};
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (uint32_t chunk_indx = 0; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            const auto* chunk = m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx];
            alloc_cnt += chunk->blk_allocator()->get_used_blks();
        }
    }
    return (alloc_cnt * block_size());
}

void VirtualDev::expand(const uint32_t addln_size) {}

void VirtualDev::rm_device() {
    for (auto& pcm : m_primary_pdev_chunks_list) {
        for (auto& c : pcm.chunks_in_pdev) {
            m_mgr->free_chunk(c);
        }
    }

    for (auto& v : m_mirror_chunks) {
        for (auto& c : v.second) {
            m_mgr->free_chunk(c);
        }
    }

    m_mgr->free_vdev(m_vb);
}

void VirtualDev::cp_flush() {
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (size_t chunk_indx{0}; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            auto* chunk = m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx];
            chunk->cp_flush();
        }
    }
}
/*void VirtualDev::blkalloc_cp_start(const std::shared_ptr< blkalloc_cp >& ba_cp) {
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (size_t chunk_indx{0}; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            auto* chunk = m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx];
            chunk->cp_start(ba_cp);
        }
    }
}*/

uint32_t VirtualDev::block_size() const { return m_vb->blk_size; }
uint32_t VirtualDev::num_mirrors() const { return m_vb->num_mirrors; }

/* Get status for all chunks */
nlohmann::json VirtualDev::get_status(const int log_level) const {
    nlohmann::json j;
    try {
        for (const auto& pdev_chunks : m_primary_pdev_chunks_list) {
            auto const chunk_list = pdev_chunks.chunks_in_pdev;
            for (const auto& chunk : chunk_list) {
                nlohmann::json chunk_j;
                chunk_j["ChunkInfo"] = chunk->get_status(log_level);
                if (chunk->blk_allocator() != nullptr) {
                    chunk_j["BlkallocInfo"] = chunk->blk_allocator()->get_status(log_level);
                }
                j[std::to_string(chunk->chunk_id())] = chunk_j;
            }
        }
    } catch (const std::exception& e) { LOGERROR("exception happened {}", e.what()); }
    return j;
}

///////////////////////// VirtualDev Private Methods /////////////////////////////
void VirtualDev::write_nmirror(const char* buf, uint32_t size, PhysicalDevChunk* chunk, uint64_t dev_offset_in) {
    uint64_t dev_offset = dev_offset_in;
    const uint64_t primary_chunk_offset = dev_offset - chunk->start_offset();

    // Write to the mirror as well
    for (auto i : boost::irange< uint32_t >(0, num_mirrors())) {
        for (auto* mchunk : m_mirror_chunks.find(chunk)->second) {
            dev_offset = mchunk->start_offset() + primary_chunk_offset;

            // We do not support async mirrored writes yet.
            mchunk->physical_dev_mutable()->sync_write(buf, size, dev_offset);
        }
    }
}

void VirtualDev::writev_nmirror(const iovec* iov, int iovcnt, uint32_t size, PhysicalDevChunk* chunk,
                                uint64_t dev_offset_in) {
    uint64_t dev_offset = dev_offset_in;
    const uint64_t primary_chunk_offset = dev_offset - chunk->start_offset();

    // Write to the mirror as well
    for (auto i : boost::irange< uint32_t >(0, num_mirrors())) {
        for (auto* mchunk : m_mirror_chunks.find(chunk)->second) {
            dev_offset = mchunk->start_offset() + primary_chunk_offset;

            // We do not support async mirrored writes yet.
            mchunk->physical_dev_mutable()->sync_writev(iov, iovcnt, size, dev_offset);
        }
    }
}

BlkAllocStatus VirtualDev::create_debug_bm() {
    try {
        for (auto& pdev_chunks : m_primary_pdev_chunks_list) {
            auto chunk_list = pdev_chunks.chunks_in_pdev;
            for (auto& chunk : chunk_list) {
                chunk->blk_allocator_mutable()->create_debug_bm();
            }
        }
        return BlkAllocStatus::SUCCESS;

    } catch (const std::exception& e) {
        LOGERROR("exception happened {}", e.what());
        return BlkAllocStatus::FAILED;
    }
}

/* Update debug bitmap for a given BlkId */
BlkAllocStatus VirtualDev::update_debug_bm(const BlkId& bid) {
    try {
        PhysicalDevChunk* chunk = nullptr;
        const uint64_t dev_offset = to_dev_offset(bid, &chunk);
        chunk->blk_allocator_mutable()->update_debug_bm(bid);
        return BlkAllocStatus::SUCCESS;

    } catch (const std::exception& e) {
        LOGERROR("Update debug bitmap hit exception {}", e.what());
        return BlkAllocStatus::FAILED;
    }
}

/* Verify debug bitmap for all chunks */
BlkAllocStatus VirtualDev::verify_debug_bm(const bool free_debug_bm) {
    try {
        for (auto& pdev_chunks : m_primary_pdev_chunks_list) {
            auto chunk_list = pdev_chunks.chunks_in_pdev;
            for (auto& chunk : chunk_list) {
                if (chunk->blk_allocator_mutable()->verify_debug_bm(free_debug_bm) == false) {
                    LOGERROR("Verify bitmap failure for chunk {}", static_cast< void* >(chunk));
                    return BlkAllocStatus::FAILED;
                } else {
                    LOGDEBUG("Verify bitmap success for chunk {}", static_cast< void* >(chunk));
                }
            }
        }
        return BlkAllocStatus::SUCCESS;
    } catch (const std::exception& e) {
        LOGERROR("exception happened {}", e.what());
        return BlkAllocStatus::FAILED;
    }
}

/* Adds a primary chunk to the chunk list in pdev */
void VirtualDev::add_primary_chunk(PhysicalDevChunk* chunk) {
    auto const pdev_id = chunk->physical_dev()->dev_id();

    if (m_chunk_size == 0) {
        m_chunk_size = chunk->size();
    } else {
        HS_DBG_ASSERT_EQ(m_chunk_size, chunk->size());
    }

    if (!m_default_chunk || (m_default_chunk->chunk_id() > chunk->chunk_id())) { m_default_chunk = chunk; }

    {
        std::unique_lock< std::mutex > lk(m_free_streams_lk);
        m_free_streams.push_back(chunk);
    }
    pdev_chunk_map* found_pcm = nullptr;
    for (auto& pcm : m_primary_pdev_chunks_list) {
        if (pcm.pdev->dev_id() == pdev_id) {
            found_pcm = &pcm;
            break;
        }
    }

    if (found_pcm) {
        found_pcm->chunks_in_pdev.push_back(chunk);
    } else {
        // Have not seen the pdev before, so add the chunk and also add it to device selector
        pdev_chunk_map pcm;
        pcm.pdev = m_mgr->get_pdev(pdev_id);
        pcm.chunks_in_pdev.push_back(chunk);

        m_primary_pdev_chunks_list.push_back(pcm);
        m_selector->add_pdev(pcm.pdev);
    }

    auto const max_chunk_size = MAX_DATA_CHUNK_SIZE(m_blk_size);
    HS_DBG_ASSERT_LE(m_chunk_size, max_chunk_size);
    std::shared_ptr< BlkAllocator > ba =
        create_blk_allocator(m_allocator_type, block_size(), phys_page_size(), align_size(), m_chunk_size,
                             m_auto_recovery, chunk->chunk_id(), m_recovery_init);
    chunk->set_blk_allocator(ba);
    if (!m_recovery_init) { chunk->recover(); }

    /* set the same blk allocator to other mirror chunks */
    auto const itr_pair = m_mirror_chunks.emplace(chunk, std::vector< PhysicalDevChunk* >{});
    if (itr_pair.second) {
        // Not found, just created a new entry
    } else {
        for (auto* chunk : itr_pair.first->second) {
            chunk->set_blk_allocator(ba);
        }
    }
}

void VirtualDev::add_mirror_chunk(PhysicalDevChunk* chunk) {
    auto const pdev_id = chunk->physical_dev()->dev_id();
    auto* pchunk = chunk->primary_chunk_mutable();

    if (m_chunk_size == 0) {
        m_chunk_size = chunk->size();
    } else {
        HS_DBG_ASSERT_EQ(m_chunk_size, chunk->size());
    }

    // Try to find the parent chunk in the map
    auto const itr_pair = m_mirror_chunks.emplace(chunk, std::vector< PhysicalDevChunk* >{});
    itr_pair.first->second.emplace_back(chunk);
    if (itr_pair.second) {
        // Not found, just created a new entry
    } else {
        // set block allocator
        itr_pair.first->second.back()->set_blk_allocator(pchunk->blk_allocator_mutable());
    }
}

PhysicalDevChunk* VirtualDev::create_dev_chunk(uint32_t pdev_ind, const std::shared_ptr< BlkAllocator >& ba,
                                               uint32_t primary_id) {
    auto* pdev = m_primary_pdev_chunks_list[pdev_ind].pdev;
    PhysicalDevChunk* chunk = m_mgr->alloc_chunk(pdev, m_vb->vdev_id, m_chunk_size, primary_id);
    if (chunk) {
        HS_LOG(DEBUG, device, "Allocating new chunk for vdev_id = {} pdev_id = {} chunk: {}", m_vb->get_vdev_id(),
               pdev->dev_id(), chunk->to_string());
        chunk->set_blk_allocator(ba);
    }

    return chunk;
}

uint64_t VirtualDev::to_dev_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const {
    *chunk = m_mgr->get_chunk_mutable(glob_uniq_id.get_chunk_num());
    return uint64_cast(glob_uniq_id.get_blk_num()) * block_size() + uint64_cast((*chunk)->start_offset());
}

uint32_t VirtualDev::align_size() const { return m_primary_pdev_chunks_list.front().pdev->align_size(); }
uint32_t VirtualDev::phys_page_size() const { return m_primary_pdev_chunks_list.front().pdev->page_size(); }

uint32_t VirtualDev::atomic_page_size() const { return m_primary_pdev_chunks_list.front().pdev->atomic_page_size(); }

} // namespace homestore
