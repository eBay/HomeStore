//
// Created by Kadayam, Hari on 08/11/17.
//
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

#include "api/meta_interface.hpp"
#include "device.h"
#include "engine/blkalloc/blk_allocator.h"
#include "engine/blkalloc/varsize_blk_allocator.h"
#include "engine/common/error.h"
#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/blkalloc/blkalloc_cp.hpp"
#include "engine/homestore_base.hpp"
#include "test_common/homestore_test_common.hpp"
#include "virtual_dev.hpp"

SISL_LOGGING_DECL(device)

namespace homestore {

uint32_t VirtualDev::s_num_chunks_created{0};

void VirtualDev::static_process_completions(const int64_t res, uint8_t* cookie) {
    boost::intrusive_ptr< virtualdev_req > vd_req{reinterpret_cast< virtualdev_req* >(cookie), false};

    HS_DBG_ASSERT_EQ(vd_req->version, 0xDEAD);

    if ((vd_req->err == no_error) && (res != 0)) {
        LOGERROR("seeing error on request id {} error {}", vd_req->request_id, res);
        /* TODO: it should have more specific errors */
        vd_req->err = std::make_error_condition(std::io_errc::stream);
    }

#ifdef _PRERELEASE
    if (homestore_flip->test_flip("io_write_comp_error_flip")) { vd_req->err = write_failed; }

    if (homestore_flip->test_flip("io_read_comp_error_flip")) { vd_req->err = read_failed; }
#endif

    if (!vd_req->format && vd_req->chunk) {
        auto* const pdev{vd_req->chunk->get_physical_dev_mutable()};
        if (vd_req->err) {
            COUNTER_INCREMENT_IF_ELSE(pdev->get_metrics(), vd_req->is_read, drive_read_errors, drive_write_errors, 1);
            pdev->device_manager_mutable()->handle_error(pdev);
        } else {
            HISTOGRAM_OBSERVE_IF_ELSE(pdev->get_metrics(), vd_req->is_read, drive_read_latency, drive_write_latency,
                                      get_elapsed_time_us(vd_req->io_start_time));
        }
    }

    if (vd_req->cb) { vd_req->cb(vd_req); }

    // NOTE: Beyond this point vd_req could be freed by the callback. So once callback is made,
    // DO NOT ACCESS vd_req beyond this point.
}

static std::shared_ptr< BlkAllocator > create_blk_allocator(const blk_allocator_type_t btype, const uint32_t vpage_sz,
                                                            const uint32_t ppage_sz, const uint32_t align_sz,
                                                            const uint64_t size, const bool is_auto_recovery,
                                                            const uint32_t unique_id, const bool is_init) {
    switch (btype) {
    case blk_allocator_type_t::fixed: {
        BlkAllocConfig cfg{vpage_sz, align_sz, size, std::string{"fixed_chunk_"} + std::to_string(unique_id)};
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< FixedBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::varsize: {
        VarsizeBlkAllocConfig cfg{vpage_sz, ppage_sz, align_sz, size,
                                  std::string("varsize_chunk_") + std::to_string(unique_id)};
        HS_DBG_ASSERT_EQ((size % MIN_DATA_CHUNK_SIZE(ppage_sz)), 0);
        cfg.set_auto_recovery(is_auto_recovery);
        return std::make_shared< VarsizeBlkAllocator >(cfg, is_init, unique_id);
    }
    case blk_allocator_type_t::none:
    default:
        return nullptr;
    }
}

void VirtualDev::init(DeviceManager* mgr, vdev_info_block* vb, vdev_comp_cb_t cb, const uint32_t page_size,
                      const bool auto_recovery, vdev_high_watermark_cb_t hwm_cb) {
    m_mgr = mgr;
    m_vb = vb;
    m_comp_cb = std::move(cb);
    m_chunk_size = 0;
    m_num_chunks = 0;
    m_pagesz = page_size;
    m_selector = std::make_unique< RoundRobinDeviceSelector >();
    m_recovery_init = false;
    m_auto_recovery = auto_recovery;
    m_hwm_cb = std::move(hwm_cb);
}

/* Create a new virtual dev for these parameters */
VirtualDev::VirtualDev(DeviceManager* mgr, const char* name, const PhysicalDevGroup pdev_group,
                       const blk_allocator_type_t allocator_type, const uint64_t context_size, const uint32_t nmirror,
                       const bool is_stripe, const uint32_t page_size, vdev_comp_cb_t cb, char* blob,
                       const uint64_t size_in, const bool auto_recovery, vdev_high_watermark_cb_t hwm_cb) :
        m_name{name},
        m_allocator_type{allocator_type},
        m_metrics{name},
        m_pdev_group{pdev_group} {
    init(mgr, nullptr, std::move(cb), page_size, auto_recovery, std::move(hwm_cb));

    const auto pdev_list = m_mgr->get_devices(pdev_group);
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
        HS_REL_ASSERT((mapped_stream_size == 0 || mapped_stream_size == pdev->get_raw_stream_size()), "stream size {}",
                      pdev->get_raw_stream_size());
        mapped_stream_size = pdev->get_raw_stream_size();
    }

    // check that all pdevs valid and of same type
    HS_DBG_ASSERT_EQ(m_primary_pdev_chunks_list.size(), pdev_list.size());
    auto size{size_in};
    const auto num_pdevs = m_primary_pdev_chunks_list.size();
    // Now its time to allocate chunks as needed
    HS_LOG_ASSERT_LT(nmirror, num_pdevs); // Mirrors should be at least 1 less than device list

    const auto max_chunk_size = MAX_DATA_CHUNK_SIZE(m_pagesz);
    const auto min_sys_chunk_size =
        MIN_DATA_CHUNK_SIZE(std::max(m_pagesz, m_primary_pdev_chunks_list[0].pdev->get_page_size()));

    // stream size is (device_size / num_streams)
    LOGINFO("min_sys_chunk_size: {}, max_chunk_size: {}, is_hdd: {}, pdev_group: {}", min_sys_chunk_size,
            max_chunk_size, is_hdd, pdev_group);

    const auto max_num_chunks = HDD_MAX_CHUNKS;
    if (pdev_group == PhysicalDevGroup::DATA && is_hdd) {
        // Only Data blkstore will come here, and it will use up all the remaining chunks if device's reported stream
        // number is larger than system supported maximm;
        const auto remaining_num_chunks = max_num_chunks - s_num_chunks_created - m_mgr->num_sys_chunks();
        const auto max_number_of_streams = num_pdevs * m_primary_pdev_chunks_list[0].pdev->get_num_streams();
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
            HS_LOG(INFO, device, "size of a chunk is resized to {}", m_chunk_size);
        }
    }

    // keep track of how many chunks has been created by non-HDD blkstore;
    s_num_chunks_created += m_num_chunks;

    HS_REL_ASSERT_LE(s_num_chunks_created, max_num_chunks, "num chunks should not exceed maximum supported!");

    LOGINFO("size of a chunk is {} is_stripe {} num chunks {}", m_chunk_size, is_stripe, m_num_chunks);
    if (m_chunk_size > max_chunk_size) {
        throw homestore::homestore_exception("invalid chunk size in init", homestore_error::invalid_chunk_size);
    }

    /* make size multiple of chunk size */
    size = m_chunk_size * m_num_chunks;
    // Create a new vdev in persistent area and get the block of it
    m_vb = mgr->alloc_vdev(context_size, nmirror, page_size, m_num_chunks, blob, size);

    for (auto i : boost::irange< uint32_t >(0, m_num_chunks)) {
        const auto pdev_ind{i % num_pdevs};

        // Create a chunk on selected physical device and add it to chunks in physdev list
        auto* chunk{create_dev_chunk(pdev_ind, nullptr, INVALID_CHUNK_ID)};
        if (chunk == nullptr) {
            LOGINFO("could not allocate all the chunks. total chunk allocated {}, total space alloated is {}. and "
                    "requested size is {}",
                    i, (i * m_chunk_size), size_in);
            HS_REL_ASSERT(0, "chunk can not be allocated");
            m_num_chunks = i;
            break;
        }

        // set the default chunk. It is used for HDD when volume can not allocate blkid from its stream
        if (!m_default_chunk || (m_default_chunk->get_chunk_id() > chunk->get_chunk_id())) { m_default_chunk = chunk; }

        LOGINFO("vdev name {}, chunk id {} chunk start offset {}, chunk size {}, pdev_ind: {} ", m_name,
                chunk->get_chunk_id(), chunk->get_start_offset(), chunk->get_size(), pdev_ind);

        m_free_streams.push_back(chunk);
        std::shared_ptr< BlkAllocator > ba{
            create_blk_allocator(allocator_type, get_page_size(), m_primary_pdev_chunks_list[0].pdev->get_page_size(),
                                 m_primary_pdev_chunks_list[0].pdev->get_align_size(), m_chunk_size, m_auto_recovery,
                                 chunk->get_chunk_id(), true /* init */)};

        // set initial value of "end of chunk offset";
        chunk->update_end_of_chunk(m_chunk_size);

        chunk->set_blk_allocator((nmirror > 0) ? ba : std::move(ba));
        m_primary_pdev_chunks_list[pdev_ind].chunks_in_pdev.push_back(chunk);

        // If we have mirror, create a map between chunk and its mirrored chunks
        if (nmirror > 0) {
            size_t next_ind{i};
            std::vector< PhysicalDevChunk* > vec;
            vec.reserve(nmirror);
            for (auto j : boost::irange< uint32_t >(0, nmirror)) {
                if ((++next_ind) == num_pdevs) { next_ind = 0; }
                auto* const mchunk{create_dev_chunk(next_ind, ba, chunk->get_chunk_id())};
                vec.push_back(mchunk);
            }
            m_mirror_chunks.emplace(std::make_pair(chunk, vec));
        }
    }

    for (const auto& pdev_chunk : m_primary_pdev_chunks_list) {
        m_selector->add_pdev(pdev_chunk.pdev);
    }
    reserve_stream(m_default_chunk->get_chunk_id());
}

/* Load the virtual dev from vdev_info_block and create a Virtual Dev. */
VirtualDev::VirtualDev(DeviceManager* mgr, const char* name, vdev_info_block* vb, const PhysicalDevGroup pdev_group,
                       const blk_allocator_type_t allocator_type, vdev_comp_cb_t cb, const bool recovery_init,
                       const bool auto_recovery, vdev_high_watermark_cb_t hwm_cb) :
        m_name{name},
        m_allocator_type{allocator_type},
        m_metrics{name},
        m_pdev_group{pdev_group} {
    init(mgr, vb, std::move(cb), vb->page_size, auto_recovery, std::move(hwm_cb));

    m_recovery_init = recovery_init;
    m_mgr->add_chunks(vb->vdev_id, [this](PhysicalDevChunk* chunk) {
        if (m_drive_iface == nullptr) { m_drive_iface = chunk->get_physical_dev_mutable()->drive_iface(); }
        add_chunk(chunk);
    });

    HS_LOG_ASSERT_EQ(vb->num_primary_chunks * (vb->num_mirrors + 1),
                     m_num_chunks); // Mirrors should be at least one less than device list.
    HS_LOG_ASSERT_EQ(vb->get_size(), vb->num_primary_chunks * m_chunk_size);
    reserve_stream(m_default_chunk->get_chunk_id());
}

void VirtualDev::reset_failed_state() {
    m_vb->set_failed(false);
    m_mgr->write_info_blocks();
}

void VirtualDev::process_completions(const boost::intrusive_ptr< virtualdev_req >& req) {
#ifdef _PRERELEASE
    if (!req->delay_induced &&
        homestore_flip->delay_flip("simulate_vdev_delay",
                                   [req, this]() {
                                       HS_LOG(DEBUG, device, "[Vdev={},req={},is_read={}] - Calling delayed completion",
                                              m_name, req->request_id, req->is_read);
                                       process_completions(req);
                                   },
                                   m_name, req->is_read)) {
        req->delay_induced = true;
        HS_LOG(DEBUG, device, "[Vdev={},req={},is_read={}] - Delaying completion", m_name, req->request_id,
               req->is_read);
        return;
    }
#endif
    if (!(req->outstanding_cbs)) {
        // call completion
        m_comp_cb(req);
    } else {
        if (req->outstanding_cb.decrement_testz(1)) {
            if (!(req->format) && !(req->fsync)) {
                // call completion
                m_comp_cb(req);
            } else if (req->format) {
                req->format_cb(req->err ? false : true);
            } else if (req->fsync) {
                req->fsync_cb(req);
            }
        }
    }

    /* XXX:we probably have to do something if a write/read is spread
     *
     * across the chunks from this layer.
     */
}

void VirtualDev::add_chunk(PhysicalDevChunk* chunk) {
    HS_LOG(INFO, device, "vdev name {} Adding chunk {} from vdev id {} from pdev id = {}", m_name,
           chunk->get_chunk_id(), chunk->get_vdev_id(), chunk->get_physical_dev()->get_dev_id());
    std::lock_guard< decltype(m_mgmt_mutex) > lock{m_mgmt_mutex};

    if (chunk->get_primary_chunk()) {
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

void VirtualDev::format(const vdev_format_cb_t& cb) {
#ifndef NDEBUG
    if (std::getenv(BLKSTORE_FORMAT_OFF.c_str())) {
        cb(true /* success */);
        return;
    }
#endif

    boost::intrusive_ptr< virtualdev_req > req{sisl::ObjectAllocator< virtualdev_req >::make_object()};
    req->outstanding_cb.set(get_num_chunks() * (get_nmirrors() + 1));
    req->outstanding_cbs = true;
    req->format = true;
    req->format_cb = cb;
    req->version = 0xDEAD;
    req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);

    for (size_t dev_ind{0}; dev_ind < m_primary_pdev_chunks_list.size(); ++dev_ind) {
        for (auto* pchunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
            auto* pdev{pchunk->get_physical_dev_mutable()};
            req->inc_ref();
            LOGINFO("writing zero for chunk: {}, size: {}, offset: {}", pchunk->get_chunk_id(), pchunk->get_size(),
                    pchunk->get_start_offset());
            pdev->write_zero(pchunk->get_size(), pchunk->get_start_offset(), reinterpret_cast< uint8_t* >(req.get()));
            auto mchunks_list = m_mirror_chunks[pchunk];
            for (auto& mchunk : mchunks_list) {
                auto* m_pdev{mchunk->get_physical_dev_mutable()};
                req->inc_ref();
                LOGINFO("writing zero for mirror chunk: {}, size: {}, offset: {}", mchunk->get_chunk_id(),
                        mchunk->get_size(), mchunk->get_start_offset());
                m_pdev->write_zero(mchunk->get_size(), mchunk->get_start_offset(),
                                   reinterpret_cast< uint8_t* >(req.get()));
            }
        }
    }
}

stream_info_t VirtualDev::alloc_stream(uint64_t size) {
    std::unique_lock< std::mutex > lk(m_free_streams_lk);
    stream_info_t stream_info;
    while (!m_free_streams.empty() && (size > 0)) {
        auto* const chunk = m_free_streams.back();
        m_free_streams.pop_back();
        ++stream_info.num_streams;
        stream_info.chunk_list.push_back(chunk);
        stream_info.stream_id.push_back(chunk->get_chunk_id());
        // either size becomes 0 or keep finding next chunk to get enough space;
        size -= std::min(size, get_stream_size());
    }
    return stream_info;
}

void VirtualDev::free_stream(const stream_info_t& stream_info) {
    std::unique_lock< std::mutex > lk(m_free_streams_lk);
    for (auto* chunk_ptr : stream_info.chunk_list) {
        m_free_streams.push_back(chunk_ptr);
    }
}

stream_info_t VirtualDev::reserve_stream(const vdev_stream_id_t* id_list, const uint32_t num_streams) {
    stream_info_t stream_info;
    if (num_streams == 0) { return stream_info; }
    std::unique_lock< std::mutex > lk(m_free_streams_lk);
    for (uint32_t i{0}; i < num_streams; ++i) {
        const auto id = id_list[i];
        for (auto it = std::begin(m_free_streams); it != std::end(m_free_streams);) {
            if ((*it)->get_chunk_id() == id) {
                ++stream_info.num_streams;
                stream_info.stream_id.push_back(id);
                stream_info.chunk_list.push_back(*it);
                it = m_free_streams.erase(it);
                break;
            } else {
                ++it;
            }
        }
    }

    HS_REL_ASSERT_EQ(num_streams, stream_info.stream_id.size(), "could not find stream with this id");
    return stream_info;
}

void VirtualDev::reserve_stream(const vdev_stream_id_t id) {
    for (auto it = m_free_streams.begin(); it != m_free_streams.end();) {
        if ((*it)->get_chunk_id() == id) {
            it = m_free_streams.erase(it);
            break;
        } else {
            ++it;
        }
    }
}

uint32_t VirtualDev::get_num_streams() const { return get_num_chunks(); }

uint64_t VirtualDev::get_stream_size() const { return get_chunk_size(); }

std::shared_ptr< blkalloc_cp > VirtualDev::attach_prepare_cp(const std::shared_ptr< blkalloc_cp >& cur_ba_cp) {
    return (PhysicalDevChunk::attach_prepare_cp(cur_ba_cp));
}

bool VirtualDev::is_blk_alloced(const BlkId& blkid) const {
    const PhysicalDevChunk* primary_chunk{m_mgr->get_chunk(blkid.get_chunk_num())};
    return (primary_chunk->get_blk_allocator()->is_blk_alloced(blkid));
}

BlkAllocStatus VirtualDev::reserve_blk(const BlkId& blkid) {
    PhysicalDevChunk* primary_chunk{m_mgr->get_chunk_mutable(blkid.get_chunk_num())};
    HS_LOG(DEBUG, device, "alloc_on_disk: bid {}", blkid.to_string());
    return primary_chunk->get_blk_allocator_mutable()->alloc_on_disk(blkid);
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

BlkAllocStatus VirtualDev::alloc_blk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                     std::vector< BlkId >& out_blkid) {
    try {
        PhysicalDevChunk* preferred_chunk = nullptr;
        auto* const stream_info = (stream_info_t*)(hints.stream_info);
        uint32_t try_streams = 0;
        if (stream_info && (stream_info->num_streams != 0)) { try_streams = stream_info->num_streams; }

        BlkAllocStatus status{BlkAllocStatus::FAILED};

        while (try_streams != 0) {
            preferred_chunk = stream_info->chunk_list[stream_info->stream_cur];
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
        dev_ind = (hints.dev_id_hint == INVALID_DEV_ID) ? m_selector->select(hints)
                                                        : static_cast< uint32_t >(hints.dev_id_hint);

        // Pick a physical chunk based on physDevId.
        // TODO: Right now there is only one primary chunk per device in a virtualdev. Need to support multiple
        // chunks. In that case just using physDevId as chunk number is not right strategy.
        uint32_t start_dev_ind{dev_ind};
        do {
            for (auto& chunk : m_primary_pdev_chunks_list[dev_ind].chunks_in_pdev) {
                status = alloc_blk_from_chunk(nblks, hints, out_blkid, chunk);
                if (status == BlkAllocStatus::SUCCESS || !hints.can_look_for_other_chunk) { break; }
            }

            if (status == BlkAllocStatus::SUCCESS || !hints.can_look_for_other_chunk) { break; }
            dev_ind = static_cast< uint32_t >((dev_ind + 1) % m_primary_pdev_chunks_list.size());
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

BlkAllocStatus VirtualDev::alloc_blk_from_chunk(const blk_count_t nblks, const blk_alloc_hints& hints,
                                                std::vector< BlkId >& out_blkid, PhysicalDevChunk* const chunk) {
#ifdef _PRERELEASE
    if (const auto fake_status{
            homestore_flip->get_test_flip< uint32_t >("blk_allocation_flip", nblks, chunk->get_vdev_id())}) {
        return static_cast< BlkAllocStatus >(fake_status.get());
    }
#endif
    static thread_local std::vector< BlkId > chunk_blkid{};
    chunk_blkid.clear();
    auto status = chunk->get_blk_allocator_mutable()->alloc(nblks, hints, chunk_blkid);
    if (status == BlkAllocStatus::PARTIAL) {
        // free partial result
        for (const auto b : chunk_blkid) {
            const auto ret = chunk->get_blk_allocator_mutable()->free_on_realtime(b);
            HS_REL_ASSERT(ret, "failed to free on realtime");
        }
        chunk->get_blk_allocator_mutable()->free(chunk_blkid);
        status = BlkAllocStatus::FAILED;
    } else if (status == BlkAllocStatus::SUCCESS) {
        // append chunk blocks to out blocks
        out_blkid.insert(std::end(out_blkid), std::make_move_iterator(std::begin(chunk_blkid)),
                         std::make_move_iterator(std::end(chunk_blkid)));
    }
    return status;
}

bool VirtualDev::free_on_realtime(const BlkId& b) {
    PhysicalDevChunk* const chunk{m_mgr->get_chunk_mutable(b.get_chunk_num())};
    return chunk->get_blk_allocator_mutable()->free_on_realtime(b);
}

void VirtualDev::free_blk(const BlkId& b) {
    PhysicalDevChunk* const chunk{m_mgr->get_chunk_mutable(b.get_chunk_num())};
    chunk->get_blk_allocator_mutable()->free(b);
}

void VirtualDev::recovery_done() {
    for (auto& pcm : m_primary_pdev_chunks_list) {
        for (auto& pchunk : pcm.chunks_in_pdev) {
            pchunk->get_blk_allocator_mutable()->inited();
            auto mchunks_list = m_mirror_chunks[pchunk];
            for (auto& mchunk : mchunks_list) {
                mchunk->get_blk_allocator_mutable()->inited();
            }
        }
    }
}

void VirtualDev::write(const BlkId& bid, const iovec* iov, const int iovcnt,
                       const boost::intrusive_ptr< virtualdev_req >& req) {
    PhysicalDevChunk* chunk;
    const auto size{get_len(iov, iovcnt)};
    const uint64_t dev_offset{to_dev_offset(bid, &chunk)};
    if (req) {
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
        req->size = size;
        req->chunk = chunk;
    }

    auto* pdev{chunk->get_physical_dev_mutable()};

    HS_LOG(TRACE, device, "Writing in device: {}, offset = {}", pdev->get_dev_id(), dev_offset);

    // return bytes written already verified to be equal to size by lower level;
    do_pwritev_internal(pdev, chunk, iov, iovcnt, size, dev_offset, req);
}

void VirtualDev::write(const BlkId& bid, const homeds::MemVector& buf,
                       const boost::intrusive_ptr< virtualdev_req >& req, const uint32_t data_offset_in) {
    BlkOpStatus ret_status{BlkOpStatus::SUCCESS};
    uint32_t data_offset{data_offset_in};
    const uint32_t size{bid.get_nblks() * get_page_size()};
    std::array< iovec, BlkId::max_blks_in_op() > iov;
    int iovcnt{0};

    const uint32_t end_offset{data_offset + bid.data_size(m_pagesz)};
    while (data_offset != end_offset) {
        sisl::blob b;
        buf.get(&b, data_offset);
        iov[iovcnt].iov_base = b.bytes;
        if (data_offset + b.size > end_offset) {
            iov[iovcnt].iov_len = end_offset - data_offset;
        } else {
            iov[iovcnt].iov_len = b.size;
        }
        data_offset += iov[iovcnt].iov_len;
        ++iovcnt;
    }

    HS_DBG_ASSERT_EQ(data_offset, end_offset);

    write(bid, iov.data(), iovcnt, req);
}

void VirtualDev::read(const BlkId& bid, const homeds::MemPiece& mp, const boost::intrusive_ptr< virtualdev_req >& req) {
    PhysicalDevChunk* primary_chunk;

    const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};

    do_read_internal(primary_chunk->get_physical_dev_mutable(), primary_chunk, primary_dev_offset,
                     reinterpret_cast< char* >(mp.ptr()), mp.size(), req);
}

void VirtualDev::read(const BlkId& bid, std::vector< iovec >& iovecs, const uint64_t size,
                      const boost::intrusive_ptr< virtualdev_req >& req) {
    PhysicalDevChunk* primary_chunk;

    const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};
    do_preadv_internal(primary_chunk->get_physical_dev_mutable(), primary_chunk, primary_dev_offset, iovecs.data(),
                       iovecs.size(), size, req);
}

void VirtualDev::readv(const BlkId& bid, const homeds::MemVector& buf,
                       const boost::intrusive_ptr< virtualdev_req >& req) {
    // Convert the input memory to iovector
    std::array< iovec, BlkId::max_blks_in_op() > iov;
    int iovcnt{0};
    const uint32_t size{buf.size()};

    // Expected to be less than allocated blk originally.
    HS_DBG_ASSERT_EQ(buf.size(), bid.get_nblks() * get_page_size());
    for (auto i : boost::irange< uint32_t >(0, buf.npieces())) {
        sisl::blob b;
        buf.get(&b, i);

        iov[iovcnt].iov_base = b.bytes;
        iov[iovcnt].iov_len = b.size;
        iovcnt++;
    }

    PhysicalDevChunk* primary_chunk;
    const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};

    auto* pdev{primary_chunk->get_physical_dev_mutable()};

    do_preadv_internal(pdev, primary_chunk, primary_dev_offset, iov.data(), iovcnt, size, req);
}

void VirtualDev::fsync_pdevs(vdev_comp_cb_t cb, uint8_t* const cookie) {
    // auto req{virtualdev_req::make_request()};
    boost::intrusive_ptr< virtualdev_req > req{sisl::ObjectAllocator< virtualdev_req >::make_object()};
    req->version = 0xDEAD;
    req->fsync = true;
    req->fsync_cb = std::move(cb);
    req->outstanding_cbs = true;
    req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
    assert(m_primary_pdev_chunks_list.size() <=
           static_cast< size_t >(std::numeric_limits< decltype(req->outstanding_cb.get()) >::max()));
    req->outstanding_cb.set(static_cast< decltype(req->outstanding_cb.get()) >(m_primary_pdev_chunks_list.size()));
    req->cookie = cookie;

    assert(!m_primary_pdev_chunks_list.empty());
    for (auto& pdev_chunk : m_primary_pdev_chunks_list) {
        auto* const pdev{pdev_chunk.pdev};
        req->inc_ref();
        HS_LOG(TRACE, device, "Flushing pdev {}", pdev->get_devname());
        pdev->fsync(reinterpret_cast< uint8_t* >(req.get()));
    }
}

void VirtualDev::submit_batch() { m_drive_iface->submit_batch(); }

void VirtualDev::get_vb_context(const sisl::blob& ctx_data) const { m_mgr->get_vb_context(m_vb->vdev_id, ctx_data); }

void VirtualDev::update_vb_context(const sisl::blob& ctx_data) { m_mgr->update_vb_context(m_vb->vdev_id, ctx_data); }

uint64_t VirtualDev::get_available_blks() const {
    uint64_t avl_blks{0};
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (uint32_t chunk_indx = 0; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            const auto* chunk{m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx]};
            avl_blks += chunk->get_blk_allocator()->get_available_blks();
        }
    }
    return avl_blks;
}

uint64_t VirtualDev::get_used_size() const {
    uint64_t alloc_cnt{0};
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (uint32_t chunk_indx = 0; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            const auto* chunk{m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx]};
            alloc_cnt += chunk->get_blk_allocator()->get_used_blks();
        }
    }
    return (alloc_cnt * get_page_size());
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

void VirtualDev::blkalloc_cp_start(const std::shared_ptr< blkalloc_cp >& ba_cp) {
    for (size_t i{0}; i < m_primary_pdev_chunks_list.size(); ++i) {
        for (size_t chunk_indx{0}; chunk_indx < m_primary_pdev_chunks_list[i].chunks_in_pdev.size(); ++chunk_indx) {
            auto* chunk{m_primary_pdev_chunks_list[i].chunks_in_pdev[chunk_indx]};
            chunk->cp_start(ba_cp);
        }
    }
}

/* Get status for all chunks */
nlohmann::json VirtualDev::get_status(const int log_level) const {
    nlohmann::json j;
    try {
        for (const auto& pdev_chunks : m_primary_pdev_chunks_list) {
            const auto chunk_list{pdev_chunks.chunks_in_pdev};
            for (const auto& chunk : chunk_list) {
                nlohmann::json chunk_j;
                chunk_j["ChunkInfo"] = chunk->get_status(log_level);
                if (chunk->get_blk_allocator() != nullptr) {
                    chunk_j["BlkallocInfo"] = chunk->get_blk_allocator()->get_status(log_level);
                }
                j[std::to_string(chunk->get_chunk_id())] = chunk_j;
            }
        }
    } catch (const std::exception& e) { LOGERROR("exception happened {}", e.what()); }
    return j;
}

///////////////////////// VirtualDev Private Methods /////////////////////////////
void VirtualDev::write_nmirror(const char* buf, const uint32_t size, PhysicalDevChunk* chunk,
                               const uint64_t dev_offset_in) {
    uint64_t dev_offset{dev_offset_in};
    const uint64_t primary_chunk_offset{dev_offset - chunk->get_start_offset()};

    // Write to the mirror as well
    for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
        for (auto* mchunk : m_mirror_chunks.find(chunk)->second) {
            dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

            // We do not support async mirrored writes yet.
            auto* pdev{mchunk->get_physical_dev_mutable()};

            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            const auto start_time{Clock::now()};
            pdev->sync_write(buf, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        }
    }
}

void VirtualDev::writev_nmirror(const iovec* iov, const int iovcnt, const uint32_t size, PhysicalDevChunk* chunk,
                                const uint64_t dev_offset_in) {
    uint64_t dev_offset{dev_offset_in};
    const uint64_t primary_chunk_offset{dev_offset - chunk->get_start_offset()};

    // Write to the mirror as well
    for (auto i : boost::irange< uint32_t >(0, get_nmirrors())) {
        for (auto* mchunk : m_mirror_chunks.find(chunk)->second) {
            dev_offset = mchunk->get_start_offset() + primary_chunk_offset;

            // We do not support async mirrored writes yet.
            auto* pdev{mchunk->get_physical_dev_mutable()};

            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
            const auto start_time{Clock::now()};
            pdev->sync_writev(iov, iovcnt, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
        }
    }
}

void VirtualDev::read_nmirror(const BlkId& bid, const std::vector< boost::intrusive_ptr< homeds::MemVector > >& mp,
                              const uint64_t size, const uint32_t nmirror) {
    HS_DBG_ASSERT_LE(nmirror, get_nmirrors());
    uint32_t cnt{0};
    PhysicalDevChunk* primary_chunk;
    const uint64_t primary_dev_offset{to_dev_offset(bid, &primary_chunk)};
    const uint64_t primary_chunk_offset{primary_dev_offset - primary_chunk->get_start_offset()};

    sisl::blob b;
    mp[cnt]->get(&b, 0);
    HS_DBG_ASSERT_EQ(b.size, bid.data_size(m_pagesz));
    primary_chunk->get_physical_dev_mutable()->sync_read(reinterpret_cast< char* >(b.bytes), b.size,
                                                         primary_dev_offset);
    if (cnt == nmirror) { return; }
    ++cnt;
    for (auto* mchunk : m_mirror_chunks.find(primary_chunk)->second) {
        const uint64_t dev_offset{mchunk->get_start_offset() + primary_chunk_offset};

        mp[cnt]->get(&b, 0);
        HS_DBG_ASSERT_EQ(b.size, bid.data_size(m_pagesz));
        mchunk->get_physical_dev_mutable()->sync_read(reinterpret_cast< char* >(b.bytes), b.size, dev_offset);

        ++cnt;
        if (cnt == nmirror + 1) { break; }
    }
}

BlkAllocStatus VirtualDev::create_debug_bm() {
    try {
        for (auto& pdev_chunks : m_primary_pdev_chunks_list) {
            auto chunk_list{pdev_chunks.chunks_in_pdev};
            for (auto& chunk : chunk_list) {
                chunk->get_blk_allocator_mutable()->create_debug_bm();
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
        PhysicalDevChunk* chunk{nullptr};
        const uint64_t dev_offset{to_dev_offset(bid, &chunk)};
        chunk->get_blk_allocator_mutable()->update_debug_bm(bid);
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
            auto chunk_list{pdev_chunks.chunks_in_pdev};
            for (auto& chunk : chunk_list) {
                if (chunk->get_blk_allocator_mutable()->verify_debug_bm(free_debug_bm) == false) {
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

uint64_t VirtualDev::get_len(const iovec* iov, const int iovcnt) {
    uint64_t len{0};
    for (int i{0}; i < iovcnt; ++i) {
        len += iov[i].iov_len;
    }
    return len;
}

ssize_t VirtualDev::do_pwritev_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const iovec* iov, const int iovcnt,
                                        const uint64_t len, const uint64_t offset_in_dev,
                                        const boost::intrusive_ptr< virtualdev_req >& req) {
    COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, 1);

    ssize_t bytes_written{0};
    const auto align_sz{pdev->get_align_size()};
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(offset_in_dev, align_sz))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    if (!req || req->isSyncCall) {
        const auto start_time{Clock::now()};
        COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
        bytes_written = pdev->sync_writev(iov, iovcnt, len, offset_in_dev);
        HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
    } else {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);
        req->inc_ref();
        req->io_start_time = Clock::now();
        pdev->writev(iov, iovcnt, len, offset_in_dev, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
        // we are going to get error in callback if the size being writen in aysc is not equal to the size that was
        // requested.
        bytes_written = len;
    }

    if (get_nmirrors()) {
        // We do not support async mirrored writes yet.
        HS_DBG_ASSERT(((req == nullptr) || req->isSyncCall), "Expected null req or a sync call");
        writev_nmirror(iov, iovcnt, len, pchunk, offset_in_dev);
    }

    return bytes_written;
}

ssize_t VirtualDev::do_pwrite_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const char* buf, const uint32_t len,
                                       const uint64_t offset_in_dev,
                                       const boost::intrusive_ptr< virtualdev_req >& req) {
    COUNTER_INCREMENT(pdev->get_metrics(), drive_write_vector_count, 1);

    const auto align_sz{pdev->get_align_size()};
    COUNTER_INCREMENT(m_metrics, vdev_write_count, 1);
    if (sisl_unlikely(!hs_utils::mod_aligned_sz(offset_in_dev, align_sz))) {
        COUNTER_INCREMENT(m_metrics, unalign_writes, 1);
    }

    ssize_t bytes_written{0};

    if (!req || req->isSyncCall) {
        const auto start_time{Clock::now()};
        COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_write_count, 1);
        bytes_written = pdev->sync_write(buf, len, offset_in_dev);
        HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_write_latency, get_elapsed_time_us(start_time));
    } else {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_async_write_count, 1);
        req->inc_ref();
        req->io_start_time = Clock::now();
        pdev->write(buf, len, offset_in_dev, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
        // we are going to get error in callback if the size being writen in aysc is not equal to the size that was
        // requested.
        bytes_written = len;
    }

    if (get_nmirrors()) {
        // We do not support async mirrored writes yet.
        HS_DBG_ASSERT(((req == nullptr) || req->isSyncCall), "Expected null req or a sync call");
        write_nmirror(buf, len, pchunk, offset_in_dev);
    }

    return bytes_written;
}

ssize_t VirtualDev::do_read_internal(PhysicalDev* pdev, PhysicalDevChunk* primary_chunk,
                                     const uint64_t primary_dev_offset, char* ptr, const uint64_t size,
                                     const boost::intrusive_ptr< virtualdev_req >& req) {
    COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, 1);
    COUNTER_INCREMENT(m_metrics, vdev_read_count, 1);
    ssize_t bytes_read{0};

    if (!req || req->isSyncCall) {
        // if req is null (sync), or it is a sync call;
        const auto start{Clock::now()};
        COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
        bytes_read = pdev->sync_read(ptr, size, primary_dev_offset);
        HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start));
    } else {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
        // aysnc read
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
        req->size = size;
        req->chunk = primary_chunk;
        req->io_start_time = Clock::now();
        req->inc_ref();

        pdev->read(ptr, size, primary_dev_offset, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
        bytes_read = size;
    }

    if (sisl_unlikely(get_nmirrors())) {
        // If failed and we have mirrors, we can read from any one of the mirrors as well

        const uint64_t primary_chunk_offset{primary_dev_offset - primary_chunk->get_start_offset()};
        for (auto* mchunk : m_mirror_chunks.find(primary_chunk)->second) {
            const uint64_t dev_offset{mchunk->get_start_offset() + primary_chunk_offset};
            auto* pdev{mchunk->get_physical_dev_mutable()};
            HS_DBG_ASSERT(((req == nullptr) || req->isSyncCall), "Expecting null req or sync call");

            COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
            const auto start_time{Clock::now()};
            pdev->sync_read(ptr, size, dev_offset);
            HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start_time));
        }
    }

    return bytes_read;
}

ssize_t VirtualDev::do_preadv_internal(PhysicalDev* pdev, PhysicalDevChunk* pchunk, const uint64_t dev_offset,
                                       iovec* iov, const int iovcnt, const uint64_t size,
                                       const boost::intrusive_ptr< virtualdev_req >& req) {
    COUNTER_INCREMENT(pdev->get_metrics(), drive_read_vector_count, iovcnt);
    COUNTER_INCREMENT(m_metrics, vdev_read_count, 1);
    ssize_t bytes_read{0};
    if (!req || req->isSyncCall) {
        const auto start{Clock::now()};
        COUNTER_INCREMENT(pdev->get_metrics(), drive_sync_read_count, 1);
        bytes_read = pdev->sync_readv(iov, iovcnt, size, dev_offset);
        HISTOGRAM_OBSERVE(pdev->get_metrics(), drive_read_latency, get_elapsed_time_us(start));
    } else {
        COUNTER_INCREMENT(pdev->get_metrics(), drive_async_read_count, 1);
        req->version = 0xDEAD;
        req->cb = std::bind(&VirtualDev::process_completions, this, std::placeholders::_1);
        req->size = size;
        req->inc_ref();
        req->chunk = pchunk;
        req->io_start_time = Clock::now();

        pdev->readv(iov, iovcnt, size, dev_offset, reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
        bytes_read = size; // no one consumes return value for async read;
    }

    if (sisl_unlikely(get_nmirrors())) {
        // If failed and we have mirrors, we can read from any one of the mirrors as well
        const uint64_t primary_chunk_offset{dev_offset - pchunk->get_start_offset()};
        for (auto& mchunk : m_mirror_chunks.find(pchunk)->second) {
            const uint64_t dev_offset_m{mchunk->get_start_offset() + primary_chunk_offset};
            req->inc_ref();
            mchunk->get_physical_dev_mutable()->readv(iov, iovcnt, size, dev_offset_m,
                                                      reinterpret_cast< uint8_t* >(req.get()), req->part_of_batch);
        }
    }

    return bytes_read;
}

/* Adds a primary chunk to the chunk list in pdev */
void VirtualDev::add_primary_chunk(PhysicalDevChunk* chunk) {
    const auto pdev_id{chunk->get_physical_dev()->get_dev_id()};

    if (m_chunk_size == 0) {
        m_chunk_size = chunk->get_size();
    } else {
        HS_DBG_ASSERT_EQ(m_chunk_size, chunk->get_size());
    }

    if (!m_default_chunk || (m_default_chunk->get_chunk_id() > chunk->get_chunk_id())) { m_default_chunk = chunk; }

    {
        std::unique_lock< std::mutex > lk(m_free_streams_lk);
        m_free_streams.push_back(chunk);
    }
    pdev_chunk_map* found_pcm{nullptr};
    for (auto& pcm : m_primary_pdev_chunks_list) {
        if (pcm.pdev->get_dev_id() == pdev_id) {
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

    const auto max_chunk_size{MAX_DATA_CHUNK_SIZE(m_pagesz)};
    HS_DBG_ASSERT_LE(m_chunk_size, max_chunk_size);
    std::shared_ptr< BlkAllocator > ba{create_blk_allocator(
        m_allocator_type, get_page_size(), m_primary_pdev_chunks_list.front().pdev->get_page_size(),
        m_primary_pdev_chunks_list.front().pdev->get_align_size(), m_chunk_size, m_auto_recovery, chunk->get_chunk_id(),
        m_recovery_init)};
    chunk->set_blk_allocator(ba);
    if (!m_recovery_init) { chunk->recover(); }

    /* set the same blk allocator to other mirror chunks */
    const auto itr_pair{m_mirror_chunks.emplace(chunk, std::vector< PhysicalDevChunk* >{})};
    if (itr_pair.second) {
        // Not found, just created a new entry
    } else {
        for (auto* chunk : itr_pair.first->second) {
            chunk->set_blk_allocator(ba);
        }
    }
}

void VirtualDev::add_mirror_chunk(PhysicalDevChunk* chunk) {
    const auto pdev_id{chunk->get_physical_dev()->get_dev_id()};
    auto* pchunk{chunk->get_primary_chunk_mutable()};

    if (m_chunk_size == 0) {
        m_chunk_size = chunk->get_size();
    } else {
        HS_DBG_ASSERT_EQ(m_chunk_size, chunk->get_size());
    }

    // Try to find the parent chunk in the map
    const auto itr_pair{m_mirror_chunks.emplace(chunk, std::vector< PhysicalDevChunk* >{})};
    itr_pair.first->second.emplace_back(chunk);
    if (itr_pair.second) {
        // Not found, just created a new entry
    } else {
        // set block allocator
        itr_pair.first->second.back()->set_blk_allocator(pchunk->get_blk_allocator_mutable());
    }
}

PhysicalDevChunk* VirtualDev::create_dev_chunk(const uint32_t pdev_ind, const std::shared_ptr< BlkAllocator >& ba,
                                               const uint32_t primary_id) {
    auto* pdev{m_primary_pdev_chunks_list[pdev_ind].pdev};
    PhysicalDevChunk* const chunk{m_mgr->alloc_chunk(pdev, m_vb->vdev_id, m_chunk_size, primary_id)};
    if (chunk) {
        HS_LOG(DEBUG, device, "Allocating new chunk for vdev_id = {} pdev_id = {} chunk: {}", m_vb->get_vdev_id(),
               pdev->get_dev_id(), chunk->to_string());
        chunk->set_blk_allocator(ba);
    }

    return chunk;
}

uint64_t VirtualDev::to_dev_offset(const BlkId& glob_uniq_id, PhysicalDevChunk** chunk) const {
    *chunk = m_mgr->get_chunk_mutable(glob_uniq_id.get_chunk_num());

    const uint64_t dev_offset{static_cast< uint64_t >(glob_uniq_id.get_blk_num()) * get_page_size() +
                              static_cast< uint64_t >((*chunk)->get_start_offset())};
    return dev_offset;
}

uint32_t VirtualDev::get_align_size() const { return m_primary_pdev_chunks_list.front().pdev->get_align_size(); }
uint32_t VirtualDev::get_phys_page_size() const {
    // return m_pagesz;
    return m_primary_pdev_chunks_list.front().pdev->get_page_size();
}

uint32_t VirtualDev::get_atomic_page_size() const {
    return m_primary_pdev_chunks_list.front().pdev->get_atomic_page_size();
}

} // namespace homestore
