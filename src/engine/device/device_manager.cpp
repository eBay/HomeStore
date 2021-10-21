/*
 * DeviceManager.cpp
 *
 *  Created on: 20-Aug-2016
 *      Author: hkadayam
 */

#include <cassert>
#include <cstring>
#include <ctime>

#ifdef __linux__
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include <boost/range.hpp>
#include <sisl/fds/bitset.hpp>
#include <sisl/fds/buffer.hpp>
#include <iomgr/iomgr.hpp>

#include "engine/blkalloc/blk_allocator.h"
#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/device/virtual_dev.hpp"

#include "device.h"

namespace homestore {

/********************************************** dm_info ***************************************************/
const size_t dm_info::s_pdev_info_blocks_size{sizeof(pdev_info_block) * HS_STATIC_CONFIG(engine.max_pdevs)};
const size_t dm_info::s_chunk_info_blocks_size{sizeof(chunk_info_block) * HS_STATIC_CONFIG(engine.max_chunks)};
const size_t dm_info::s_vdev_info_blocks_size{sizeof(vdev_info_block) * HS_STATIC_CONFIG(engine.max_vdevs)};
const size_t dm_info::dm_info_block_size{sizeof(dm_info) + s_pdev_info_blocks_size + s_chunk_info_blocks_size +
                                         s_vdev_info_blocks_size};

std::atomic< uint64_t > virtualdev_req::s_req_id{0};

void PhysicalDevChunk::recover(std::unique_ptr< sisl::Bitset > recovered_bm, meta_blk* const mblk) {
    m_meta_blk_cookie = mblk;
    if (m_allocator) {
        m_allocator->set_disk_bm(std::move(recovered_bm));
    } else {
        m_recovered_bm = std::move(recovered_bm);
    }
}

void PhysicalDevChunk::recover() {
    assert(m_allocator != nullptr);
    if (m_recovered_bm != nullptr) { m_allocator->set_disk_bm(std::move(m_recovered_bm)); }
}

void PhysicalDevChunk::cp_start(std::shared_ptr< blkalloc_cp > ba_cp) {
    auto bitmap_mem = get_blk_allocator_mutable()->cp_start(std::move(ba_cp));
    if (m_meta_blk_cookie) {
        MetaBlkMgrSI()->update_sub_sb(bitmap_mem->bytes, bitmap_mem->size, m_meta_blk_cookie);
    } else {
        MetaBlkMgrSI()->add_sub_sb("BLK_ALLOC", bitmap_mem->bytes, bitmap_mem->size, m_meta_blk_cookie);
    }

    get_blk_allocator_mutable()->cp_done();
}

std::shared_ptr< blkalloc_cp >
PhysicalDevChunk::attach_prepare_cp(const PhysicalDevGroup pdev_group,
                                    [[maybe_unused]] std::shared_ptr< blkalloc_cp > cur_ba_cp) {
    return std::make_shared< blkalloc_cp >();
}

DeviceManager::DeviceManager(NewVDevCallback vcb, const uint32_t vdev_metadata_size,
                             const iomgr::io_interface_comp_cb_t& io_comp_cb,
                             const iomgr::iomgr_drive_type data_drive_type,
                             const iomgr::iomgr_drive_type fast_drive_type, const vdev_error_callback& vdev_error_cb) :
        m_new_vdev_cb{std::move(vcb)},
        m_data_drive_type{data_drive_type},
        m_fast_drive_type{fast_drive_type},
        m_vdev_metadata_size{vdev_metadata_size},
        m_vdev_error_cb{vdev_error_cb} {

    m_data_open_flags = get_open_flags(HS_STATIC_CONFIG(input.data_open_flags));
    m_fast_open_flags = get_open_flags(HS_STATIC_CONFIG(input.fast_open_flags));

    // initialize memory structures in chunk memory
    const auto initialize_memory_structures{[](uint8_t** chunk_memory, auto& dm_derived, const auto page_size,
                                               const auto alignment) {
        dm_derived.info_size = sisl::round_up(dm_info::dm_info_block_size, page_size);
        *chunk_memory = hs_utils::iobuf_alloc(dm_derived.info_size, sisl::buftag::superblk, alignment);
        dm_derived.info = new (*chunk_memory) dm_info{};
        std::uninitialized_default_construct(dm_derived.info->get_pdev_info_blocks(),
                                             dm_derived.info->get_pdev_info_blocks() +
                                                 HS_STATIC_CONFIG(engine.max_pdevs));
        std::uninitialized_default_construct(dm_derived.info->get_chunk_info_blocks(),
                                             dm_derived.info->get_chunk_info_blocks() +
                                                 HS_STATIC_CONFIG(engine.max_chunks));
        std::uninitialized_default_construct(dm_derived.info->get_vdev_info_blocks(),
                                             dm_derived.info->get_vdev_info_blocks() +
                                                 HS_STATIC_CONFIG(engine.max_vdevs));
        if (dm_info::dm_info_block_size < dm_derived.info_size) {
            std::memset(*chunk_memory + dm_info::dm_info_block_size, 0,
                        dm_derived.info_size - dm_info::dm_info_block_size);
        }

        dm_derived.pdev_hdr = &dm_derived.info->pdev_hdr;
        dm_derived.chunk_hdr = &dm_derived.info->chunk_hdr;
        dm_derived.vdev_hdr = &dm_derived.info->vdev_hdr;
    }};

    initialize_memory_structures(&m_data_chunk_memory, m_data_dm_derived,
                                 HS_STATIC_CONFIG(data_drive_attr.phys_page_size),
                                 HS_STATIC_CONFIG(data_drive_attr.align_size));
    initialize_memory_structures(
        &m_fast_chunk_memory, m_fast_dm_derived, HS_STATIC_CONFIG(fast_drive_attr.phys_page_size),
        HS_STATIC_CONFIG(fast_drive_attr.align_size) > 0 ? HS_STATIC_CONFIG(fast_drive_attr.align_size)
                                                         : HS_STATIC_CONFIG(data_drive_attr.align_size));
    m_scan_cmpltd = false;

    // Attach completions to the drive end point this DeviceManager is going to use
    iomanager.default_drive_interface()->attach_completion_cb(io_comp_cb);

    HS_LOG_ASSERT_LE(m_vdev_metadata_size, MAX_CONTEXT_DATA_SZ);
}

/* It returns total capacity availble to use by virtual dev. */
size_t DeviceManager::get_total_cap(const PhysicalDevGroup pdev_group) const {
    /* we don't support hetrogenous disks */
    if (pdev_group == PhysicalDevGroup::DATA) {
        return (m_data_pdevs.size() * (m_data_pdevs[get_pdev_id_start(PhysicalDevGroup::DATA)]->get_total_cap()));
    } else {
        return (m_fast_pdevs.size() * (m_fast_pdevs[get_pdev_id_start(PhysicalDevGroup::FAST)]->get_total_cap()));
    }
}

void DeviceManager::init_devices(const std::vector< dev_info >& data_devices,
                                 const std::vector< dev_info >& fast_devices) {
    // all devices will be inited with same system uuid;
    const auto sys_uuid{hs_utils::gen_system_uuid()};

    const auto init_dm_derived{[this, &sys_uuid](const PhysicalDevGroup pdev_group, auto& devices,
                                                 const auto& open_flags, const auto& drive_type, auto& pdevs) {
        const auto pdev_start_id{m_pdev_id};
        auto* const chunk_memory{get_chunk_memory(pdev_group)};
        auto& dm_derived{get_dm_derived(pdev_group)};

        // set the offset
        dm_derived.info->magic = MAGIC;
        dm_derived.info->version = CURRENT_DM_INFO_VERSION;
        dm_derived.info->size = dm_derived.info_size;
        dm_derived.info->version = CURRENT_DM_INFO_VERSION;

        // Create new vdev info
        dm_derived.vdev_info = dm_derived.info->get_vdev_info_blocks();
        dm_derived.vdev_hdr->magic = MAGIC;
        dm_derived.vdev_hdr->num_vdevs = 0;
        dm_derived.vdev_hdr->first_vdev_id = INVALID_VDEV_ID;
        dm_derived.vdev_hdr->info_offset = static_cast< uint64_t >(reinterpret_cast< uint8_t* >(dm_derived.vdev_info) -
                                                                   reinterpret_cast< uint8_t* >(dm_derived.info));
        dm_derived.vdev_hdr->context_data_size = m_vdev_metadata_size;

        // create new chunk info
        dm_derived.chunk_info = dm_derived.info->get_chunk_info_blocks();
        dm_derived.chunk_hdr->magic = MAGIC;
        dm_derived.chunk_hdr->num_chunks = 0;
        dm_derived.chunk_hdr->info_offset = static_cast< uint64_t >(
            reinterpret_cast< uint8_t* >(dm_derived.chunk_info) - reinterpret_cast< uint8_t* >(dm_derived.info));
        HS_LOG_ASSERT_LE(HS_STATIC_CONFIG(engine.max_chunks), MAX_CHUNK_ID);

        // create new pdev info
        dm_derived.pdev_info = dm_derived.info->get_pdev_info_blocks();
        dm_derived.pdev_hdr->magic = MAGIC;
        dm_derived.pdev_hdr->num_phys_devs = static_cast< uint32_t >(devices.size());
        dm_derived.pdev_hdr->info_offset = static_cast< uint64_t >(reinterpret_cast< uint8_t* >(dm_derived.pdev_info) -
                                                                   reinterpret_cast< uint8_t* >(dm_derived.info));

        uint64_t pdev_size{0};
        uint64_t max_dev_offset{0};
        for (auto& d : devices) {
            bool is_inited;

            std::unique_ptr< PhysicalDev > pdev{
                std::make_unique< PhysicalDev >(this, pdev_group, d.dev_names, open_flags, sys_uuid, m_pdev_id++,
                                                max_dev_offset, drive_type, true, dm_derived.info_size, &is_inited)};

            LOGINFO("Initializing {} device name: {}, type: {} with system uuid: {}.", pdev_group, d.dev_names,
                    drive_type, std::ctime(&sys_uuid));

            max_dev_offset += pdev->get_size();
            if (!pdev_size) {
                pdev_size = pdev->get_size();
            } else if (pdev_size != pdev->get_size()) {
                std::ostringstream ss;
                ss << "heterogenous {} disks expected size = " << pdev_group << pdev_size << " found size "
                   << pdev->get_size() << "disk name: " << pdev->get_devname();
                const std::string s{ss.str()};
                throw homestore::homestore_exception(s, homestore_error::hetrogenous_disks);
            }
            const auto id{pdev->get_dev_id()};
            pdevs[id] = std::move(pdev);
            dm_derived.pdev_info[id] = pdevs[id]->get_info_blk();
        }

        if (pdev_group == PhysicalDevGroup::DATA) { m_last_data_pdev_id = m_pdev_id - 1; }
    }};
    init_dm_derived(PhysicalDevGroup::DATA, data_devices, m_data_open_flags, m_data_drive_type, m_data_pdevs);
    if (!fast_devices.empty()) {
        init_dm_derived(PhysicalDevGroup::FAST, fast_devices, m_fast_open_flags, m_fast_drive_type, m_fast_pdevs);
    }

    m_scan_cmpltd = true;

    write_info_blocks(PhysicalDevGroup::DATA);
    if (!fast_devices.empty()) { write_info_blocks(PhysicalDevGroup::FAST); }
}

DeviceManager::~DeviceManager() {
    const auto reset_pointers{[](auto& dm_derived) {
        dm_derived.info = nullptr;
        dm_derived.pdev_hdr = nullptr;
        dm_derived.chunk_hdr = nullptr;
        dm_derived.vdev_hdr = nullptr;
        dm_derived.pdev_info = nullptr;
        dm_derived.chunk_info = nullptr;
        dm_derived.vdev_info = nullptr;
    }};

    hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(m_data_chunk_memory), sisl::buftag::superblk);
    reset_pointers(m_data_dm_derived);
    if (m_fast_chunk_memory) {
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(m_fast_chunk_memory), sisl::buftag::superblk);
        reset_pointers(m_fast_dm_derived);
    }
}

void DeviceManager::update_end_of_chunk(const PhysicalDevGroup pdev_group, PhysicalDevChunk* const chunk,
                                        const off_t offset) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};
    chunk->update_end_of_chunk(static_cast< uint64_t >(offset));
    write_info_blocks(pdev_group);
}

void DeviceManager::get_vb_context(const PhysicalDevGroup pdev_group, const uint32_t vdev_id,
                                   const sisl::blob& ctx_data) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};
    HS_LOG_ASSERT_LE(ctx_data.size, vdev_info_block::max_context_size());
    assert(ctx_data.size <= vdev_info_block::max_context_size());
    auto& dm_derived{get_dm_derived(pdev_group)};
    std::memcpy(ctx_data.bytes, dm_derived.vdev_info[vdev_id].context_data, ctx_data.size);
}

void DeviceManager::update_vb_context(const PhysicalDevGroup pdev_group, const uint32_t vdev_id,
                                      const sisl::blob& ctx_data) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};
    HS_LOG_ASSERT_LE(ctx_data.size, vdev_info_block::max_context_size());
    assert(ctx_data.size <= vdev_info_block::max_context_size());
    auto& dm_derived{get_dm_derived(pdev_group)};
    std::memcpy(dm_derived.vdev_info[vdev_id].context_data, ctx_data.bytes, ctx_data.size);
    write_info_blocks(pdev_group);
}

void DeviceManager::load_and_repair_devices(const std::vector< dev_info >& data_devices,
                                            const std::vector< dev_info >& fast_devices, const hs_uuid_t& sys_uuid) {

    bool data_rewrite{false}, fast_rewrite{false};

    const auto load_devices{[this, &sys_uuid](const PhysicalDevGroup pdev_group, auto& devices, const auto& open_flags,
                                              const auto& drive_type, auto& pdevs, auto& chunks, bool& rewrite) {
        uint32_t device_id{INVALID_DEV_ID};
        std::vector< std::unique_ptr< PhysicalDev > > uninit_devs;
        uninit_devs.reserve(devices.size());

        auto* const chunk_memory{get_chunk_memory(pdev_group)};
        auto& dm_derived{get_dm_derived(pdev_group)};
        auto& gen_count{get_gen_count(pdev_group)};
        size_t pdev_size{0};
        for (auto& d : devices) {
            bool is_inited;
            std::unique_ptr< PhysicalDev > pdev{
                std::make_unique< PhysicalDev >(this, pdev_group, d.dev_names, open_flags, sys_uuid, INVALID_DEV_ID, 0,
                                                drive_type, false, dm_derived.info_size, &is_inited)};
            if (!is_inited) {
                // Super block is not present, possibly a new device, will format the device later
                HS_LOG(CRITICAL, device,
                       "{} device {} appears to be not formatted. Will format it and replace it with the failed disks."
                       "Replacing it with the failed disks can cause data loss",
                       pdev_group, d.dev_names);
                uninit_devs.push_back(std::move(pdev));

                HS_RELEASE_ASSERT(false, "hot plug-in device not supported!");

                continue;
            }

            LOGINFO("Loaded {} device: {}, type: {} with system uuid: {}", pdev_group, d.dev_names, m_data_drive_type,
                    std::ctime(&sys_uuid));

            if (!pdev_size) { pdev_size = pdev->get_size(); }
            HS_LOG_ASSERT_EQ(pdev_size, pdev->get_size(), "Not all physical devices are of equal size");

            if (gen_count.load() < pdev->sb_gen_cnt()) {
                gen_count = pdev->sb_gen_cnt();
                device_id = pdev->get_dev_id();
                rewrite = HS_STATIC_CONFIG(input.is_read_only) ? false : true;
            }
#if 0
        static auto sys_uuid = pdev->get_sys_uuid();

        // sanity check that all devices should have same homestore system uuid;
        HS_RELEASE_ASSERT_EQ(sys_uuid, pdev->get_sys_uuid(), "homestore system uuid mismatch found on devices {}, {}",
                             sys_uuid, pdev->get_sys_uuid());
#endif
            HS_ASSERT_NULL(LOGMSG, pdevs[pdev->get_dev_id()].get());

            pdevs[pdev->get_dev_id()] = std::move(pdev);
        }

        if (pdev_group == PhysicalDevGroup::DATA) {
            m_last_data_pdev_id = devices.size() - 1;
            m_pdev_id = dm_derived.pdev_hdr->num_phys_devs;
        } else {
            m_pdev_id += dm_derived.pdev_hdr->num_phys_devs;
        }

        if (gen_count.load() == 0) {
            std::ostringstream ss;
            ss << "No valid device found. line no:" << __LINE__ << "file name:" << __FILE__;
            const std::string s{ss.str()};
            throw homestore::homestore_exception(s, homestore_error::no_valid_device_found);
        }

        // load the info blocks
        read_info_blocks(pdev_group, device_id);

        // TODO : If it is different then existing chunk in pdev superblock has to be deleted and new has to be created
        HS_LOG_ASSERT_EQ(dm_derived.info_size, dm_derived.info->get_size());
        HS_LOG_ASSERT_EQ(dm_derived.info->get_version(), CURRENT_DM_INFO_VERSION);

        // find the devices which has to be replaced
        HS_LOG_ASSERT_LE(dm_derived.pdev_hdr->get_num_phys_devs(), HS_STATIC_CONFIG(engine.max_pdevs));
        const auto pdev_id_start{get_pdev_id_start(pdev_group)};
        for (uint32_t dev_id{pdev_id_start}; dev_id < pdev_id_start + dm_derived.pdev_hdr->num_phys_devs; ++dev_id) {
            auto* const pdev{get_pdev(dev_id)};
            if (pdev == nullptr) {
                std::unique_ptr< PhysicalDev > pdev{std::move(uninit_devs.back())};
                HS_ASSERT_NOTNULL(LOGMSG, pdev.get());
                if (pdev == nullptr) {
                    /* we don't have sufficient disks to replace */
                    std::ostringstream ss;
                    ss << "No spare disk found. line no: " << __LINE__ << "file name:" << __FILE__;
                    const std::string s{ss.str()};
                    throw homestore::homestore_exception(s, homestore_error::no_spare_disk);
                    return;
                }
                uninit_devs.pop_back();
                if (pdev_size != pdev->get_size()) {
                    std::ostringstream ss;
                    ss << pdev_group << " heterogenous disks expected size = " << pdev_size << " found size "
                       << pdev->get_size() << "disk name" << pdev->get_devname();
                    const std::string s{ss.str()};
                    throw homestore::homestore_exception(s, homestore_error::hetrogenous_disks);
                }
                pdev->update(dev_id, dm_derived.pdev_info[dev_id].dev_offset,
                             dm_derived.pdev_info[dev_id].first_chunk_id);
                pdevs[dev_id] = std::move(pdev);

                // mark all the vdevs mounted on this disk to failed state
                // TODO:It is ok for now as we have lesser number of chunks. Once we have
                // larger number of chunks, we should optimize it.
                for (uint32_t i{0}; i < HS_STATIC_CONFIG(engine.max_chunks); ++i) {
                    if (dm_derived.chunk_info[i].pdev_id == dev_id && dm_derived.chunk_info[i].is_slot_allocated() &&
                        dm_derived.chunk_info[i].vdev_id != INVALID_VDEV_ID) {
                        const auto vdev_id{dm_derived.chunk_info[i].vdev_id};
                        HS_LOG_ASSERT_EQ(dm_derived.vdev_info[vdev_id].get_vdev_id(), vdev_id);
                        // mark this vdev failed
                        dm_derived.vdev_info[vdev_id].set_failed(true);
                    }
                }
                rewrite = true;
            }
        }

        HS_LOG_ASSERT_EQ(uninit_devs.empty(), true, "Found spare devices which are not added to the system!");

        // scan and create all the chunks for all physical devices
        uint32_t num_chunks{0};
        for (uint32_t dev_id{pdev_id_start}; dev_id < pdev_id_start + dm_derived.pdev_hdr->num_phys_devs; ++dev_id) {
            auto* const pdev{get_pdev(dev_id)};
            uint32_t cid{pdev->get_first_chunk_id()};
            while (cid != INVALID_CHUNK_ID) {
                auto* const chunk{get_chunk_mutable(cid, pdev->m_pdev_group)};
                HS_ASSERT_NULL(LOGMSG, chunk);
                HS_LOG_ASSERT_LT(cid, HS_STATIC_CONFIG(engine.max_chunks));
                chunks[cid] = std::make_unique< PhysicalDevChunk >(pdevs[dm_derived.chunk_info[cid].pdev_id].get(),
                                                                   &dm_derived.chunk_info[cid]);
                if (dm_derived.chunk_info[cid].is_sb_chunk()) {
                    pdevs[dm_derived.chunk_info[cid].pdev_id]->attach_superblock_chunk(chunks[cid].get());
                }
                HS_LOG_ASSERT_EQ(dm_derived.chunk_info[cid].get_chunk_id(), cid);
                cid = dm_derived.chunk_info[cid].next_chunk_id;
                ++num_chunks;
            }
        }

        HS_LOG_ASSERT_EQ(num_chunks, dm_derived.chunk_hdr->get_num_chunks());
    }};
    // load data devices
    load_devices(PhysicalDevGroup::DATA, data_devices, m_data_open_flags, m_data_drive_type, m_data_pdevs,
                 m_data_chunks, data_rewrite);

    if (!fast_devices.empty()) {
        // load fast devices
        load_devices(PhysicalDevGroup::FAST, fast_devices, m_fast_open_flags, m_fast_drive_type, m_fast_pdevs,
                     m_fast_chunks, fast_rewrite);
    }
    m_scan_cmpltd = true;

    const auto create_vdevs{[this](const PhysicalDevGroup pdev_group, const bool rewrite) {
        if (rewrite) {
            // rewriting superblock
            write_info_blocks(pdev_group);
        }

        // create vdevs
        auto& dm_derived{get_dm_derived(pdev_group)};
        uint32_t vid{dm_derived.vdev_hdr->first_vdev_id};
        uint32_t num_vdevs{0};
        while (vid != INVALID_VDEV_ID) {
            HS_LOG_ASSERT_LT(vid, HS_STATIC_CONFIG(engine.max_vdevs));
            get_last_vdev_id(pdev_group) = vid;
            m_new_vdev_cb(this, &dm_derived.vdev_info[vid]);
            HS_LOG_ASSERT_EQ(dm_derived.vdev_info[vid].is_slot_allocated(), true);
            HS_LOG_ASSERT_EQ(dm_derived.vdev_info[vid].get_vdev_id(), vid);
            vid = dm_derived.vdev_info[vid].next_vdev_id;
            ++num_vdevs;
        }
        HS_LOG_ASSERT_EQ(num_vdevs, dm_derived.vdev_hdr->get_num_vdevs());
    }};

    // create data vdevs
    create_vdevs(PhysicalDevGroup::DATA, data_rewrite);
    if (!fast_devices.empty()) {
        // create fast vdevs
        create_vdevs(PhysicalDevGroup::FAST, fast_rewrite);
    }
}

void DeviceManager::handle_error(PhysicalDev* const pdev) {
    const auto cnt{pdev->inc_error_cnt()};

    /* When cnt reaches max_error_count we notify only once until
     * we reset the cnt to zero.
     */
    if (cnt < HS_DYNAMIC_CONFIG(device->max_error_before_marking_dev_down)
#ifdef _PRERELEASE
        && !(homestore_flip->test_flip("device_fail", pdev->get_devname()))
#endif
    ) {
        return;
    }

    /* send errors on all vdev in this pdev */
    const auto pdev_id{pdev->get_dev_id()};
    const auto& dm_dervived{get_dm_derived(pdev->m_pdev_group)};
    for (uint32_t i{0}; i < HS_STATIC_CONFIG(engine.max_chunks); ++i) {
        if (dm_dervived.chunk_info[i].pdev_id == pdev_id) {
            const auto vdev_id{dm_dervived.chunk_info[i].vdev_id};
            m_vdev_error_cb(&dm_dervived.vdev_info[vdev_id]);
        }
    }
}

void DeviceManager::add_chunks(const uint32_t vid, const PhysicalDevGroup pdev_group, const chunk_add_callback& cb) {
    const auto pdev_id_start{get_pdev_id_start(pdev_group)};
    const auto& dm_dervived{get_dm_derived(pdev_group)};
    for (uint32_t dev_id{pdev_id_start}; dev_id < pdev_id_start + dm_dervived.pdev_hdr->num_phys_devs; ++dev_id) {
        auto* const pdev{get_pdev(dev_id)};
        uint32_t cid{pdev->get_first_chunk_id()};
        while (cid != INVALID_CHUNK_ID) {
            auto* const chunk{get_chunk_mutable(cid, pdev->m_pdev_group)};
            HS_ASSERT_NOTNULL(DEBUG, chunk);
            if (chunk->get_vdev_id() == vid) { cb(chunk); }
            cid = chunk->get_next_chunk_id();
        }
    }
}

void DeviceManager::inited() {
    const auto init_pdevs{[this](const PhysicalDevGroup pdev_group) {
        auto& dm_derived{get_dm_derived(pdev_group)};
        const auto pdev_start_id{get_pdev_id_start(pdev_group)};
        for (uint32_t dev_id{pdev_start_id}; dev_id < pdev_start_id + dm_derived.pdev_hdr->num_phys_devs; ++dev_id) {
            auto* const pdev{get_pdev(dev_id)};
            uint32_t cid{pdev->get_first_chunk_id()};
            while (cid != INVALID_CHUNK_ID) {
                auto* chunk{get_chunk_mutable(cid, pdev->m_pdev_group)};
                if (chunk->get_vdev_id() == INVALID_VDEV_ID) {
                    cid = chunk->get_next_chunk_id();
                    continue;
                }
                HS_ASSERT_NOTNULL(DEBUG, chunk->get_blk_allocator().get());
                chunk->get_blk_allocator_mutable()->inited();
                cid = chunk->get_next_chunk_id();
            }
        }
    }};

    init_pdevs(PhysicalDevGroup::DATA);
    if (fast_devices_present()) { init_pdevs(PhysicalDevGroup::FAST); }
}

void DeviceManager::blk_alloc_meta_blk_found_cb(meta_blk* const mblk, const sisl::byte_view buf, const size_t size) {
    // TO DO: Might need to address alignment based on data or fast type
    std::unique_ptr< sisl::Bitset > recovered_bm{
        new sisl::Bitset{hs_utils::extract_byte_array(buf, MetaBlkMgrSI()->is_aligned_buf_needed(size))}};
    // TO DO: Possibly do something here based on presence of fast drives
    const auto bitmap_id{recovered_bm->get_id()};
    const auto [pdev_group, chunk_id]{BlkAllocator::get_pdev_group_and_chunk_id(bitmap_id)};
    auto* const chunk{get_chunk_mutable(chunk_id, pdev_group)};
    LOGINFO("get id {} pdev group {}", chunk_id, pdev_group);
    chunk->recover(std::move(recovered_bm), mblk);
}

void DeviceManager::init_done() {
    const auto init_done_pdevs{[this](const PhysicalDevGroup pdev_group) {
        auto& dm_derived{get_dm_derived(pdev_group)};
        const auto pdev_start_id{get_pdev_id_start(pdev_group)};
        for (uint32_t dev_id{pdev_start_id}; dev_id < pdev_start_id + dm_derived.pdev_hdr->num_phys_devs; ++dev_id) {
            auto* const pdev{get_pdev(dev_id)};
            pdev->init_done();
        }
    }};

    init_done_pdevs(PhysicalDevGroup::DATA);
    if (fast_devices_present()) { init_done_pdevs(PhysicalDevGroup::FAST); }
}

void DeviceManager::close_devices() {
    const auto close_pdevs{[this](const PhysicalDevGroup pdev_group) {
        auto& dm_derived{get_dm_derived(pdev_group)};
        const auto pdev_start_id{get_pdev_id_start(pdev_group)};
        for (uint32_t dev_id{pdev_start_id}; dev_id < pdev_start_id + dm_derived.pdev_hdr->num_phys_devs; ++dev_id) {
            auto* const pdev{get_pdev(dev_id)};
            pdev->close_device();
        }
    }};

    close_pdevs(PhysicalDevGroup::DATA);
    if (fast_devices_present()) { close_pdevs(PhysicalDevGroup::FAST); }
}

int DeviceManager::get_open_flags(const io_flag oflags) {
    int open_flags;

    switch (oflags) {
    case io_flag::BUFFERED_IO:
        open_flags = O_RDWR | O_CREAT;
        break;
    case io_flag::READ_ONLY:
        open_flags = O_RDONLY;
        break;
    case io_flag::DIRECT_IO:
        open_flags = O_RDWR | O_CREAT | O_DIRECT;
        break;
    default:
        open_flags = O_RDWR | O_CREAT;
    }

    return open_flags;
}

void DeviceManager::zero_boot_sbs(const std::vector< dev_info >& devices, const iomgr_drive_type drive_type,
                                  const io_flag oflags) {
    return PhysicalDev::zero_boot_sbs(devices, drive_type, get_open_flags(oflags));
}
#if 0
void DeviceManager::zero_pdev_sbs() {
    for (uint32_t dev_id = 0; dev_id < m_pdev_hdr->num_phys_devs; ++dev_id) {
        m_pdevs[dev_id]->zero_superblock();
    }
}
#endif
/* add constant */
bool DeviceManager::add_devices(const std::vector< dev_info >& data_devices,
                                const std::vector< dev_info >& fast_devices) {
    uint64_t max_dev_offset{0};
    MetaBlkMgrSI()->register_handler("BLK_ALLOC", bind_this(DeviceManager::blk_alloc_meta_blk_found_cb, 3), nullptr,
                                     true /* do_crc */);

    HS_RELEASE_ASSERT(data_devices.size() > 0, "Expecting at least one data device");

    hs_uuid_t data_system_uuid{INVALID_SYSTEM_UUID};
    hs_uuid_t fast_system_uuid{INVALID_SYSTEM_UUID};

    const auto verify_superblock{[this](const PhysicalDevGroup pdev_group, auto& devices, const auto& open_flags,
                                        const auto& drive_type, hs_uuid_t& system_uuid) {
        for (auto& d : devices) {
            std::unique_ptr< PhysicalDev > pdev{
                std::make_unique< PhysicalDev >(this, pdev_group, d.dev_names, open_flags, drive_type)};

            if (pdev->has_valid_superblock(system_uuid)) { return true; }
        }
        return false;
    }};
    const bool valid_data_block{verify_superblock(PhysicalDevGroup::DATA, data_devices, m_data_open_flags,
                                                  m_data_drive_type, data_system_uuid)};
    bool valid_fast_block{true};
    if (!fast_devices.empty()) {
        valid_fast_block = verify_superblock(PhysicalDevGroup::FAST, fast_devices, m_fast_open_flags, m_fast_drive_type,
                                             fast_system_uuid);
    }

    if (valid_data_block && valid_fast_block) { m_first_time_boot = false; }

    if (!m_first_time_boot) {
        HS_DEBUG_ASSERT_NE(data_system_uuid, INVALID_SYSTEM_UUID);
        if (!fast_devices.empty()) { HS_DEBUG_ASSERT_NE(fast_system_uuid, INVALID_SYSTEM_UUID); }
        load_and_repair_devices(data_devices, fast_devices, data_system_uuid);
    } else {
        HS_DEBUG_ASSERT_EQ(data_system_uuid, INVALID_SYSTEM_UUID);
        if (!fast_devices.empty()) { HS_DEBUG_ASSERT_EQ(fast_system_uuid, INVALID_SYSTEM_UUID); }
        init_devices(data_devices, fast_devices);
    }

    return m_first_time_boot;
}

/* Note: Whosoever is calling this function should take the mutex. We don't allow multiple reads */
void DeviceManager::read_info_blocks(const PhysicalDevGroup pdev_group, const uint32_t dev_id) {
    auto& dm_derived{get_dm_derived(pdev_group)};
    auto* const chunk_memory{get_chunk_memory(pdev_group)};
    auto* const pdev{get_pdev(dev_id)};
    pdev->read_dm_chunk(reinterpret_cast< char* >(chunk_memory), dm_derived.info_size);

    auto* const dm{reinterpret_cast< dm_info* >(chunk_memory)};
    HS_DEBUG_ASSERT_EQ(dm->get_magic(), MAGIC);
#ifndef NO_CHECKSUM
    const auto crc{crc16_t10dif(init_crc_16,
                                reinterpret_cast< const unsigned char* >(chunk_memory + dm_info::s_dm_payload_offset),
                                dm_derived.info_size - dm_info::s_dm_payload_offset)};
    HS_DEBUG_ASSERT_EQ(dm->get_checksum(), crc);
#endif

    HS_DEBUG_ASSERT_EQ(dm_derived.vdev_hdr->get_magic(), MAGIC);
    HS_DEBUG_ASSERT_EQ(dm_derived.chunk_hdr->get_magic(), MAGIC);
    HS_DEBUG_ASSERT_EQ(dm_derived.pdev_hdr->get_magic(), MAGIC);

    dm_derived.vdev_info = reinterpret_cast< vdev_info_block* >(chunk_memory + dm_derived.vdev_hdr->info_offset);
    dm_derived.chunk_info = reinterpret_cast< chunk_info_block* >(chunk_memory + dm_derived.chunk_hdr->info_offset);
    dm_derived.pdev_info = reinterpret_cast< pdev_info_block* >(chunk_memory + dm_derived.pdev_hdr->info_offset);
}

// Note: Whosoever is calling this function should take the mutex. We don't allow multiple writes */
void DeviceManager::write_info_blocks(const PhysicalDevGroup pdev_group) {
    // we don't write anything until all the devices are not scanned. Only write that can
    // happen before scanning of device is completed is allocation of chunks.
    if (!m_scan_cmpltd) { return; }
    auto& gen_count{get_gen_count(pdev_group)};
    ++gen_count;

    const auto* const chunk_memory{get_chunk_memory(pdev_group)};
    auto& dm_derived{get_dm_derived(pdev_group)};

#ifndef NO_CHECKSUM
    dm_derived.info->checksum =
        crc16_t10dif(init_crc_16, reinterpret_cast< const unsigned char* >(chunk_memory + dm_info::s_dm_payload_offset),
                     dm_derived.info_size - dm_info::s_dm_payload_offset);
#endif

    const auto pdev_start_id{get_pdev_id_start(pdev_group)};
    for (uint32_t i{pdev_start_id}; i < pdev_start_id + dm_derived.pdev_hdr->num_phys_devs; ++i) {
        auto* const pdev{get_pdev(i)};
        pdev->write_dm_chunk(gen_count, reinterpret_cast< const char* >(chunk_memory), dm_derived.info_size);
    }

    HS_DEBUG_ASSERT_EQ(dm_derived.vdev_hdr->get_magic(), MAGIC);
    HS_DEBUG_ASSERT_EQ(dm_derived.chunk_hdr->get_magic(), MAGIC);
    HS_DEBUG_ASSERT_EQ(dm_derived.pdev_hdr->get_magic(), MAGIC);
}

PhysicalDevChunk* DeviceManager::alloc_chunk(PhysicalDev* const pdev, const uint32_t vdev_id, const uint64_t req_size,
                                             const uint32_t primary_id) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};

    HS_DEBUG_ASSERT_EQ(req_size %
                           (pdev->m_pdev_group == PhysicalDevGroup::DATA
                                ? HS_STATIC_CONFIG(data_drive_attr.phys_page_size)
                                : HS_STATIC_CONFIG(fast_drive_attr.phys_page_size)),
                       0);
    PhysicalDevChunk* const chunk{pdev->find_free_chunk(req_size)};
    if (chunk == nullptr) {
        std::ostringstream ss;
        ss << "No space available for chunk size = " << req_size << " in pdev id = " << pdev->get_dev_id();
        const std::string s{ss.str()};
        throw homestore::homestore_exception(s, homestore_error::no_space_avail);
    }
    HS_DEBUG_ASSERT_GE(chunk->get_size(), req_size);
    chunk->set_vdev_id(vdev_id); // Set the chunk as busy or engaged to a vdev
    chunk->set_primary_chunk_id(primary_id);
    chunk->update_end_of_chunk(req_size);

    if (chunk->get_size() > req_size) {
        // There is some left over space, create a new chunk and insert it after current chunk
        create_new_chunk(pdev, chunk->get_start_offset() + req_size, chunk->get_size() - req_size, chunk);
        chunk->set_size(req_size);
    }

    write_info_blocks(pdev->m_pdev_group);
    return chunk;
}

void DeviceManager::free_chunk(const PhysicalDevGroup pdev_group, PhysicalDevChunk* const chunk) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};
    chunk->set_free();

    PhysicalDev* const pdev{chunk->get_physical_dev_mutable()};
    const auto freed_ids{pdev->merge_free_chunks(chunk)};
    for (const auto ids : freed_ids) {
        if (ids != INVALID_CHUNK_ID) { remove_chunk(pdev_group, ids); }
    }
    write_info_blocks(pdev_group);
}

vdev_info_block* DeviceManager::alloc_vdev(const PhysicalDevGroup pdev_group, const uint32_t req_size,
                                           const uint32_t nmirrors, const uint32_t page_size, const uint32_t nchunks,
                                           char* const blob, const uint64_t size) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};

    vdev_info_block* const vb{alloc_new_vdev_slot(pdev_group)};
    if (vb == nullptr) {
        std::ostringstream ss;
        ss << "No free slot available for virtual device creation";
        const std::string s{ss.str()};
        throw homestore::homestore_exception(s, homestore_error::no_space_avail);
    }
    vb->size = size;
    vb->num_mirrors = nmirrors;
    vb->page_size = page_size;
    vb->num_primary_chunks = nchunks;
    assert(req_size <= vdev_info_block::max_context_size());
    std::memcpy(vb->context_data, blob, req_size);

    auto& last_vdev_id{get_last_vdev_id(pdev_group)};
    vb->prev_vdev_id = last_vdev_id;
    auto& dm_derived{get_dm_derived(pdev_group)};
    if (last_vdev_id == INVALID_VDEV_ID) {
        // This is the first vdev being created.
        HS_DEBUG_ASSERT_EQ(dm_derived.vdev_hdr->get_first_vdev_id(), INVALID_VDEV_ID);
        dm_derived.vdev_hdr->first_vdev_id = vb->vdev_id;
    } else {
        auto* const prev_vb{&dm_derived.vdev_info[last_vdev_id]};
        prev_vb->next_vdev_id = vb->vdev_id;
    }
    last_vdev_id = vb->vdev_id;
    vb->next_vdev_id = INVALID_VDEV_ID;

    HS_LOG(DEBUG, device, "Creating vdev id = {} size = {} group = {}", vb->get_vdev_id(), vb->get_size(), pdev_group);
    dm_derived.vdev_hdr->num_vdevs++;
    write_info_blocks(pdev_group);
    return vb;
}

void DeviceManager::free_vdev(const PhysicalDevGroup pdev_group, vdev_info_block* const vb) {
    std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};

    const auto prev_vb_id{vb->prev_vdev_id};
    const auto next_vb_id{vb->next_vdev_id};

    auto& dm_derived{get_dm_derived(pdev_group)};
    if (prev_vb_id != INVALID_VDEV_ID) {
        dm_derived.vdev_info[prev_vb_id].next_vdev_id = next_vb_id;
    } else {
        dm_derived.vdev_hdr->first_vdev_id = vb->next_vdev_id;
    }

    if (next_vb_id != INVALID_VDEV_ID) dm_derived.vdev_info[next_vb_id].prev_vdev_id = prev_vb_id;
    vb->set_slot_allocated(false);

    --(dm_derived.vdev_hdr->num_vdevs);
    write_info_blocks(pdev_group);
}

/* This method creates a new chunk for a given physical device and attaches the chunk to the physical device
 * after previous chunk (if non-null) or last if null */
PhysicalDevChunk* DeviceManager::create_new_chunk(PhysicalDev* const pdev, const uint64_t start_offset,
                                                  const uint64_t size, PhysicalDevChunk* const prev_chunk) {
    uint32_t slot;

    // Allocate a slot for the new chunk (which becomes new chunk id) and create a new PhysicalDevChunk instance
    // and attach it to a physical device
    chunk_info_block* const c{alloc_new_chunk_slot(pdev->m_pdev_group, &slot)};
    if (c == nullptr) {
        std::ostringstream ss;
        ss << "No free slot available for chunk creation";
        const std::string s{ss.str()};
        throw homestore::homestore_exception(s, homestore_error::no_space_avail);
    }

    auto chunk{std::make_unique< PhysicalDevChunk >(pdev, slot, start_offset, size, c)};
    PhysicalDevChunk* const craw{chunk.get()};
    pdev->attach_chunk(craw, prev_chunk);

    HS_LOG(DEBUG, device, "Creating chunk: {}", chunk->to_string());
    if (pdev->m_pdev_group == PhysicalDevGroup::DATA) {
        m_data_chunks[chunk->get_chunk_id()] = std::move(chunk);
        ++(m_data_dm_derived.chunk_hdr->num_chunks);
    } else {
        m_fast_chunks[chunk->get_chunk_id()] = std::move(chunk);
        ++(m_fast_dm_derived.chunk_hdr->num_chunks);
    }

    return craw;
}

void DeviceManager::remove_chunk(const PhysicalDevGroup pdev_group, const uint32_t chunk_id) {
    auto& dm_derived{get_dm_derived(pdev_group)};
    HS_DEBUG_ASSERT_EQ(dm_derived.chunk_info[chunk_id].is_slot_allocated(), true);
    dm_derived.chunk_info[chunk_id].set_slot_allocated(false); // Free up the slot for future allocations
    --(dm_derived.chunk_hdr->num_chunks);
}

chunk_info_block* DeviceManager::alloc_new_chunk_slot(const PhysicalDevGroup pdev_group, uint32_t* const pslot_num) {
    auto& dm_derived{get_dm_derived(pdev_group)};
    const uint32_t start_slot{dm_derived.chunk_hdr->num_chunks};
    uint32_t cur_slot{start_slot};
    do {
        if (!dm_derived.chunk_info[cur_slot].is_slot_allocated()) {
            dm_derived.chunk_info[cur_slot].set_slot_allocated(true);
            *pslot_num = cur_slot;
            return &dm_derived.chunk_info[cur_slot];
        }
        ++cur_slot;
        if (cur_slot == HS_STATIC_CONFIG(engine.max_chunks)) cur_slot = 0;
    } while (cur_slot != start_slot);

    return nullptr;
}

vdev_info_block* DeviceManager::alloc_new_vdev_slot(const PhysicalDevGroup pdev_group) {
    auto& dm_derived{get_dm_derived(pdev_group)};
    for (uint32_t id{0}; id < HS_STATIC_CONFIG(engine.max_vdevs); ++id) {
        vdev_info_block* const vb{&dm_derived.vdev_info[id]};

        if (!vb->is_slot_allocated()) {
            vb->set_slot_allocated(true);
            vb->vdev_id = id;
            return vb;
        }
    }

    return nullptr;
}
} // namespace homestore
