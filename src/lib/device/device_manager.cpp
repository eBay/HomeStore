/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#include <vector>

#include <iomgr/iomgr.hpp>
#include <homestore/crc.h>
#include <sisl/logging/logging.h>

#include <boost/uuid/random_generator.hpp>

#include <homestore/homestore_decl.hpp>
#include "device/chunk.h"
#include "device/device.h"
#include "device/hs_super_blk.h"
#include "device/physical_dev.hpp"
#include "device/virtual_dev.hpp"
#include "common/homestore_utils.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {

static int determine_open_flags(io_flag oflags) {
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

static bool is_hdd(const std::string& devname) {
    const iomgr::drive_type dtype = iomgr::DriveInterface::get_drive_type(devname);
    if (dtype == iomgr::drive_type::block_hdd || dtype == iomgr::drive_type::file_on_hdd) { return true; }
    return false;
}

static void populate_vdev_info(const vdev_parameters& vparam, uint32_t vdev_id,
                               const std::vector< PhysicalDev* >& pdevs, vdev_info* out_info);

DeviceManager::DeviceManager(const std::vector< dev_info >& devs, vdev_create_cb_t vdev_create_cb) :
        m_dev_infos{devs}, m_vdev_create_cb{std::move(vdev_create_cb)} {
    bool found_hdd_dev{false};
    for (const auto& dev_info : devs) {
        if (is_hdd(dev_info.dev_name)) {
            HomeStoreStaticConfig::instance().hdd_drive_present = true;
            found_hdd_dev = true;
            break;
        }
    }

    if (found_hdd_dev) {
        if ((HS_STATIC_CONFIG(input.data_open_flags) == io_flag::DIRECT_IO) &&
            !HS_DYNAMIC_CONFIG(device->direct_io_mode)) {
            // override direct i/o for HDD's
            LOGINFO("Overridding HDD open flags from DIRECT_IO to BUFFERED_IO");
            m_hdd_open_flags = determine_open_flags(io_flag::BUFFERED_IO);
        } else {
            m_hdd_open_flags = determine_open_flags(HS_STATIC_CONFIG(input.data_open_flags));
        }
    }
    m_ssd_open_flags = determine_open_flags(HS_STATIC_CONFIG(input.fast_open_flags));

    // Read from all the devices and check if there is a valid superblock present in those devices.
    m_first_time_boot = true;
    for (const auto& d : devs) {
        first_block fblk = PhysicalDev::read_first_block(d.dev_name, device_open_flags(d.dev_name));
        if (fblk.is_valid()) {
            if (fblk.hdr.gen_number > m_first_blk_hdr.gen_number) { m_first_blk_hdr = fblk.hdr; }
            m_first_time_boot = false;
            break;
        }
    }
}

void DeviceManager::format_devices() {
    ++m_first_blk_hdr.gen_number;
    m_first_blk_hdr.version = first_block_header::CURRENT_SUPERBLOCK_VERSION;
    std::strncpy(m_first_blk_hdr.product_name, first_block_header::PRODUCT_NAME,
                 first_block_header::s_product_name_size);
    m_first_blk_hdr.num_pdevs = uint32_cast(m_dev_infos.size());
    m_first_blk_hdr.max_vdevs = hs_super_blk::MAX_VDEVS_IN_SYSTEM;
    m_first_blk_hdr.max_system_chunks = hs_super_blk::MAX_CHUNKS_IN_SYSTEM;
    m_first_blk_hdr.system_uuid = boost::uuids::random_generator()();

    // Get common iomgr_attributes
    for (auto& dinfo : m_dev_infos) {
        auto attr = iomgr::DriveInterface::get_attributes(dinfo.dev_name);
        if (dinfo.dev_size == 0) { dinfo.dev_size = PhysicalDev::get_dev_size(dinfo.dev_name); }
        auto sb_size = hs_super_blk::total_used_size(dinfo);
        auto buf = hs_utils::iobuf_alloc(sb_size, sisl::buftag::superblk, attr.align_size);
        std::memset(buf, 0, sb_size);

        first_block* fblk = r_cast< first_block* >(buf);
        fblk->magic = first_block::HOMESTORE_MAGIC;
        fblk->checksum = 0;          // Computed while writing the first block
        fblk->hdr = m_first_blk_hdr; // Entire header is copied as is
        auto pdev_id = populate_pdev_info(dinfo, attr, m_first_blk_hdr.system_uuid, fblk->this_pdev_hdr);
        fblk->checksum = crc32_ieee(init_crc32, uintptr_cast(fblk), first_block::s_atomic_fb_size);

        auto pdev = std::make_unique< PhysicalDev >(dinfo, device_open_flags(dinfo.dev_name), fblk->this_pdev_hdr);

        LOGINFO("Formatting Homestore on Device={} with first block as: [{}] total_super_blk_size={}", dinfo.dev_name,
                fblk->to_string(), sb_size);
        pdev->write_super_block(buf, sb_size, hs_super_blk::first_block_offset());

        auto it = m_pdevs_by_type.find(dinfo.dev_type);
        if (it == m_pdevs_by_type.end()) {
            bool happened;
            std::tie(it, happened) = m_pdevs_by_type.insert(std::pair{dinfo.dev_type, std::vector< PhysicalDev* >{}});
        }
        it->second.push_back(pdev.get());

        pdev->format_chunks();
        m_all_pdevs[pdev_id] = std::move(pdev);

        hs_utils::iobuf_free(buf, sisl::buftag::superblk);
    }
}

void DeviceManager::load_devices() {
    RELEASE_ASSERT_EQ(m_first_blk_hdr.version, first_block_header::CURRENT_SUPERBLOCK_VERSION,
                      "We don't support superblock version upgrade yet");

    RELEASE_ASSERT_EQ(m_first_blk_hdr.num_pdevs, m_dev_infos.size(),
                      "WARNING: The homestore is formatted with {} devices, but restarted with {} devices. Homestore "
                      "does not support dynamic addition/removal of devices",
                      m_first_blk_hdr.num_pdevs, m_dev_infos.size());

    for (const auto& d : m_dev_infos) {
        first_block fblk = PhysicalDev::read_first_block(d.dev_name, device_open_flags(d.dev_name));
        pdev_info_header* pinfo = &fblk.this_pdev_hdr;

        RELEASE_ASSERT_EQ(pinfo->get_system_uuid_str(), m_first_blk_hdr.get_system_uuid_str(),
                          "Device {} has uuid stamp different than this instance uuid. Perhaps device from other "
                          "homestore is provided?",
                          d.dev_name);

        auto pdev = std::make_unique< PhysicalDev >(d, device_open_flags(d.dev_name), *pinfo);
        LOGINFO("Loading Homestore from Device={} with first block as: [{}]", d.dev_name, fblk.to_string());

        auto it = m_pdevs_by_type.find(d.dev_type);
        if (it == m_pdevs_by_type.end()) {
            bool happened;
            std::tie(it, happened) = m_pdevs_by_type.insert(std::pair{d.dev_type, std::vector< PhysicalDev* >{}});
        }
        it->second.push_back(pdev.get());

        m_all_pdevs[pinfo->pdev_id] = std::move(pdev);
    }

    load_vdevs();
}

void DeviceManager::close_devices() {
    for (auto& pdev : m_all_pdevs) {
        if (pdev) { pdev->close_device(); }
    }
}

shared< VirtualDev > DeviceManager::create_vdev(vdev_parameters&& vparam) {
    std::unique_lock lg{m_vdev_mutex};

    // Allocate a new vdev_id
    auto vdev_id = m_vdev_id_bm.get_next_reset_bit(0u);
    if (vdev_id == sisl::Bitset::npos) { throw std::out_of_range("System has no room for additional vdev"); }
    m_vdev_id_bm.set_bit(vdev_id);

    std::vector< PhysicalDev* > pdevs = pdevs_by_type_internal(vparam.dev_type);
    RELEASE_ASSERT_GT(pdevs.size(), 0, "Unable to find any pdevs for given vdev type, can't create vdev");
    RELEASE_ASSERT(vparam.blk_size % pdevs[0]->align_size() == 0, "blk_size should be multiple of pdev align_size");
    // Identify the number of chunks
    if (vparam.multi_pdev_opts == vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED) {
        auto total_streams = std::accumulate(pdevs.begin(), pdevs.end(), 0u,
                                             [](int r, const PhysicalDev* a) { return r + a->num_streams(); });
        vparam.num_chunks = sisl::round_up(vparam.num_chunks, total_streams);
    } else if (vparam.multi_pdev_opts == vdev_multi_pdev_opts_t::ALL_PDEV_MIRRORED) {
        vparam.num_chunks = sisl::round_up(vparam.num_chunks, pdevs[0]->num_streams()) * pdevs.size();
    } else if (vparam.multi_pdev_opts == vdev_multi_pdev_opts_t::SINGLE_FIRST_PDEV) {
        pdevs.erase(pdevs.begin() + 1, pdevs.end()); // Just pick first device
    } else {
        pdevs.erase(pdevs.begin() + 1, pdevs.end()); // TODO: Pick random one
    }

    // Based on the min chunk size, we calculate the max number of chunks that can be created in each target pdev
    uint32_t min_chunk_size = hs_super_blk::min_chunk_size(vparam.dev_type);
    // FIXME: it is possible that each vdev is less than max_num_chunks, but total is more than MAX_CHUNKS_IN_SYSTEM.
    // uint32 convert is safe as it only overflow when vdev size > 64PB with 16MB min_chunk_size.
    uint32_t max_num_chunks = std::min(uint32_t(vparam.vdev_size / min_chunk_size), hs_super_blk::MAX_CHUNKS_IN_SYSTEM);

    auto input_vdev_size = vparam.vdev_size;
    if (vparam.size_type == vdev_size_type_t::VDEV_SIZE_STATIC) {
        // If its static size, vdev_size should be provided.
        RELEASE_ASSERT_GT(vparam.vdev_size, 0, "Vdev size cant be 0");

        // Either num_chunks or chunk_size can be provided and we calculate the other.
        if (vparam.num_chunks != 0) {
            auto input_num_chunks = vparam.num_chunks;
            // max chunk size is 4GB (uint32_max), capping it by tune up num_chunks
            uint32_t min_num_chunks = (vparam.vdev_size - 1) / std::numeric_limits< uint32_t >::max() + 1;
            vparam.num_chunks = std::max(vparam.num_chunks, min_num_chunks);
            vparam.num_chunks = std::min(vparam.num_chunks, max_num_chunks);

            if (input_num_chunks != vparam.num_chunks) {
                LOGINFO("{} Virtual device is attempted to be created with num_chunks={}, it needs to be adjust to "
                        "new_num_chunks={}",
                        vparam.vdev_name, in_bytes(input_num_chunks), in_bytes(vparam.num_chunks));
            }

            // this ensure chunk_size % vparam.blk_size == 0
            vparam.vdev_size = sisl::round_down(vparam.vdev_size, vparam.num_chunks * vparam.blk_size);
            if (input_vdev_size != vparam.vdev_size) {
                LOGINFO(
                    "{} Virtual device is attempted to be created with size={}, it needs to be rounded to new_size={}"
                    " to be the multiple of {} (num_chunks {} * blk_size {}).",
                    vparam.vdev_name, input_vdev_size, vparam.vdev_size, in_bytes(vparam.num_chunks * vparam.blk_size),
                    vparam.num_chunks, in_bytes(vparam.blk_size));
            }
            vparam.chunk_size = vparam.vdev_size / vparam.num_chunks;
        } else if (vparam.chunk_size != 0) {
            auto input_chunk_size = vparam.chunk_size;
            vparam.chunk_size = std::max(vparam.chunk_size, min_chunk_size);
            vparam.chunk_size = sisl::round_up(vparam.chunk_size, vparam.blk_size);
            if (input_chunk_size != vparam.chunk_size) {
                LOGINFO("{} Virtual device is attempted to be created with chunk_size={}, it needs to be adjust to "
                        "new_chunk_size={}",
                        vparam.vdev_name, in_bytes(input_chunk_size), in_bytes(vparam.chunk_size));
            }

            vparam.vdev_size = sisl::round_down(vparam.vdev_size, vparam.chunk_size);
            if (input_vdev_size != vparam.vdev_size) {
                LOGINFO(
                    "{} Virtual device is attempted to be created with size={}, it needs to be rounded to new_size={}",
                    vparam.vdev_name, in_bytes(input_vdev_size), in_bytes(vparam.vdev_size));
            }

            vparam.num_chunks = vparam.vdev_size / vparam.chunk_size;
        } else {
            RELEASE_ASSERT(false, "Both num_chunks and chunk_size cant be zero for vdev");
        }

    } else {
        // We need chunk_size. We start with zero num_chunks.
        RELEASE_ASSERT_GT(vparam.chunk_size, 0, "Chunk size should be provided");
        auto input_chunk_size = vparam.chunk_size;
        vparam.chunk_size = std::max(vparam.chunk_size, min_chunk_size);
        vparam.chunk_size = sisl::round_up(vparam.chunk_size, vparam.blk_size);
        if (input_chunk_size != vparam.chunk_size) {
            LOGINFO("{} Virtual device is attempted to be created with chunk_size={}, it needs to be adjust to "
                    "new_chunk_size={}",
                    vparam.vdev_name, in_bytes(input_chunk_size), in_bytes(vparam.chunk_size));
        }

        vparam.vdev_size = sisl::round_down(vparam.vdev_size, vparam.chunk_size);
        if (input_vdev_size != vparam.vdev_size) {
            LOGINFO("{} Virtual device is attempted to be created with size={}, it needs to be rounded to new_size={}",
                    vparam.vdev_name, in_bytes(input_vdev_size), in_bytes(vparam.vdev_size));
        }
    }
    // sanity checks
    RELEASE_ASSERT(vparam.vdev_size % vparam.chunk_size == 0, "vdev_size should be multiple of chunk_size");
    RELEASE_ASSERT(vparam.chunk_size % vparam.blk_size == 0, "chunk_size should be multiple of blk_size");
    RELEASE_ASSERT(vparam.chunk_size >= min_chunk_size, "chunk_size should be greater than or equal to min_chunk_size");

    RELEASE_ASSERT(vparam.num_chunks <= max_num_chunks, "num_chunks should be less than or equal to max_num_chunks");
    RELEASE_ASSERT(input_vdev_size >= vparam.vdev_size, "vdev_size should be less than or equal to input_vdev_size");

    LOGINFO(
        "New Virtal Dev={} of size={} with id={} is attempted to be created with multi_pdev_opts={}. The params are "
        "adjusted as follows: VDev_Size={} Num_pdevs={} Total_chunks_across_all_pdevs={} Each_Chunk_Size={}",
        vparam.vdev_name, in_bytes(input_vdev_size), vdev_id, vparam.multi_pdev_opts, in_bytes(vparam.vdev_size),
        pdevs.size(), vparam.num_chunks, in_bytes(vparam.chunk_size));

    // Convert the vparameters to the vdev_info
    auto buf = hs_utils::iobuf_alloc(vdev_info::size, sisl::buftag::superblk, pdevs[0]->align_size());
    auto vinfo = new (buf) vdev_info();
    populate_vdev_info(vparam, vdev_id, pdevs, vinfo);

    // Do a callback for the upper layer to create the vdev instance from vdev_info
    shared< VirtualDev > vdev = m_vdev_create_cb(*vinfo, false /* load_existing */);
    m_vdevs[vdev_id] = vdev;

    // Create initial chunk based on current size
    if (vparam.num_chunks != 0) {
        for (auto& pdev : pdevs) {
            std::vector< uint32_t > chunk_ids;

            // Create chunk ids for all chunks in each of these pdevs
            for (uint32_t c{0}; c < vparam.num_chunks / pdevs.size(); ++c) {
                auto chunk_id = m_chunk_id_bm.get_next_reset_bit(0u);
                if (chunk_id == sisl::Bitset::npos) {
                    throw std::out_of_range("System has no room for additional chunks");
                }
                m_chunk_id_bm.set_bit(chunk_id);
                chunk_ids.push_back(chunk_id);
            }

            // Create all chunks at one shot and add each one to the vdev
            auto chunks = pdev->create_chunks(chunk_ids, vdev_id, vparam.chunk_size);
            for (auto& chunk : chunks) {
                vdev->add_chunk(chunk, true /* fresh_chunk */);
                m_chunks[chunk->chunk_id()] = chunk;
            }
        }
    }

    // Handle any initialization needed.
    vdev->init();

    // Locate and write the vdev info in the super blk area of all pdevs this vdev will be created on
    for (auto& pdev : pdevs) {
        uint64_t offset = hs_super_blk::vdev_sb_offset() + (vdev_id * vdev_info::size);
        pdev->write_super_block(buf, vdev_info::size, offset);
    }

    vinfo->~vdev_info();
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);
    LOGINFO("Virtal Dev={} of size={} successfully created", vparam.vdev_name, in_bytes(vparam.vdev_size));
    return vdev;
}

void DeviceManager::load_vdevs() {
    std::unique_lock lg{m_vdev_mutex};

    for (auto& [dtype, pdevs] : m_pdevs_by_type) {
        auto vdev_infos = read_vdev_infos(pdevs);

        for (auto& vinfo : vdev_infos) {
            m_vdev_id_bm.set_bit(vinfo.vdev_id);
            m_vdevs[vinfo.vdev_id] = m_vdev_create_cb(vinfo, true /* load_existing */);
        }
    }

    // There are some vdevs load their chunks in each of pdev
    if (m_vdevs.size()) {
        for (auto& pdev : m_all_pdevs) {
            pdev->load_chunks([this](cshared< Chunk >& chunk) -> bool {
                // Found a chunk for which vdev information is missing
                if (m_vdevs[chunk->vdev_id()] == nullptr) {
                    LOGWARN("Found a chunk id={}, which is expected to be part of vdev_id={}, but that vdev "
                            "information is missing, may be before vdev is created, system crashed. Need upper layer "
                            "to retry vdev create",
                            chunk->chunk_id(), chunk->vdev_id());
                    return false;
                }
                m_chunk_id_bm.set_bit(chunk->chunk_id());
                m_chunks[chunk->chunk_id()] = chunk;
                HS_LOG(TRACE, device, "loaded chunks {} ", chunk->to_string())
                m_vdevs[chunk->vdev_id()]->add_chunk(chunk, false /* fresh_chunk */);
                return true;
            });
        }
    }

    // Run initialization of all vdevs.
    for (auto& vdev : m_vdevs) {
        vdev->init();
    }
}

shared< Chunk > DeviceManager::create_chunk(HSDevType dev_type, uint32_t vdev_id, uint64_t chunk_size,
                                            const sisl::blob& data) {
    std::unique_lock lg{m_vdev_mutex};
    auto pdevs = pdevs_by_type_internal(dev_type);
    auto chunk_id = m_chunk_id_bm.get_next_reset_bit(0u);
    if (chunk_id == sisl::Bitset::npos) { throw std::out_of_range("System has no room for additional chunk"); }
    m_chunk_id_bm.set_bit(chunk_id);

    shared< Chunk > chunk;
    PhysicalDev* pdev = nullptr;
    // Create a chunk on any pdev of device type.
    for (const auto& dev : pdevs) {
        // Ordinal added in add_chunk.
        chunk = dev->create_chunk(chunk_id, vdev_id, chunk_size, 0 /* ordinal */, data);
        if (chunk != nullptr) {
            pdev = dev;
            break;
        }
    }

    if (!chunk) { throw std::out_of_range("Unable to create chunk on physical devices"); }

    auto vdev = m_vdevs[vdev_id];
    vdev->add_chunk(chunk, true /* fresh_chunk */);
    m_chunks[chunk->chunk_id()] = chunk;

    auto buf = hs_utils::iobuf_alloc(vdev_info::size, sisl::buftag::superblk, pdev->align_size());
    auto vdev_info = vdev->info();
    vdev_info.vdev_size += chunk_size;
    vdev_info.num_primary_chunks++;
    vdev_info.compute_checksum();

    // Update the vdev info.
    vdev->update_info(vdev_info);
    std::memcpy(buf, &vdev_info, sizeof(vdev_info));
    uint64_t offset = hs_super_blk::vdev_sb_offset() + (vdev_id * vdev_info::size);
    pdev->write_super_block(buf, vdev_info::size, offset);
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);

    HS_LOG(TRACE, device, "Created chunk id={} dev_type={} vdev_id={} size={}", chunk_id, (uint8_t)dev_type, vdev_id,
           chunk_size);
    return chunk;
}

void DeviceManager::remove_chunk(shared< Chunk > chunk) {
    std::unique_lock lg{m_vdev_mutex};
    remove_chunk_locked(chunk);
}

void DeviceManager::remove_chunk_locked(shared< Chunk > chunk) {
    auto chunk_id = chunk->chunk_id();
    auto vdev_id = chunk->vdev_id();

    // Reset chunk id bitmap.
    m_chunk_id_bm.reset_bit(chunk_id);

    // Delete from the physical dev.
    auto pdev = chunk->physical_dev_mutable();
    pdev->remove_chunk(chunk);

    // Remove from the vdev.
    auto vdev = m_vdevs[vdev_id];
    vdev->remove_chunk(chunk);

    m_chunks[chunk_id].reset();

    // Update the vdev info.
    auto buf = hs_utils::iobuf_alloc(vdev_info::size, sisl::buftag::superblk, pdev->align_size());
    auto vdev_info = vdev->info();
    vdev_info.vdev_size -= vdev_info.chunk_size;
    vdev_info.num_primary_chunks--;
    vdev_info.compute_checksum();

    vdev->update_info(vdev_info);
    std::memcpy(buf, &vdev_info, sizeof(vdev_info));
    uint64_t offset = hs_super_blk::vdev_sb_offset() + (vdev_id * vdev_info::size);
    pdev->write_super_block(buf, vdev_info::size, offset);
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);

    HS_LOG(TRACE, device, "Removed chunk id={} vdev_id={}", chunk_id, vdev_id);
}

uint32_t DeviceManager::populate_pdev_info(const dev_info& dinfo, const iomgr::drive_attributes& attr,
                                           const uuid_t& uuid, pdev_info_header& pinfo) {
    bool hdd = is_hdd(dinfo.dev_name);

    pinfo.pdev_id = m_cur_pdev_id++;
    pinfo.mirror_super_block = hdd ? 0x01 : 0x00;
    pinfo.max_pdev_chunks = hs_super_blk::max_chunks_in_pdev(dinfo);

    auto sb_size = hs_super_blk::total_size(dinfo);
    pinfo.data_offset = hs_super_blk::first_block_offset() + sb_size;
    pinfo.size = dinfo.dev_size - pinfo.data_offset - (hdd ? sb_size : 0);
    pinfo.dev_attr = attr;
    pinfo.system_uuid = uuid;

    return pinfo.pdev_id;
}

uint64_t DeviceManager::total_capacity() const {
    uint64_t cap{0};
    for (const auto& pdev : m_all_pdevs) {
        cap += pdev->data_size();
    }
    return cap;
}

uint64_t DeviceManager::total_capacity(HSDevType dtype) const {
    uint64_t cap{0};
    const auto& pdevs = pdevs_by_type_internal(dtype);
    for (const auto& pdev : pdevs) {
        cap += pdev->data_size();
    }
    return cap;
}

static void populate_vdev_info(const vdev_parameters& vparam, uint32_t vdev_id,
                               const std::vector< PhysicalDev* >& pdevs, vdev_info* out_info) {
    out_info->vdev_size = vparam.vdev_size;
    out_info->vdev_id = vdev_id;
    out_info->num_mirrors = (vparam.multi_pdev_opts == vdev_multi_pdev_opts_t::ALL_PDEV_MIRRORED) ? pdevs.size() : 0;
    out_info->blk_size = vparam.blk_size;
    out_info->num_primary_chunks =
        (vparam.multi_pdev_opts == vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED) ? pdevs.size() : 1u;
    out_info->chunk_size = vparam.chunk_size;
    out_info->set_allocated();
    out_info->set_dev_type(vparam.dev_type);
    out_info->set_pdev_choice(vparam.multi_pdev_opts);
    out_info->set_name(vparam.vdev_name);
    out_info->set_user_private(vparam.context_data);
    out_info->alloc_type = s_cast< uint8_t >(vparam.alloc_type);
    out_info->chunk_sel_type = s_cast< uint8_t >(vparam.chunk_sel_type);
    out_info->compute_checksum();
}

std::vector< vdev_info > DeviceManager::read_vdev_infos(const std::vector< PhysicalDev* >& pdevs) {
    std::vector< vdev_info > ret_vinfos;
    auto buf =
        hs_utils::iobuf_alloc(hs_super_blk::vdev_super_block_size(), sisl::buftag::superblk, pdevs[0]->align_size());

    // TODO: Read from all pdevs and validate that they are correct
    pdevs[0]->read_super_block(buf, hs_super_blk::vdev_super_block_size(), hs_super_blk::vdev_sb_offset());

    uint8_t* ptr = buf;
    for (uint32_t v{0}; v < hs_super_blk::MAX_VDEVS_IN_SYSTEM; ++v, ptr += vdev_info::size) {
        vdev_info* vinfo = r_cast< vdev_info* >(ptr);
        if (vinfo->checksum != 0) {
            auto expected_crc = vinfo->checksum;
            vinfo->checksum = 0;
            auto crc = crc16_t10dif(hs_init_crc_16, r_cast< const unsigned char* >(vinfo), sizeof(vdev_info));
            RELEASE_ASSERT_EQ(crc, expected_crc, "VDev id={} mismatch on crc", v);
            vinfo->checksum = crc;
        }

        if (vinfo->slot_allocated) { ret_vinfos.push_back(*vinfo); }
    }

    hs_utils::iobuf_free(buf, sisl::buftag::superblk);
    return ret_vinfos;
}

int DeviceManager::device_open_flags(const std::string& devname) const {
    return is_hdd(devname) ? m_hdd_open_flags : m_ssd_open_flags;
}

std::vector< PhysicalDev* > DeviceManager::get_pdevs_by_dev_type(HSDevType dtype) const {
    return m_pdevs_by_type.at(dtype);
}

const std::vector< PhysicalDev* >& DeviceManager::pdevs_by_type_internal(HSDevType dtype) const {
    auto it = m_pdevs_by_type.find(dtype);
    if (it == m_pdevs_by_type.cend()) { it = m_pdevs_by_type.find(HSDevType::Data); }
    return it->second;
}

uint32_t DeviceManager::atomic_page_size(HSDevType dtype) const {
    return pdevs_by_type_internal(dtype)[0]->atomic_page_size();
}

uint32_t DeviceManager::optimal_page_size(HSDevType dtype) const {
    return pdevs_by_type_internal(dtype)[0]->optimal_page_size();
}
uint32_t DeviceManager::align_size(HSDevType dtype) const { return pdevs_by_type_internal(dtype)[0]->align_size(); }

std::vector< shared< VirtualDev > > DeviceManager::get_vdevs() const {
    std::vector< shared< VirtualDev > > ret_v;
    for (const auto& vdev : m_vdevs) {
        if (vdev != nullptr) { ret_v.push_back(vdev); }
    }
    return ret_v;
}

std::vector< shared< Chunk > > DeviceManager::get_chunks() const {
    std::unique_lock lg{m_vdev_mutex};
    std::vector< shared< Chunk > > res;
    res.reserve(m_chunks.size());
    for (auto& chunk : m_chunks) {
        if (chunk) res.push_back(chunk);
    }
    return res;
}

// Some of the hs_super_blk details
uint64_t hs_super_blk::vdev_super_block_size() { return (hs_super_blk::MAX_VDEVS_IN_SYSTEM * vdev_info::size); }

uint64_t hs_super_blk::chunk_super_block_size(const dev_info& dinfo) {
    return chunk_info_bitmap_size(dinfo) + (max_chunks_in_pdev(dinfo) * chunk_info::size);
}

ChunkPool::ChunkPool(DeviceManager& dmgr, Params&& params) : m_dmgr(dmgr), m_params(std::move(params)) {}

ChunkPool::~ChunkPool() {
    {
        std::unique_lock< std::mutex > lk{m_pool_mutex};
        m_run_pool = false;
        m_pool_cv.notify_one();
    }
    // Wait for the chunk pool to finish.
    m_pool_halt.getFuture().get();
    m_producer_thread.join();
}

void ChunkPool::start() {
    RELEASE_ASSERT(!m_run_pool, "Pool already started");
    {
        std::unique_lock< std::mutex > lk{m_pool_mutex};
        m_run_pool = true;
    }
    m_producer_thread = std::thread(&ChunkPool::producer, this);
    HS_LOG(INFO, device, "Starting chunk pool for vdev {}", m_params.vdev_id);
}

void ChunkPool::producer() {
    // Fill the chunk pool.
    while (true) {
        // Wait until run is false or pool is less than half the capacity
        // so that consumer have space to release unused chunks back to pool.
        std::unique_lock< std::mutex > lk{m_pool_mutex};
        m_pool_cv.wait(lk, [this] {
            if (m_run_pool == false) return true;
            if (m_pool.size() < (m_params.pool_capacity / 2)) return true;
            return false;
        });

        if (!m_run_pool) {
            m_pool_halt.setValue();
            return;
        }

        auto private_data = m_params.init_private_data_cb();
        auto chunk = m_dmgr.create_chunk(static_cast< HSDevType >(m_params.hs_dev_type), m_params.vdev_id,
                                         m_params.chunk_size, std::move(private_data));
        RELEASE_ASSERT(chunk, "Cannot create chunk");
        m_pool.push_back(chunk);
        HS_LOG(TRACE, device, "Produced chunk to pool id {} type {} vdev {} size {}", chunk->chunk_id(),
               m_params.hs_dev_type, m_params.vdev_id, m_params.chunk_size);
        m_pool_cv.notify_one();
    }
}

shared< Chunk > ChunkPool::dequeue() {
    RELEASE_ASSERT(m_run_pool, "Pool not started");
    shared< Chunk > chunk;
    {
        std::unique_lock< std::mutex > lk{m_pool_mutex};
        m_pool_cv.wait(lk, [this] { return !m_pool.empty(); });
        chunk = m_pool.back();
        m_pool.pop_back();
    }
    RELEASE_ASSERT(chunk, "Chunk invalid");
    HS_LOG(TRACE, device, "Dequeue chunk {} from pool", chunk->chunk_id());
    m_pool_cv.notify_one();
    return chunk;
}

bool ChunkPool::enqueue(shared< Chunk >& chunk) {
    RELEASE_ASSERT(chunk, "Chunk invalid");
    bool reuse = false;
    {
        std::unique_lock< std::mutex > lk{m_pool_mutex};
        if (m_pool.size() < m_params.pool_capacity) {
            chunk->set_user_private(m_params.init_private_data_cb());
            m_pool.push_back(chunk);
            reuse = true;
            HS_LOG(TRACE, device, "Enqueue chunk {} to pool", chunk->chunk_id());
        }
    }

    if (!reuse) {
        // If cache is full, remove the chunk.
        HS_LOG(TRACE, device, "Cache is full removing chunk {}", chunk->chunk_id());
        m_dmgr.remove_chunk(chunk);
    } else {
        m_pool_cv.notify_one();
    }
    return reuse;
}

} // namespace homestore
