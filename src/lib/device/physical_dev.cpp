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
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <system_error>

#ifdef __linux__
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include <folly/Exception.h>
#include <iomgr/iomgr.hpp>

#include <homestore/meta_service.hpp>

#include "physical_dev.hpp"
#include "device.h"
#include "blkalloc/blk_allocator.h"
#include "common/homestore_flip.hpp"
#include "common/homestore_utils.hpp"

namespace homestore {

static std::atomic< uint64_t > glob_phys_dev_offset{0};
static std::atomic< uint32_t > glob_phys_dev_ids{0};

const size_t dm_info::s_pdev_info_blocks_size = sizeof(pdev_info_block) * HS_STATIC_CONFIG(engine.max_pdevs);
const size_t dm_info::s_vdev_info_blocks_size = sizeof(vdev_info_block) * HS_STATIC_CONFIG(engine.max_vdevs);
size_t dm_info::s_chunk_info_blocks_size = sizeof(chunk_info_block) * HS_STATIC_CONFIG(engine.max_chunks);
size_t dm_info::s_dm_info_block_size{sizeof(dm_info) + s_pdev_info_blocks_size + s_chunk_info_blocks_size +
                                     s_vdev_info_blocks_size};

// this constructor is to read superblock to determine whether it is first time boot;
//
PhysicalDev::PhysicalDev(const std::string& devname, int oflags) : m_devname{devname}, m_metrics{devname} {
    read_and_fill_superblock(oflags);
}

// first time and recovery boot constructor goes here;
//
PhysicalDev::PhysicalDev(DeviceManager* mgr, const std::string& devname, int oflags, const hs_uuid_t& system_uuid,
                         uint32_t dev_num, uint64_t dev_offset, bool is_init, uint64_t dm_info_size,
                         const iomgr::io_interface_comp_cb_t& io_comp_cb, bool* is_inited) :
        m_mgr{mgr}, m_devname{devname}, m_metrics{devname} {
    read_and_fill_superblock(oflags);

    if (is_init) { m_super_blk->set_system_uuid(system_uuid); }
    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = INVALID_CHUNK_ID;

    int oflags_used = oflags;
    if (devname.find("/tmp") == 0 ||
        ((m_drive_iface->interface_type() == drive_interface_type::uring) && !m_mgr->is_hdd_direct_io_mode())) {
        // tmp directory in general does not allow Direct I/O
        LOGINFO("Trying to remove O_DIRECT bit from open flags: before: {}, after: {}", oflags_used,
                oflags & (~O_DIRECT));
        oflags_used &= ~O_DIRECT;
    }

    LOGINFO("Opening device {} with {} mode.", devname, oflags_used & O_DIRECT ? "DIRECT_IO" : "BUFFERED_IO");

    m_iodev = iomgr::DriveInterface::open_dev(devname, oflags_used);
    if (m_iodev == nullptr
#ifdef _PRERELEASE
        || (homestore_flip->test_flip("device_boot_fail", devname.c_str()))
#endif
    ) {

        free_superblock();
        HS_LOG(ERROR, device, "device open failed errno {} dev_name {}", errno, devname.c_str());
        throw std::system_error(errno, std::system_category(), "error while opening the device");
    }
    m_drive_iface = m_iodev->drive_interface();
    m_drive_iface->attach_completion_cb(io_comp_cb);

    // Get the device size
    try {
        m_devsize = m_drive_iface->get_size(m_iodev.get());
    } catch (std::exception& e) {
        free_superblock();
        throw(e);
    }

    if (m_devsize == 0) {
        auto const s = fmt::format("Device {} size={} is too small", devname, m_devsize);
        HS_LOG_ASSERT(0, s.c_str());
        throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
    }

    auto const current_size = m_devsize;
    m_devsize = sisl::round_down(m_devsize, page_size());
    if (m_devsize != current_size) {
        LOGWARN("device size is not the multiple of physical page size old size {}", current_size);
    }
    LOGINFO("Device {} opened with dev_id={} size={}", m_devname, m_iodev->dev_id(), in_bytes(m_devsize));
    m_dm_chunk[0] = m_dm_chunk[1] = nullptr;
    if (is_init) {
        /* create a chunk */
        uint64_t const sb_size = SUPERBLOCK_SIZE(page_size());
        HS_LOG_ASSERT_EQ((size() % page_size()), 0, "Expected drive size to be aligned with physical page size");
        m_mgr->create_new_chunk(this, sb_size, size() - sb_size, nullptr);
        m_mgr->incr_num_sys_chunks();

        /* check for min size */
        uint64_t const min_size = sb_size + 2 * dm_info_size;
        if (m_devsize <= min_size) {
            auto const s = fmt::format("Device {} size={} is too small min_size={}", m_devname, m_devsize, min_size);
            HS_LOG_ASSERT(0, s.c_str());
            throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
        }

        /* We create two chunks for super blocks. Since writing a sb chunk is not atomic operation,
         * so at any given point only one SB chunk is valid.
         */
        for (size_t i{0}; i < 2; ++i) {
            HS_LOG_ASSERT_EQ((dm_info_size % page_size()), 0, "dm size is not aligned {}", dm_info_size);
            m_dm_chunk[i] = m_mgr->alloc_chunk(this, INVALID_VDEV_ID, dm_info_size, INVALID_CHUNK_ID);
            m_mgr->incr_num_sys_chunks();
            m_dm_chunk[i]->set_sb_chunk();
        }
        /* super block is written when first DM info block is written. Writing a superblock and making
         * a disk valid before that doesn't make sense as that disk is of no use until DM info is not
         * written.
         */
    } else {
        *is_inited = load_super_block(system_uuid);
        if (*is_inited) {
            /* If it is different then it mean it require upgrade/revert handling */
            HS_LOG_ASSERT_EQ(m_super_blk->dm_chunk[0].get_chunk_size(), dm_info_size);
            HS_LOG_ASSERT_EQ(m_super_blk->dm_chunk[1].get_chunk_size(), dm_info_size);
            if (is_init_done() == false) { init_done(); }
        }
    }
}

PhysicalDev::~PhysicalDev() {
    LOGINFO("device name {} superblock magic {:#x} product name {} version {}", m_devname, m_super_blk->get_magic(),
            m_super_blk->get_product_name(), m_super_blk->get_version());
    free_superblock();
}

void PhysicalDev::update(uint32_t dev_num, uint64_t dev_offset, uint32_t f_chunk_id) {
    HS_DBG_ASSERT_EQ(dev_id(), INVALID_DEV_ID);
    HS_DBG_ASSERT_EQ(first_chunk_id(), INVALID_CHUNK_ID);

    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = f_chunk_id;
}

void PhysicalDev::attach_superblock_chunk(PhysicalDevChunk* chunk) {
    if (!m_superblock_valid) {
        HS_DBG_ASSERT_NULL(m_dm_chunk[m_cur_indx]);
        HS_DBG_ASSERT_LT(m_cur_indx, 2);
        m_dm_chunk[m_cur_indx++] = chunk;
        return;
    }
    if (chunk->chunk_id() == m_super_blk->dm_chunk[0].chunk_id) {
        HS_DBG_ASSERT_NULL(m_dm_chunk[0]);
        m_dm_chunk[0] = chunk;
    } else {
        HS_DBG_ASSERT_EQ(chunk->chunk_id(), m_super_blk->dm_chunk[1].chunk_id);
        HS_DBG_ASSERT_NULL(m_dm_chunk[1]);
        m_dm_chunk[1] = chunk;
    }
}

void PhysicalDev::free_superblock() { hs_utils::iobuf_free(uintptr_cast(m_super_blk), sisl::buftag::superblk); }

void PhysicalDev::alloc_superblock(uint32_t sb_size, uint32_t align_sz) {
    auto* membuf = hs_utils::iobuf_alloc(sb_size, sisl::buftag::superblk, align_sz);

    m_super_blk = new (membuf) super_block{};
    if (sizeof(super_block) < sb_size) { std::memset(membuf + sizeof(super_block), 0, sb_size - sizeof(super_block)); }
}

bool PhysicalDev::resize_superblock_if_needed(uint32_t phys_page_sz, uint32_t align_size) {
    auto const sb_size = SUPERBLOCK_SIZE(phys_page_sz);

    // it is fine atomic page size + pyaload size is larger than super_block size;
    HS_REL_ASSERT_LE(super_block::s_min_sb_size, sb_size);
    auto const saved_sb_ptr = m_super_blk;
    if (super_block::s_min_sb_size < sb_size) {
        alloc_superblock(sb_size, align_size); // need to resize the superblock_size
        // copy old sb content to new one;
        std::memcpy(uintptr_cast(m_super_blk), uintptr_cast(saved_sb_ptr), super_block::s_min_sb_size);
        hs_utils::iobuf_free(uintptr_cast(saved_sb_ptr), sisl::buftag::superblk); // free the old superblock;
        return true;
    }

    return false;
}

void PhysicalDev::read_and_fill_superblock(int oflags) {
    // allocate minimal size of superblock for read;
    auto const minimal_sb_size = super_block::s_min_sb_size;
    alloc_superblock(minimal_sb_size, 512);

    m_iodev = iomgr::DriveInterface::open_dev(m_devname, oflags);
    m_drive_iface = m_iodev->drive_interface();

    auto const bytes_read = m_drive_iface->sync_read(m_iodev.get(), reinterpret_cast< char* >(m_super_blk),
                                                     static_cast< uint32_t >(minimal_sb_size), 0);
    if (sisl_unlikely((bytes_read < 0) || (static_cast< size_t >(bytes_read) != minimal_sb_size))) {
        throw std::system_error(errno, std::system_category(), "error while reading a superblock" + get_devname());
    }

    bool is_init_required = false;
    auto const iomgr_attr = iomgr::DriveInterface::get_attributes(m_devname);
    LOGINFO("Device Superblock {}", m_super_blk->to_string());

    if (validate_device()) {
        if (!is_from_upgradable_version()) {
            // Now we know that superblock is valid. So resize it by reading it from the superblock.
            resize_superblock_if_needed(page_size(), align_size());
            return;
        }
    } else {
        is_init_required = true;
    }

    /* It require either upgrade or initialization */
    resize_superblock_if_needed(iomgr_attr.phys_page_size, iomgr_attr.align_size);

    if (is_init_required) {
        m_super_blk->magic = MAGIC;
        std::strncpy(m_super_blk->product_name, PRODUCT_NAME, super_block::s_product_name_size);
        m_super_blk->product_name[super_block::s_product_name_size - 1] = 0;
    }

    // write back updated or saved attributes only when it is zerored or resized;

    // It is a new fields added in superblock in 1.3
    m_super_blk->dev_attr.phys_page_size = iomgr_attr.phys_page_size;
    m_super_blk->dev_attr.align_size = iomgr_attr.align_size;
    m_super_blk->dev_attr.atomic_phys_page_size = iomgr_attr.atomic_phys_page_size;
    m_super_blk->dev_attr.num_streams = iomgr_attr.num_streams;

    m_super_blk->version = CURRENT_SUPERBLOCK_VERSION;

    HS_REL_ASSERT(m_super_blk->dev_attr.is_valid(), "invalid device attributes: {}", m_super_blk->dev_attr.to_string());

    // now perisit the attr to disk;
    write_superblock();

    LOGINFO("Stored dev_attr from iomgr: {} for device id: {}", m_super_blk->dev_attr.to_string(),
            m_super_blk->this_dev_info.dev_num);
}

size_t PhysicalDev::total_cap() const {
    return (m_devsize - (SUPERBLOCK_SIZE(page_size()) + m_dm_chunk[0]->size() + m_dm_chunk[1]->size()));
}

bool PhysicalDev::load_super_block(const hs_uuid_t& system_uuid) {
    // read_superblock();

    // Validate if its homestore formatted device
    const bool is_omstore_dev = validate_device();
    if (!is_omstore_dev) {
        LOGCRITICAL("invalid device name {} found magic {} product name {} version {}", m_devname,
                    m_super_blk->get_magic(), m_super_blk->get_product_name(), m_super_blk->get_version());
        return false;
    }

    if (m_super_blk->get_system_uuid() != system_uuid) {
        auto const s = fmt::format("we found the homestore formatted device with a different system UUID");
        LOGCRITICAL("{}", s);
        throw homestore::homestore_exception(s, homestore_error::formatted_disk_found);
    }

    m_info_blk.dev_num = m_super_blk->this_dev_info.dev_num;
    m_info_blk.dev_offset = m_super_blk->this_dev_info.dev_offset;
    m_info_blk.first_chunk_id = m_super_blk->this_dev_info.first_chunk_id;
    m_cur_indx = m_super_blk->cur_indx;
    m_superblock_valid = true;

    return true;
}

void PhysicalDev::read_dm_chunk(char* const mem, const uint64_t size) {
    HS_DBG_ASSERT_EQ(m_super_blk->dm_chunk[m_cur_indx & s_dm_chunk_mask].get_chunk_size(), size);
    auto const offset = m_super_blk->dm_chunk[m_cur_indx & s_dm_chunk_mask].chunk_start_offset;
    m_drive_iface->sync_read(m_iodev.get(), mem, size, offset);
}

void PhysicalDev::write_dm_chunk(const uint64_t gen_cnt, const char* const mem, const uint64_t size) {
    auto const offset = m_dm_chunk[(++m_cur_indx) & s_dm_chunk_mask]->start_offset();
    m_drive_iface->sync_write(m_iodev.get(), mem, size, offset);
    write_super_block(gen_cnt);
}

uint64_t PhysicalDev::sb_gen_cnt() { return m_super_blk->gen_cnt; }

void PhysicalDev::write_super_block(const uint64_t gen_cnt) {
    // Format the super block and this device info structure
    HS_DBG_ASSERT_NE(dev_id(), INVALID_DEV_ID);
    HS_DBG_ASSERT_NE(first_chunk_id(), INVALID_CHUNK_ID);

    m_super_blk->this_dev_info.dev_num = m_info_blk.dev_num;
    m_super_blk->this_dev_info.first_chunk_id = m_info_blk.first_chunk_id;
    m_super_blk->this_dev_info.dev_offset = m_info_blk.dev_offset;
    m_super_blk->gen_cnt = gen_cnt;
    m_super_blk->cur_indx = m_cur_indx;

    for (size_t i{0}; i < super_block::s_num_dm_chunks; ++i) {
        std::memcpy(voidptr_cast(&(m_super_blk->dm_chunk[i])), s_cast< const void* >(m_dm_chunk[i]->chunk_info()),
                    sizeof(chunk_info_block));
    }

    // Write the information to the offset
    write_superblock();
    m_superblock_valid = true;
}

void PhysicalDev::zero_boot_sbs(const std::vector< dev_info >& devices, int oflags) {
    if (devices.empty()) { return; }

    for (const auto& dev : devices) {
        // alloc re-usable super block
        auto const dev_type = dev.dev_type;
        const std::string& dev_str = dev.dev_names;
        auto const superblock_size = super_block::s_min_sb_size;
        auto* membuf = hs_utils::iobuf_alloc(superblock_size, sisl::buftag::superblk, 512);
        super_block* super_blk = new (membuf) super_block{};
        if (sizeof(super_block) < superblock_size) {
            std::memset(membuf + sizeof(super_block), 0, superblock_size - sizeof(super_block));
        }

        HS_LOG_ASSERT_LE(sizeof(super_block), superblock_size,
                         "Device {} Ondisk Superblock size not enough to hold in-mem", dev_str);
        // open device
        auto iodev = iomgr::DriveInterface::open_dev(dev_str, oflags);

        // write zeroed sb to disk
        auto const bytes =
            iodev->drive_interface()->sync_write(iodev.get(), (const char*)super_blk, superblock_size, 0);
        if (sisl_unlikely((bytes < 0) || (static_cast< size_t >(bytes) != superblock_size))) {
            LOGINFO("Failed to zeroed superblock of device: {}, errno: {}", dev_str, errno);
            throw std::system_error(errno, std::system_category(), "error while writing a superblock" + dev_str);
        }

        LOGINFO("Successfully zeroed superblock of device: {}", dev_str);

        // close device;
        iodev->drive_interface()->close_dev(iodev);
        // free super_blk
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(super_blk), sisl::buftag::superblk);
    }
}

bool PhysicalDev::has_valid_superblock(hs_uuid_t& out_uuid) {
    // read_superblock();

    // Validate if its homestore formatted device
    const bool ret = (validate_device() && is_init_done());

    if (ret) { out_uuid = m_super_blk->get_system_uuid(); }
    return ret;
}

void PhysicalDev::close_device() { m_drive_iface->close_dev(m_iodev); }

void PhysicalDev::init_done() {
    m_super_blk->set_init_done(true);
    write_superblock();
}

// this function needs to be updated for new releases;
inline bool PhysicalDev::is_from_upgradable_version() const {
    if (m_super_blk->version < SUPERBLOCK_VERSION_1_3) {
        // we only support 1.2 to 1.3 upgrade;
        return CURRENT_SUPERBLOCK_VERSION == SUPERBLOCK_VERSION_1_3;
    } else {
        if (m_super_blk->version != CURRENT_SUPERBLOCK_VERSION) {
            LOGCRITICAL("Trying to upgrade from unrecogonized old release: {} to current release: {}",
                        m_super_blk->version, CURRENT_SUPERBLOCK_VERSION);
            HS_REL_ASSERT(false, "Unsupported upgrade path {} to {}", m_super_blk->version, CURRENT_SUPERBLOCK_VERSION);
        }

        // we are just doing a normal reboot
        return false;
    }
}

inline bool PhysicalDev::validate_device() const {
    return (m_super_blk->magic == MAGIC) && (std::strcmp(m_super_blk->product_name, PRODUCT_NAME) == 0) &&
        (m_super_blk->version == CURRENT_SUPERBLOCK_VERSION ||
         is_from_upgradable_version()); // version can be current or from an upgradable old version;
}

inline void PhysicalDev::write_superblock() {
    auto const superblock_size = SUPERBLOCK_SIZE(page_size());
    auto const bytes{m_drive_iface->sync_write(m_iodev.get(), reinterpret_cast< const char* >(m_super_blk),
                                               static_cast< uint32_t >(superblock_size), 0)};
    if (sisl_unlikely((bytes < 0) || (static_cast< size_t >(bytes) != superblock_size))) {

        throw std::system_error(errno, std::system_category(), "error while writing a superblock" + get_devname());
    }
}

inline void PhysicalDev::read_superblock() {
    auto const superblock_size = SUPERBLOCK_SIZE(page_size());
    auto const bytes{m_drive_iface->sync_read(m_iodev.get(), reinterpret_cast< char* >(m_super_blk),
                                              static_cast< uint32_t >(superblock_size), 0)};
    if (sisl_unlikely((bytes < 0) || (static_cast< size_t >(bytes) != superblock_size))) {
        throw std::system_error(errno, std::system_category(), "error while reading a superblock" + get_devname());
    }
}

folly::Future< bool > PhysicalDev::async_write(const char* data, uint32_t size, uint64_t offset bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    return m_drive_iface->async_write(m_iodev.get(), data, size, offset, part_of_batch)
        .thenError([this](auto const& e) -> bool {
            LOGERROR("Error on async_write: exception={}", e.what());
            device_manager_mutable()->handle_error(this);
            return false;
        });
}

folly::Future< bool > PhysicalDev::async_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                                bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    return m_drive_iface->async_writev(m_iodev.get(), iov, iovcnt, size, offset, part_of_batch)
        .thenError([this](auto const& e) -> bool {
            LOGERROR("Error on async_writev: exception={}", e.what());
            device_manager_mutable()->handle_error(this);
            return false;
        });
}

folly::Future< bool > PhysicalDev::async_read(char* data, uint32_t size, uint64_t offset, bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    return m_drive_iface->async_read(m_iodev.get(), data, size, offset, part_of_batch)
        .thenError([this](auto const& e) -> bool {
            LOGERROR("Error on async_read: exception={}", e.what());
            device_manager_mutable()->handle_error(this);
            return false;
        });
}

folly::Future< bool > PhysicalDev::async_readv(iovec* iov, int iovcnt, uint32_t size, uint64_t offset,
                                               bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    return m_drive_iface->async_readv(m_iodev.get(), iov, iovcnt, size, offset, part_of_batch)
        .thenError([this](auto const& e) -> bool {
            LOGERROR("Error on async_readv: exception={}", e.what());
            device_manager_mutable()->handle_error(this);
            return false;
        });
}

folly::Future< bool > PhysicalDev::async_write_zero(uint64_t size, uint64_t offset) {
    return m_drive_iface->async_write_zero(m_iodev.get(), size, offset).thenError([this](auto const& e) -> bool {
        LOGERROR("Error on async_write_zero: exception={}", e.what());
        device_manager_mutable()->handle_error(this);
        return false;
    });
}

folly::Future< bool > PhysicalDev::queue_fsync() { m_drive_iface->queue_fsync(m_iodev.get()); }

void PhysicalDev::sync_write(const char* data, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
        COUNTER_INCREMENT(m_metrics, drive_sync_write_count, 1);
        auto const start_time = Clock::now();
        m_drive_iface->sync_write(m_iodev.get(), data, size, offset);
        HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
    }
}

void PhysicalDev::sync_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
        COUNTER_INCREMENT(m_metrics, drive_sync_write_count, 1);
        auto const start_time = Clock::now();
        m_drive_iface->sync_writev(m_iodev.get(), iov, iovcnt, size, offset);
        HISTOGRAM_OBSERVE(m_metrics, drive_write_latency, get_elapsed_time_us(start_time));
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
    }
}

void PhysicalDev::sync_read(char* data, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
        COUNTER_INCREMENT(m_metrics, drive_sync_read_count, 1);
        auto const start_time = Clock::now();
        m_drive_iface->sync_read(m_iodev.get(), data, size, offset);
        HISTOGRAM_OBSERVE(m_metrics, drive_read_latency, get_elapsed_time_us(start_time));
        return ret;
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
    }
}

void PhysicalDev::sync_readv(iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
        COUNTER_INCREMENT(m_metrics, drive_sync_read_count, 1);
        auto const start_time = Clock::now();
        m_drive_iface->sync_readv(m_iodev.get(), iov, iovcnt, size, offset);
        HISTOGRAM_OBSERVE(m_metrics, drive_read_latency, get_elapsed_time_us(start_time));
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
    }
}

void PhysicalDev::sync_write_zero(uint64_t size, uint64_t offset) {
    m_drive_iface->sync_write_zero(m_iodev.get(), size, offset);
}

void PhysicalDev::attach_chunk(PhysicalDevChunk* chunk, PhysicalDevChunk* after) {
    if (after) {
        chunk->set_next_chunk(after->next_chunk_mutable());
        chunk->set_prev_chunk(after);

        auto* next = after->next_chunk_mutable();
        if (next) next->set_prev_chunk(chunk);
        after->set_next_chunk(chunk);
    } else {
        HS_DBG_ASSERT_EQ(first_chunk_id(), INVALID_CHUNK_ID);
        m_info_blk.first_chunk_id = chunk->chunk_id();
    }
}

std::array< uint32_t, 2 > PhysicalDev::merge_free_chunks(PhysicalDevChunk* chunk) {
    std::array< uint32_t, 2 > freed_ids{INVALID_CHUNK_ID, INVALID_CHUNK_ID};
    uint32_t nids{0};

    // Check if previous and next chunk are free, if so make it contiguous chunk
    PhysicalDevChunk* prev_chunk = chunk->prev_chunk_mutable();
    PhysicalDevChunk* next_chunk = chunk->next_chunk_mutable();

    if (prev_chunk && !prev_chunk->is_busy()) {
        // We can merge our space to prev_chunk and remove our current chunk.
        prev_chunk->set_size(prev_chunk->size() + chunk->size());
        prev_chunk->set_next_chunk(chunk->next_chunk_mutable());

        // Erase the current chunk entry
        prev_chunk->set_next_chunk(chunk->next_chunk_mutable());
        if (next_chunk) next_chunk->set_prev_chunk(prev_chunk);

        freed_ids[nids++] = chunk->chunk_id();
        chunk = prev_chunk;
    }

    if (next_chunk && !next_chunk->is_busy()) {
        next_chunk->set_size(chunk->size() + next_chunk->size());
        next_chunk->set_start_offset(chunk->start_offset());

        // Erase the current chunk entry
        next_chunk->set_prev_chunk(chunk->prev_chunk_mutable());
        auto* p = chunk->prev_chunk_mutable();
        if (p) p->set_next_chunk(next_chunk);
        freed_ids[nids++] = chunk->chunk_id();
    }
    return freed_ids;
}

pdev_info_block PhysicalDev::get_info_blk() { return m_info_blk; }

PhysicalDevChunk* PhysicalDev::find_free_chunk(uint64_t req_size) {
    // Get the slot with closest size;
    PhysicalDevChunk* closest_chunk{nullptr};

    PhysicalDevChunk* chunk = device_manager_mutable()->get_chunk_mutable(m_info_blk.first_chunk_id);
    while (chunk) {
        auto const size = chunk->size();
        if (!chunk->is_busy() && size >= req_size) {
            if ((closest_chunk == nullptr) || (chunk->size() < closest_chunk->size())) { closest_chunk = chunk; }
        }

        chunk = device_manager_mutable()->get_chunk_mutable(chunk->next_chunk_id());
    }

    if (closest_chunk == nullptr) {
        LOGWARN("No available chunk found for req_size: {}, this devsize={}, num_streams={}, id={}, page_size={}",
                in_bytes(req_size), in_bytes(size()), num_streams(), dev_id(), in_bytes(page_size()));
    } else {
        LOGINFO("Found free chunk for req_size: {}, in devid={}", in_bytes(req_size), dev_id());
    }

    return closest_chunk;
}

std::string PhysicalDev::to_string() const {
    auto str = fmt::format("Device={}, ID={}, Size={}, SuperBlk=[{}], Chunks[", m_devname, m_iodev->dev_id(), size(),
                           m_super_blk->to_string());
    const PhysicalDevChunk* pchunk = device_manager()->get_chunk(m_info_blk.first_chunk_id);
    while (pchunk) {
        str += pchunk->to_string();
        pchunk = pchunk->next_chunk();
    }
    str += "]";
    return str;
}

bool PhysicalDev::is_hdd() const {
    const iomgr::drive_type dtype = iomgr::DriveInterface::get_drive_type(m_devname);
    if (dtype == iomgr::drive_type::block_hdd || dtype == iomgr::drive_type::file_on_hdd) { return true; }
    return false;
}

uint64_t PhysicalDev::raw_stream_size() const {
    if (!is_hdd()) { return size(); }
    return size() / num_streams();
}

uint64_t PhysicalDev::stream_aligned_offset() const { return (size() / num_streams()); }
uint32_t PhysicalDev::align_size() const { return m_super_blk->dev_attr.align_size; }
uint32_t PhysicalDev::page_size() const { return m_super_blk->dev_attr.phys_page_size; }
uint32_t PhysicalDev::atomic_page_size() const { return m_super_blk->dev_attr.atomic_phys_page_size; }
uint32_t PhysicalDev::num_streams() const { return m_super_blk->dev_attr.num_streams; }

#if 0
uint64_t PhysicalDev::get_stream_offset_multiple() {
    if (!is_hdd()) { return 0; }
    auto const page_size = (m_pdev_group == PhysicalDevGroup::DATA ? HS_STATIC_CONFIG(data_drive_attr.phys_page_size)
                                                             : HS_STATIC_CONFIG(fast_drive_attr.phys_page_size));
    return sisl::round_up((size() / 10), page_size);
}
#endif

/********************* PhysicalDevChunk Section ************************/
PhysicalDevChunk::PhysicalDevChunk(PhysicalDev* pdev, chunk_info_block* cinfo) {
    m_chunk_info = cinfo;
    m_pdev = pdev;
#if 0
    const std::unique_ptr< PhysicalDev > &p =
            (static_cast<const homeds::sparse_vector< std::unique_ptr< PhysicalDev > > &>(device_manager()->m_pdevs))[cinfo->pdev_id];
    m_pdev = p.get();
#endif
}

PhysicalDevChunk::PhysicalDevChunk(PhysicalDev* pdev, uint32_t chunk_id, uint64_t start_offset, uint64_t size,
                                   chunk_info_block* cinfo) {
    m_chunk_info = cinfo;
    // Fill in with new chunk info
    m_chunk_info->chunk_id = chunk_id;
    m_chunk_info->set_slot_allocated(true);
    m_chunk_info->pdev_id = pdev->dev_id();
    m_chunk_info->chunk_start_offset = start_offset;
    m_chunk_info->chunk_size = size;
    m_chunk_info->prev_chunk_id = INVALID_CHUNK_ID;
    m_chunk_info->next_chunk_id = INVALID_CHUNK_ID;
    m_chunk_info->primary_chunk_id = INVALID_CHUNK_ID;
    m_chunk_info->vdev_id = INVALID_VDEV_ID;
    m_chunk_info->set_sb_chunk(false);
    m_chunk_info->end_of_chunk_size = static_cast< int64_t >(size);
    m_pdev = pdev;
}

PhysicalDevChunk::~PhysicalDevChunk() {}

const PhysicalDevChunk* PhysicalDevChunk::next_chunk() const { return device_manager()->get_chunk(next_chunk_id()); }

PhysicalDevChunk* PhysicalDevChunk::next_chunk_mutable() {
    return device_manager_mutable()->get_chunk_mutable(next_chunk_id());
}

const PhysicalDevChunk* PhysicalDevChunk::prev_chunk() const { return device_manager()->get_chunk(prev_chunk_id()); }

PhysicalDevChunk* PhysicalDevChunk::prev_chunk_mutable() {
    return device_manager_mutable()->get_chunk_mutable(prev_chunk_id());
}

const PhysicalDevChunk* PhysicalDevChunk::primary_chunk() const {
    return device_manager()->get_chunk(m_chunk_info->primary_chunk_id);
}

PhysicalDevChunk* PhysicalDevChunk::primary_chunk_mutable() {
    return device_manager_mutable()->get_chunk_mutable(m_chunk_info->primary_chunk_id);
}

const DeviceManager* PhysicalDevChunk::device_manager() const { return physical_dev()->device_manager(); }
DeviceManager* PhysicalDevChunk::device_manager_mutable() { return physical_dev_mutable()->device_manager_mutable(); }

std::string PhysicalDevChunk::to_string() const {
    return fmt::format("chunk_id={} pdev_id={} vdev_id={} start_offset={} size={} prev_chunk_id={} next_chunk_id={} "
                       "busy?={} slot_allocated?={}",
                       chunk_id(), m_chunk_info->pdev_id, m_chunk_info->vdev_id, m_chunk_info->chunk_start_offset,
                       m_chunk_info->chunk_size, m_chunk_info->prev_chunk_id, m_chunk_info->next_chunk_id, is_busy(),
                       m_chunk_info->is_slot_allocated());
}

nlohmann::json PhysicalDevChunk::get_status([[maybe_unused]] int log_level) const {
    nlohmann::json j;
    j["chunk_id"] = chunk_id();
    j["prev_chunk_id"] = m_chunk_info->prev_chunk_id;
    j["next_chunk_id"] = m_chunk_info->next_chunk_id;
    j["pdev_id"] = m_chunk_info->pdev_id;
    j["vdev_id"] = m_chunk_info->vdev_id;
    j["start_offset"] = m_chunk_info->chunk_start_offset;
    j["size"] = m_chunk_info->chunk_size;
    j["busy?"] = is_busy();
    j["slot_alloced?"] = m_chunk_info->is_slot_allocated();
    return j;
}

//////////////////////////// PhysicalDevChunk section ///////////////////////////////
void PhysicalDevChunk::recover(std::unique_ptr< sisl::Bitset > recovered_bm, meta_blk* mblk) {
    m_meta_blk_cookie = mblk;
    if (m_allocator) {
        m_allocator->set_disk_bm(std::move(recovered_bm));
    } else {
        m_recovered_bm = std::move(recovered_bm);
    }
}

void PhysicalDevChunk::recover() {
    if (m_allocator && m_recovered_bm) { m_allocator->set_disk_bm(std::move(m_recovered_bm)); }
}

void PhysicalDevChunk::cp_flush() {
    auto allocator = blk_allocator_mutable();

    // only do write when bitmap is dirty
    if (allocator->need_flush_dirty_bm()) {
        auto bitmap_mem = allocator->acquire_underlying_buffer();
        if (m_meta_blk_cookie) {
            meta_service().update_sub_sb(bitmap_mem->bytes, bitmap_mem->size, m_meta_blk_cookie);
        } else {
            meta_service().add_sub_sb("BLK_ALLOC", bitmap_mem->bytes, bitmap_mem->size, m_meta_blk_cookie);
        }
        allocator->reset_disk_bm_dirty();
        allocator->release_underlying_buffer();
    } else {
        COUNTER_INCREMENT(m_pdev->metrics(), drive_skipped_chunk_bm_writes, 1);
    }
}
} // namespace homestore
