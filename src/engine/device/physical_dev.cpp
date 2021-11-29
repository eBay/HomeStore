/*
 * PhysicalDev.cpp
 *
 *  Created on: 05-Aug-2016
 *      Author: hkadayam
 */

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

#include <boost/utility.hpp>
#include <folly/Exception.h>
#include <iomgr/iomgr.hpp>
#include <sisl/utility/thread_factory.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include "device.h"
#include "engine/common/homestore_config.hpp"
#include "engine/common/homestore_assert.hpp"
#include "engine/common/homestore_flip.hpp"
#include "engine/common/homestore_header.hpp"
#include "engine/common/homestore_utils.hpp"

SDS_LOGGING_DECL(device)

namespace homestore {

static std::atomic< uint64_t > glob_phys_dev_offset{0};
static std::atomic< uint32_t > glob_phys_dev_ids{0};

PhysicalDev::~PhysicalDev() {
    LOGINFO("device name {} superblock magic {} product name {} version {}", m_devname, m_super_blk->get_magic(),
            m_super_blk->get_product_name(), m_super_blk->get_version());
    hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(m_super_blk), sisl::buftag::superblk);
}

void PhysicalDev::update(const uint32_t dev_num, const uint64_t dev_offset, const uint32_t first_chunk_id) {
    HS_DEBUG_ASSERT_EQ(m_info_blk.get_dev_num(), INVALID_DEV_ID);
    HS_DEBUG_ASSERT_EQ(m_info_blk.get_first_chunk_id(), INVALID_CHUNK_ID);

    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = first_chunk_id;
}

void PhysicalDev::attach_superblock_chunk(PhysicalDevChunk* const chunk) {
    if (!m_superblock_valid) {
        HS_ASSERT_NULL(DEBUG, m_dm_chunk[m_cur_indx]);
        HS_DEBUG_ASSERT_LT(m_cur_indx, 2);
        m_dm_chunk[m_cur_indx++] = chunk;
        return;
    }
    if (chunk->get_chunk_id() == m_super_blk->dm_chunk[0].chunk_id) {
        HS_ASSERT_NULL(DEBUG, m_dm_chunk[0]);
        m_dm_chunk[0] = chunk;
    } else {
        HS_DEBUG_ASSERT_EQ(chunk->get_chunk_id(), m_super_blk->dm_chunk[1].get_chunk_id());
        HS_ASSERT_NULL(DEBUG, m_dm_chunk[1]);
        m_dm_chunk[1] = chunk;
    }
}

PhysicalDev::PhysicalDev(DeviceManager* const mgr, const std::string& devname, const int oflags,
                         const iomgr::io_interface_comp_cb_t& io_comp_cb) :
        m_mgr{mgr}, m_devname{devname}, m_metrics{devname} {

    HS_RELEASE_ASSERT_LE(sizeof(super_block), SUPERBLOCK_SIZE(get_atomic_page_size(m_devname)),
                         "Device {} Ondisk Superblock size not enough to hold in-mem", devname);

    const auto superblock_size{SUPERBLOCK_SIZE(get_atomic_page_size(m_devname))};
    auto* const membuf{hs_utils::iobuf_alloc(SUPERBLOCK_SIZE(get_atomic_page_size(m_devname)), sisl::buftag::superblk,
                                             get_align_size(m_devname))};
    m_super_blk = new (membuf) super_block{};
    if (sizeof(super_block) < superblock_size) {
        std::memset(membuf + sizeof(super_block), 0, superblock_size - sizeof(super_block));
    }

    m_iodev = iomgr::DriveInterface::open_dev(devname, oflags);
    m_drive_iface = m_iodev->drive_interface();
    m_drive_iface->attach_completion_cb(io_comp_cb);
    read_superblock();
}

PhysicalDev::PhysicalDev(DeviceManager* const mgr, const std::string& devname, const int oflags,
                         const hs_uuid_t& system_uuid, const uint32_t dev_num, const uint64_t dev_offset,
                         const bool is_init, const uint64_t dm_info_size,
                         const iomgr::io_interface_comp_cb_t& io_comp_cb, bool* const is_inited) :
        m_mgr{mgr}, m_devname{devname}, m_metrics{devname} {

    /* super block should always be written atomically. */
    HS_RELEASE_ASSERT_LE(sizeof(super_block), SUPERBLOCK_SIZE(get_atomic_page_size(m_devname)),
                         "Device {} Ondisk Superblock size not enough to hold in-mem", devname);
    const auto superblock_size{SUPERBLOCK_SIZE(get_atomic_page_size(m_devname))};

    auto* const membuf{hs_utils::iobuf_alloc(SUPERBLOCK_SIZE(get_atomic_page_size(m_devname)), sisl::buftag::superblk,
                                             get_align_size(m_devname))};
    m_super_blk = new (membuf) super_block{};
    if (sizeof(super_block) < superblock_size) {
        std::memset(membuf + sizeof(super_block), 0, superblock_size - sizeof(super_block));
    }

    if (is_init) { m_super_blk->set_system_uuid(system_uuid); }
    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = INVALID_CHUNK_ID;

    int oflags_used{oflags};
    if (devname.find("/tmp") == 0) {
        // tmp directory in general does not allow Direct I/O
        oflags_used &= ~O_DIRECT;
    }
    m_iodev = iomgr::DriveInterface::open_dev(devname, oflags_used);
    if (m_iodev == nullptr
#ifdef _PRERELEASE
        || (homestore_flip->test_flip("device_boot_fail", devname.c_str()))
#endif
    ) {

        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(m_super_blk), sisl::buftag::superblk);

        HS_LOG(ERROR, device, "device open failed errno {} dev_name {}", errno, devname.c_str());
        throw std::system_error(errno, std::system_category(), "error while opening the device");
    }
    m_drive_iface = m_iodev->drive_interface();
    m_drive_iface->attach_completion_cb(io_comp_cb);

    // Get the device size
    try {
        m_devsize = m_drive_iface->get_size(m_iodev.get());
    } catch (std::exception& e) {
        hs_utils::iobuf_free(reinterpret_cast< uint8_t* >(m_super_blk), sisl::buftag::superblk);
        throw(e);
    }

    if (m_devsize == 0) {
        const auto s{fmt::format("Device {} size={} is too small", devname, m_devsize)};
        HS_ASSERT(LOGMSG, 0, s.c_str());
        throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
    }

    const auto current_size{m_devsize};
    m_devsize = sisl::round_down(m_devsize, get_page_size(m_devname));
    if (m_devsize != current_size) {
        LOGWARN("device size is not the multiple of physical page size old size {}", current_size);
    }
    LOGINFO("Device {} opened with dev_id={} size={}", m_devname, m_iodev->dev_id(), m_devsize);
    m_dm_chunk[0] = m_dm_chunk[1] = nullptr;
    if (is_init) {
        /* create a chunk */
        const uint64_t sb_size{SUPERBLOCK_SIZE(get_atomic_page_size(m_devname))};
        HS_LOG_ASSERT_EQ((get_size() % get_page_size(m_devname)), 0,
                         "Expected drive size to be aligned with physical page size");
        m_mgr->create_new_chunk(this, sb_size, get_size() - sb_size, nullptr);

        /* check for min size */
        const uint64_t min_size{sb_size + 2 * dm_info_size};
        if (m_devsize <= min_size) {
            const auto s{fmt::format("Device {} size={} is too small min_size={}", m_devname, m_devsize, min_size)};
            HS_ASSERT(LOGMSG, 0, s.c_str());
            throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
        }

        /* We create two chunks for super blocks. Since writing a sb chunk is not atomic operation,
         * so at any given point only one SB chunk is valid.
         */
        for (size_t i{0}; i < 2; ++i) {
            HS_LOG_ASSERT_EQ((dm_info_size % get_page_size(m_devname)), 0, "dm size is not aligned {}", dm_info_size);
            m_dm_chunk[i] = m_mgr->alloc_chunk(this, INVALID_VDEV_ID, dm_info_size, INVALID_CHUNK_ID);
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

size_t PhysicalDev::get_total_cap() {
    return (m_devsize -
            (SUPERBLOCK_SIZE(get_atomic_page_size(m_devname)) + m_dm_chunk[0]->get_size() + m_dm_chunk[1]->get_size()));
}

bool PhysicalDev::load_super_block(const hs_uuid_t& system_uuid) {
    read_superblock();

    // Validate if its homestore formatted device

    const bool is_omstore_dev{validate_device()};

    if (!is_omstore_dev) {
        LOGCRITICAL("invalid device name {} found magic {} product name {} version {}", m_devname,
                    m_super_blk->get_magic(), m_super_blk->get_product_name(), m_super_blk->get_version());
        return false;
    }

    if (m_super_blk->get_system_uuid() != system_uuid) {
        std::ostringstream ss;
        ss << "we found the homestore formatted device with a different system UUID";
        const std::string s{ss.str()};
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
    HS_DEBUG_ASSERT_EQ(m_super_blk->dm_chunk[m_cur_indx & s_dm_chunk_mask].get_chunk_size(), size);
    const auto offset{m_super_blk->dm_chunk[m_cur_indx & s_dm_chunk_mask].chunk_start_offset};
    m_drive_iface->sync_read(m_iodev.get(), mem, size, offset);
}

void PhysicalDev::write_dm_chunk(const uint64_t gen_cnt, const char* const mem, const uint64_t size) {
    const auto offset{m_dm_chunk[(++m_cur_indx) & s_dm_chunk_mask]->get_start_offset()};
    m_drive_iface->sync_write(m_iodev.get(), mem, size, offset);
    write_super_block(gen_cnt);
}

uint64_t PhysicalDev::sb_gen_cnt() { return m_super_blk->gen_cnt; }

void PhysicalDev::write_super_block(const uint64_t gen_cnt) {
    // Format the super block and this device info structure
    m_super_blk->magic = MAGIC;
    std::strncpy(m_super_blk->product_name, PRODUCT_NAME, super_block::s_product_name_size);
    m_super_blk->product_name[super_block::s_product_name_size - 1] = 0;
    m_super_blk->version = CURRENT_SUPERBLOCK_VERSION;

    HS_DEBUG_ASSERT_NE(m_info_blk.get_dev_num(), INVALID_DEV_ID);
    HS_DEBUG_ASSERT_NE(m_info_blk.get_first_chunk_id(), INVALID_CHUNK_ID);

    m_super_blk->this_dev_info.dev_num = m_info_blk.dev_num;
    m_super_blk->this_dev_info.first_chunk_id = m_info_blk.first_chunk_id;
    m_super_blk->this_dev_info.dev_offset = m_info_blk.dev_offset;
    m_super_blk->gen_cnt = gen_cnt;
    m_super_blk->cur_indx = m_cur_indx;

    for (size_t i{0}; i < super_block::s_num_dm_chunks; ++i) {
        std::memcpy(static_cast< void* >(&(m_super_blk->dm_chunk[i])),
                    static_cast< const void* >(m_dm_chunk[i]->get_chunk_info()), sizeof(chunk_info_block));
    }

    // Write the information to the offset
    write_superblock();
    m_superblock_valid = true;
}

void PhysicalDev::zero_boot_sbs(const std::vector< dev_info >& devices, const int oflags) {
    if (devices.empty()) return;

    for (const auto& dev : devices) {

        // alloc re-usable super block
        const auto dev_type{dev.dev_type};
        const std::string& dev_str{dev.dev_names};
        const auto superblock_size{SUPERBLOCK_SIZE(get_atomic_page_size(dev_str))};
        auto* const membuf{hs_utils::iobuf_alloc(superblock_size, sisl::buftag::superblk, get_align_size(dev_str))};
        super_block* const super_blk{new (membuf) super_block{}};
        if (sizeof(super_block) < superblock_size) {
            std::memset(membuf + sizeof(super_block), 0, superblock_size - sizeof(super_block));
        }

        HS_LOG_ASSERT_LE(sizeof(super_block), superblock_size,
                         "Device {} Ondisk Superblock size not enough to hold in-mem", dev_str);
        // open device
        auto iodev = iomgr::DriveInterface::open_dev(dev_str, oflags);

        // write zeroed sb to disk
        const auto bytes{iodev->drive_interface()->sync_write(iodev.get(), (const char*)super_blk, superblock_size, 0)};
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
    read_superblock();

    // Validate if its homestore formatted device
    const bool ret{(validate_device() && is_init_done())};

    if (ret) { out_uuid = m_super_blk->get_system_uuid(); }
    return ret;
}

void PhysicalDev::close_device() { m_drive_iface->close_dev(m_iodev); }

void PhysicalDev::init_done() {
    m_super_blk->set_init_done(true);
    write_superblock();
}

inline bool PhysicalDev::validate_device() {
    return ((m_super_blk->magic == MAGIC) && (std::strcmp(m_super_blk->product_name, PRODUCT_NAME) == 0) &&
            (m_super_blk->version == CURRENT_SUPERBLOCK_VERSION));
}

inline void PhysicalDev::write_superblock() {
    const auto superblock_size{SUPERBLOCK_SIZE(get_atomic_page_size(m_devname))};
    const auto bytes{m_drive_iface->sync_write(m_iodev.get(), reinterpret_cast< const char* >(m_super_blk),
                                               static_cast< uint32_t >(superblock_size), 0)};
    if (sisl_unlikely((bytes < 0) || (static_cast< size_t >(bytes) != superblock_size))) {

        throw std::system_error(errno, std::system_category(), "error while writing a superblock" + get_devname());
    }
}

inline void PhysicalDev::read_superblock() {
    const auto superblock_size{SUPERBLOCK_SIZE(get_atomic_page_size(m_devname))};
    // std::memset(static_cast< void* >(m_super_blk), 0, SUPERBLOCK_SIZE(get_atomic_page_size(m_devname)));
    const auto bytes{m_drive_iface->sync_read(m_iodev.get(), reinterpret_cast< char* >(m_super_blk),
                                              static_cast< uint32_t >(superblock_size), 0)};
    if (sisl_unlikely((bytes < 0) || (static_cast< size_t >(bytes) != superblock_size))) {
        throw std::system_error(errno, std::system_category(), "error while reading a superblock" + get_devname());
    }
}

void PhysicalDev::write(const char* const data, const uint32_t size, const uint64_t offset, uint8_t* const cookie,
                        const bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    m_drive_iface->async_write(m_iodev.get(), data, size, offset, cookie, part_of_batch);
}

void PhysicalDev::writev(const iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset,
                         uint8_t* const cookie, const bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    m_drive_iface->async_writev(m_iodev.get(), iov, iovcnt, size, offset, cookie, part_of_batch);
}

void PhysicalDev::read(char* const data, const uint32_t size, const uint64_t offset, uint8_t* const cookie,
                       const bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    m_drive_iface->async_read(m_iodev.get(), data, size, offset, cookie, part_of_batch);
}

void PhysicalDev::readv(iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset,
                        uint8_t* const cookie, const bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    m_drive_iface->async_readv(m_iodev.get(), iov, iovcnt, size, offset, cookie, part_of_batch);
}

ssize_t PhysicalDev::sync_write(const char* const data, const uint32_t size, const uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
        return m_drive_iface->sync_write(m_iodev.get(), data, size, offset);
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
    }
}

ssize_t PhysicalDev::sync_writev(const iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
        return m_drive_iface->sync_writev(m_iodev.get(), iov, iovcnt, size, offset);
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
    }
}

void PhysicalDev::write_zero(const uint64_t size, const uint64_t offset, uint8_t* const cookie) {
    m_drive_iface->write_zero(m_iodev.get(), size, offset, cookie);
}

ssize_t PhysicalDev::sync_read(char* const data, const uint32_t size, const uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
        return m_drive_iface->sync_read(m_iodev.get(), data, size, offset);
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
        return -1;
    }
}

ssize_t PhysicalDev::sync_readv(iovec* const iov, const int iovcnt, const uint32_t size, const uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
        return m_drive_iface->sync_readv(m_iodev.get(), iov, iovcnt, size, offset);
    } catch (const std::system_error& e) {
        device_manager_mutable()->handle_error(this);
        throw std::system_error(e.code(), fmt::format("dev_name: {}: {}", get_devname(), e.what()));
        return -1;
    }
}

void PhysicalDev::attach_chunk(PhysicalDevChunk* const chunk, PhysicalDevChunk* const after) {
    if (after) {
        chunk->set_next_chunk(after->get_next_chunk_mutable());
        chunk->set_prev_chunk(after);

        auto* const next{after->get_next_chunk_mutable()};
        if (next) next->set_prev_chunk(chunk);
        after->set_next_chunk(chunk);
    } else {
        HS_DEBUG_ASSERT_EQ(m_info_blk.get_first_chunk_id(), INVALID_CHUNK_ID);
        m_info_blk.first_chunk_id = chunk->get_chunk_id();
    }
}

std::array< uint32_t, 2 > PhysicalDev::merge_free_chunks(PhysicalDevChunk* chunk) {
    std::array< uint32_t, 2 > freed_ids{INVALID_CHUNK_ID, INVALID_CHUNK_ID};
    uint32_t nids{0};

    // Check if previous and next chunk are free, if so make it contiguous chunk
    PhysicalDevChunk* const prev_chunk{chunk->get_prev_chunk_mutable()};
    PhysicalDevChunk* const next_chunk{chunk->get_next_chunk_mutable()};

    if (prev_chunk && !prev_chunk->is_busy()) {
        // We can merge our space to prev_chunk and remove our current chunk.
        prev_chunk->set_size(prev_chunk->get_size() + chunk->get_size());
        prev_chunk->set_next_chunk(chunk->get_next_chunk_mutable());

        // Erase the current chunk entry
        prev_chunk->set_next_chunk(chunk->get_next_chunk_mutable());
        if (next_chunk) next_chunk->set_prev_chunk(prev_chunk);

        freed_ids[nids++] = chunk->get_chunk_id();
        chunk = prev_chunk;
    }

    if (next_chunk && !next_chunk->is_busy()) {
        next_chunk->set_size(chunk->get_size() + next_chunk->get_size());
        next_chunk->set_start_offset(chunk->get_start_offset());

        // Erase the current chunk entry
        next_chunk->set_prev_chunk(chunk->get_prev_chunk_mutable());
        auto* const p{chunk->get_prev_chunk_mutable()};
        if (p) p->set_next_chunk(next_chunk);
        freed_ids[nids++] = chunk->get_chunk_id();
    }
    return freed_ids;
}

pdev_info_block PhysicalDev::get_info_blk() { return m_info_blk; }

PhysicalDevChunk* PhysicalDev::find_free_chunk(const uint64_t req_size, const bool is_stream_aligned) {
    // Get the slot with closest size;
    PhysicalDevChunk* closest_chunk{nullptr};

    PhysicalDevChunk* chunk{device_manager_mutable()->get_chunk_mutable(m_info_blk.first_chunk_id)};
    while (chunk) {
        const auto size = is_stream_aligned
            ? chunk->get_aligned_size(get_stream_aligned_offset(), get_page_size(m_devname))
            : chunk->get_size();
        if (!chunk->is_busy() && size >= req_size) {
            if ((closest_chunk == nullptr) || (chunk->get_size() < closest_chunk->get_size())) {
                closest_chunk = chunk;
            }
        }
        chunk = device_manager_mutable()->get_chunk_mutable(chunk->get_next_chunk_id());
    }

    return closest_chunk;
}

std::string PhysicalDev::to_string() {
    std::ostringstream ss;
    ss << "Device name = " << m_devname << "\n";
    ss << "Device ID = " << m_iodev->dev_id() << "\n";
    ss << "Device size = " << m_devsize << "\n";
    ss << "Super Block :\n";
    ss << "\tMagic = " << m_super_blk->magic << "\n";
    ss << "\tProduct Name = " << m_super_blk->get_product_name() << "\n";
    ss << "\tHeader version = " << m_super_blk->version << "\n";
    ss << "\tPdev Id = " << m_info_blk.dev_num << "\n";
    ss << "\tPdev Offset = " << m_info_blk.dev_offset << "\n";
    ss << "\tFirst chunk id = " << m_info_blk.first_chunk_id << "\n";

    const PhysicalDevChunk* pchunk{device_manager()->get_chunk(m_info_blk.first_chunk_id)};
    while (pchunk) {
        ss << "\t\t" << pchunk->to_string() << "\n";
        pchunk = pchunk->get_next_chunk();
    }

    return ss.str();
}

bool PhysicalDev::is_hdd() const {
    const iomgr::drive_type dtype = iomgr::DriveInterface::get_drive_type(m_devname);
    if (dtype == iomgr::drive_type::block_hdd || dtype == iomgr::drive_type::file_on_hdd) { return true; }
    return false;
}

uint64_t PhysicalDev::get_stream_size() const {
    if (!is_hdd()) { return get_size(); }
    const auto page_size = get_page_size(m_devname);

    // TODO: replace 10 with iomgr api
    return sisl::round_down((get_size() / 10), page_size);
}

uint64_t PhysicalDev::get_stream_aligned_offset() const { return (get_size() / 10); }
uint32_t PhysicalDev::get_align_size(const std::string& devname) {
    const auto observed_attr = iomgr::DriveInterface::get_attributes(devname);
    return observed_attr.align_size;
}

uint32_t PhysicalDev::get_page_size(const std::string& devname) {
    const auto observed_attr = iomgr::DriveInterface::get_attributes(devname);
    return observed_attr.phys_page_size;
}

uint32_t PhysicalDev::get_atomic_page_size(const std::string& devname) {
    const auto observed_attr = iomgr::DriveInterface::get_attributes(devname);
    return observed_attr.atomic_phys_page_size;
}

#if 0
uint64_t PhysicalDev::get_stream_offset_multiple() {
    if (!is_hdd()) { return 0; }
    const auto page_size = (m_pdev_group == PhysicalDevGroup::DATA ? HS_STATIC_CONFIG(data_drive_attr.phys_page_size)
                                                             : HS_STATIC_CONFIG(fast_drive_attr.phys_page_size));
    return sisl::round_up((get_size() / 10), page_size);
}
#endif

/********************* PhysicalDevChunk Section ************************/
PhysicalDevChunk::PhysicalDevChunk(PhysicalDev* const pdev, chunk_info_block* const cinfo) {
    m_chunk_info = cinfo;
    m_pdev = pdev;
#if 0
    const std::unique_ptr< PhysicalDev > &p =
            (static_cast<const homeds::sparse_vector< std::unique_ptr< PhysicalDev > > &>(device_manager()->m_pdevs))[cinfo->pdev_id];
    m_pdev = p.get();
#endif
}

PhysicalDevChunk::PhysicalDevChunk(PhysicalDev* const pdev, const uint32_t chunk_id, const uint64_t start_offset,
                                   const uint64_t size, chunk_info_block* const cinfo) {
    m_chunk_info = cinfo;
    // Fill in with new chunk info
    m_chunk_info->chunk_id = chunk_id;
    m_chunk_info->set_slot_allocated(true);
    m_chunk_info->pdev_id = pdev->get_dev_id();
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

const PhysicalDevChunk* PhysicalDevChunk::get_next_chunk() const {
    return device_manager()->get_chunk(get_next_chunk_id());
}

PhysicalDevChunk* PhysicalDevChunk::get_next_chunk_mutable() {
    return device_manager_mutable()->get_chunk_mutable(get_next_chunk_id());
}

const PhysicalDevChunk* PhysicalDevChunk::get_prev_chunk() const {
    return device_manager()->get_chunk(get_prev_chunk_id());
}

PhysicalDevChunk* PhysicalDevChunk::get_prev_chunk_mutable() {
    return device_manager_mutable()->get_chunk_mutable(get_prev_chunk_id());
}

const PhysicalDevChunk* PhysicalDevChunk::get_primary_chunk() const {
    return device_manager()->get_chunk(m_chunk_info->primary_chunk_id);
}

PhysicalDevChunk* PhysicalDevChunk::get_primary_chunk_mutable() {
    return device_manager_mutable()->get_chunk_mutable(m_chunk_info->primary_chunk_id);
}

const DeviceManager* PhysicalDevChunk::device_manager() const { return get_physical_dev()->device_manager(); }

DeviceManager* PhysicalDevChunk::device_manager_mutable() {
    return get_physical_dev_mutable()->device_manager_mutable();
}

std::string PhysicalDevChunk::to_string() const {
    return fmt::format("chunk_id={} pdev_id={} vdev_id={} start_offset={} size={} prev_chunk_id={} next_chunk_id={} "
                       "busy?={} slot_allocated?={}",
                       get_chunk_id(), m_chunk_info->pdev_id, m_chunk_info->vdev_id, m_chunk_info->chunk_start_offset,
                       m_chunk_info->chunk_size, m_chunk_info->prev_chunk_id, m_chunk_info->next_chunk_id, is_busy(),
                       m_chunk_info->is_slot_allocated());
}

nlohmann::json PhysicalDevChunk::get_status([[maybe_unused]] const int log_level) const {
    nlohmann::json j;
    j["chunk_id"] = get_chunk_id();
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
} // namespace homestore
