/*
 * PhysicalDev.cpp
 *
 *  Created on: 05-Aug-2016
 *      Author: hkadayam
 */

#include "device.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <iostream>
#include <folly/Exception.h>
#include <boost/utility.hpp>
#ifdef __linux__
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif
#include "engine/common/homestore_assert.hpp"
#include <iomgr/iomgr.hpp>
#include <utility/thread_factory.hpp>
#include "engine/common/homestore_flip.hpp"

SDS_LOGGING_DECL(device)

#define drive_iface iomgr::IOManager::instance().default_drive_interface()

namespace homestore {

static std::atomic< uint64_t > glob_phys_dev_offset(0);
static std::atomic< uint32_t > glob_phys_dev_ids(0);

PhysicalDev::~PhysicalDev() {
    LOGINFO("device name {} superblock magic {} product name {} version {}", m_devname, m_super_blk->get_magic(),
            m_super_blk->get_product_name(), m_super_blk->get_version());
    hs_iobuf_free((uint8_t*)m_super_blk);
}

void PhysicalDev::update(uint32_t dev_num, uint64_t dev_offset, uint32_t first_chunk_id) {
    HS_DEBUG_ASSERT_EQ(m_info_blk.get_dev_num(), INVALID_DEV_ID);
    HS_DEBUG_ASSERT_EQ(m_info_blk.get_first_chunk_id(), INVALID_CHUNK_ID);

    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = first_chunk_id;
}

void PhysicalDev::attach_superblock_chunk(PhysicalDevChunk* chunk) {
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

PhysicalDev::PhysicalDev(DeviceManager* mgr, const std::string& devname, int const oflags,
                         iomgr::iomgr_drive_type drive_type) :
        m_mgr{mgr}, m_devname{devname}, m_metrics{devname} {

    HS_LOG_ASSERT_LE(sizeof(super_block), SUPERBLOCK_SIZE, "Device {} Ondisk Superblock size not enough to hold in-mem",
                     devname);
    m_super_blk = (super_block*)hs_iobuf_alloc(SUPERBLOCK_SIZE);
    memset(m_super_blk, 0, SUPERBLOCK_SIZE);

    m_iodev = drive_iface->open_dev(devname.c_str(), drive_type, oflags);
    read_superblock();
}

PhysicalDev::PhysicalDev(DeviceManager* mgr, const std::string& devname, int const oflags, hs_uuid_t& system_uuid,
                         uint32_t dev_num, uint64_t dev_offset, iomgr::iomgr_drive_type drive_type, bool is_init,
                         uint64_t dm_info_size, bool* is_inited, bool is_restricted_mode) :
        m_mgr{mgr}, m_devname{devname}, m_metrics{devname}, m_restricted_mode{is_restricted_mode} {
    /* super block should always be written atomically. */
    HS_LOG_ASSERT_LE(sizeof(super_block), SUPERBLOCK_SIZE, "Device {} Ondisk Superblock size not enough to hold in-mem",
                     devname);
    m_super_blk = (super_block*)hs_iobuf_alloc(SUPERBLOCK_SIZE);
    memset(m_super_blk, 0, SUPERBLOCK_SIZE);

    if (is_init) { m_super_blk->system_uuid = system_uuid; }
    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = INVALID_CHUNK_ID;

    int oflags_used{oflags};
    if (devname.find("/tmp") == 0) {
        // tmp directory in general does not allow Direct I/O
        oflags_used &= ~O_DIRECT;
    }
    m_iodev = drive_iface->open_dev(devname.c_str(), drive_type, oflags_used);
    if (m_iodev == nullptr
#ifdef _PRERELEASE
        || (homestore_flip->test_flip("device_boot_fail", devname.c_str()))
#endif
    ) {

        hs_iobuf_free((uint8_t*)m_super_blk);

        HS_LOG(ERROR, device, "device open failed errno {} dev_name {}", errno, devname.c_str());
        throw std::system_error(errno, std::system_category(), "error while opening the device");
    }

    // Get the device size
    try {
        m_devsize = drive_iface->get_size(m_iodev.get());
    } catch (std::exception& e) {
        hs_iobuf_free((uint8_t*)m_super_blk);
        throw(e);
    }

    if (m_devsize == 0) {
        auto s = fmt::format("Device {} drive_type={} size={} is too small", devname, enum_name(drive_type), m_devsize);
        HS_ASSERT(LOGMSG, 0, s.c_str());
        throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
    }

    auto temp = m_devsize;
    m_devsize = sisl::round_down(m_devsize, HS_STATIC_CONFIG(drive_attr.phys_page_size));
    if (m_devsize != temp) { LOGWARN("device size is not the multiple of physical page size old size {}", temp); }
    LOGINFO("Device {} opened with dev_id={} size={}", m_devname, m_iodev->dev_id(), m_devsize);
    m_dm_chunk[0] = m_dm_chunk[1] = nullptr;
    if (is_init) {
        /* create a chunk */
        uint64_t sb_size = sisl::round_up(SUPERBLOCK_SIZE, HS_STATIC_CONFIG(drive_attr.phys_page_size));
        HS_LOG_ASSERT_EQ(get_size() % HS_STATIC_CONFIG(drive_attr.phys_page_size), 0,
                         "Expected drive size to be aligned with physical page size");
        m_mgr->create_new_chunk(this, sb_size, get_size() - sb_size, nullptr);

        /* check for min size */
        uint64_t min_size = SUPERBLOCK_SIZE + 2 * dm_info_size;
        if (m_devsize <= min_size) {
            auto s = fmt::format("Device {} size={} is too small min_size={}", m_devname, m_devsize, min_size);
            HS_ASSERT(LOGMSG, 0, s.c_str());
            throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
        }

        /* We create two chunks for super blocks. Since writing a sb chunk is not atomic operation,
         * so at any given point only one SB chunk is valid.
         */
        for (int i = 0; i < 2; ++i) {
            uint64_t align_size = sisl::round_up(dm_info_size, HS_STATIC_CONFIG(drive_attr.phys_page_size));
            HS_LOG_ASSERT_EQ(align_size, dm_info_size);
            m_dm_chunk[i] = m_mgr->alloc_chunk(this, INVALID_VDEV_ID, align_size, INVALID_CHUNK_ID);
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
    return (m_devsize - (SUPERBLOCK_SIZE + m_dm_chunk[0]->get_size() + m_dm_chunk[1]->get_size()));
}

bool PhysicalDev::load_super_block(hs_uuid_t& system_uuid) {
    read_superblock();

    // Validate if its homestore formatted device

    bool is_omstore_dev = validate_device();

    if (!is_omstore_dev) {
        LOGCRITICAL("invalid device name {} found magic {} product name {} version {}", m_devname,
                    m_super_blk->get_magic(), m_super_blk->get_product_name(), m_super_blk->get_version());
        return false;
    }

    if (m_super_blk->system_uuid != system_uuid) {
        std::stringstream ss;
        ss << "we found the homestore formatted device with a different system UUID";
        const std::string s = ss.str();
        LOGCRITICAL("{}", ss.str());
        throw homestore::homestore_exception(s, homestore_error::formatted_disk_found);
    }

    m_info_blk.dev_num = m_super_blk->this_dev_info.dev_num;
    m_info_blk.dev_offset = m_super_blk->this_dev_info.dev_offset;
    m_info_blk.first_chunk_id = m_super_blk->this_dev_info.first_chunk_id;
    m_cur_indx = m_super_blk->cur_indx;
    m_superblock_valid = true;

    return true;
}

void PhysicalDev::read_dm_chunk(char* mem, uint64_t size) {
    HS_DEBUG_ASSERT_EQ(m_super_blk->dm_chunk[m_cur_indx % 2].get_chunk_size(), size);
    auto offset = m_super_blk->dm_chunk[m_cur_indx % 2].chunk_start_offset;
    drive_iface->sync_read(m_iodev.get(), mem, size, (off_t)offset);
}

void PhysicalDev::write_dm_chunk(uint64_t gen_cnt, char* mem, uint64_t size) {
    auto offset = m_dm_chunk[(++m_cur_indx) % 2]->get_start_offset();
    drive_iface->sync_write(m_iodev.get(), mem, size, (off_t)offset);
    write_super_block(gen_cnt);
}

uint64_t PhysicalDev::sb_gen_cnt() { return m_super_blk->gen_cnt; }

void PhysicalDev::write_super_block(uint64_t gen_cnt) {
    // Format the super block and this device info structure
    m_super_blk->magic = MAGIC;
    strcpy(m_super_blk->product_name, PRODUCT_NAME);
    m_super_blk->version = CURRENT_SUPERBLOCK_VERSION;

    HS_DEBUG_ASSERT_NE(m_info_blk.get_dev_num(), INVALID_DEV_ID);
    HS_DEBUG_ASSERT_NE(m_info_blk.get_first_chunk_id(), INVALID_CHUNK_ID);

    m_super_blk->this_dev_info.dev_num = m_info_blk.dev_num;
    m_super_blk->this_dev_info.first_chunk_id = m_info_blk.first_chunk_id;
    m_super_blk->this_dev_info.dev_offset = m_info_blk.dev_offset;
    m_super_blk->gen_cnt = gen_cnt;
    m_super_blk->cur_indx = m_cur_indx;

    for (int i = 0; i < 2; i++) {
        memcpy(&m_super_blk->dm_chunk[i], m_dm_chunk[i]->get_chunk_info(), sizeof(chunk_info_block));
    }

    // Write the information to the offset
    write_superblock();
    m_superblock_valid = true;
}

void PhysicalDev::zero_boot_sbs(const std::vector< dev_info >& devices, iomgr_drive_type drive_type, const int oflags) {
    // alloc re-usable super block
    auto super_blk = (super_block*)hs_iobuf_alloc(SUPERBLOCK_SIZE);

    // zero in-memory super block
    memset(super_blk, 0, SUPERBLOCK_SIZE);

    for (const auto dev : devices) {
        HS_LOG_ASSERT_LE(sizeof(super_block), SUPERBLOCK_SIZE,
                         "Device {} Ondisk Superblock size not enough to hold in-mem", dev.dev_names);
        // open device
        auto iodev = drive_iface->open_dev(dev.dev_names.c_str(), drive_type, oflags);

        // write zeroed sb to disk
        auto bytes = drive_iface->sync_write(iodev.get(), (const char*)super_blk, SUPERBLOCK_SIZE, 0);
        if (sisl_unlikely((bytes < 0) || (size_t)bytes != SUPERBLOCK_SIZE)) {
            LOGINFO("Failed to zeroed superblock of device: {}, errno: {}", dev.dev_names, errno);
            throw std::system_error(errno, std::system_category(), "error while writing a superblock" + dev.dev_names);
        }

        LOGINFO("Successfully zeroed superblock of device: {}", dev.dev_names);

        // close device;
        drive_iface->close_dev(iodev);
    }

    // free super_blk
    hs_iobuf_free((uint8_t*)super_blk);
}

void PhysicalDev::zero_superblock() {
    if (m_restricted_mode) {
        memset(m_super_blk, 0, SUPERBLOCK_SIZE);
        write_superblock();
    } else {
        LOGINFO("zero operation is not allowed in non-restricted mode.");
    }
}

bool PhysicalDev::has_valid_superblock(hs_uuid_t& out_uuid) {
    read_superblock();

    // Validate if its homestore formatted device
    bool ret = (validate_device() && is_init_done());

    if (ret) { out_uuid = m_super_blk->system_uuid; }
    return ret;
}

void PhysicalDev::close_device() { drive_iface->close_dev(m_iodev); }

void PhysicalDev::init_done() {
    m_super_blk->init_done = true;
    write_superblock();
}

inline bool PhysicalDev::validate_device() {
    return ((m_super_blk->magic == MAGIC) && (strcmp(m_super_blk->product_name, "OmStore") == 0) &&
            (m_super_blk->version == CURRENT_SUPERBLOCK_VERSION));
}

inline void PhysicalDev::write_superblock() {
    auto bytes = drive_iface->sync_write(m_iodev.get(), (const char*)m_super_blk, SUPERBLOCK_SIZE, 0);
    if (sisl_unlikely((bytes < 0) || (size_t)bytes != SUPERBLOCK_SIZE)) {
        throw std::system_error(errno, std::system_category(), "error while writing a superblock" + get_devname());
    }
}

inline void PhysicalDev::read_superblock() {
    memset(m_super_blk, 0, SUPERBLOCK_SIZE);
    auto bytes = drive_iface->sync_read(m_iodev.get(), (char*)m_super_blk, SUPERBLOCK_SIZE, 0);
    if (sisl_unlikely((bytes < 0) || ((size_t)bytes != SUPERBLOCK_SIZE))) {
        throw std::system_error(errno, std::system_category(), "error while reading a superblock" + get_devname());
    }
}

void PhysicalDev::write(const char* data, uint32_t size, uint64_t offset, uint8_t* cookie, bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    drive_iface->async_write(m_iodev.get(), data, size, (off_t)offset, cookie, part_of_batch);
}

void PhysicalDev::writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset, uint8_t* cookie,
                         bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
    drive_iface->async_writev(m_iodev.get(), iov, iovcnt, size, offset, cookie, part_of_batch);
}

void PhysicalDev::read(char* data, uint32_t size, uint64_t offset, uint8_t* cookie, bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    drive_iface->async_read(m_iodev.get(), data, size, (off_t)offset, cookie, part_of_batch);
}

void PhysicalDev::readv(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset, uint8_t* cookie,
                        bool part_of_batch) {
    HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
    drive_iface->async_readv(m_iodev.get(), iov, iovcnt, size, (off_t)offset, cookie, part_of_batch);
}

ssize_t PhysicalDev::sync_write(const char* data, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
        return drive_iface->sync_write(m_iodev.get(), data, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << ":" << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
    }
}

ssize_t PhysicalDev::sync_writev(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, write_io_sizes, (((size - 1) / 1024) + 1));
        return drive_iface->sync_writev(m_iodev.get(), iov, iovcnt, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
    }
}

void PhysicalDev::write_zero(uint32_t size, uint64_t offset, uint8_t* cookie) {
    drive_iface->write_zero(m_iodev.get(), size, offset, cookie);
}

ssize_t PhysicalDev::sync_read(char* data, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
        return drive_iface->sync_read(m_iodev.get(), data, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
        return -1;
    }
}

ssize_t PhysicalDev::sync_readv(const iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    try {
        HISTOGRAM_OBSERVE(m_metrics, read_io_sizes, (((size - 1) / 1024) + 1));
        return drive_iface->sync_readv(m_iodev.get(), iov, iovcnt, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
        return -1;
    }
}

void PhysicalDev::attach_chunk(PhysicalDevChunk* chunk, PhysicalDevChunk* after) {
    if (after) {
        chunk->set_next_chunk(after->get_next_chunk());
        chunk->set_prev_chunk(after);

        auto next = after->get_next_chunk();
        if (next) next->set_prev_chunk(chunk);
        after->set_next_chunk(chunk);
    } else {
        HS_DEBUG_ASSERT_EQ(m_info_blk.get_first_chunk_id(), INVALID_CHUNK_ID);
        m_info_blk.first_chunk_id = chunk->get_chunk_id();
    }
}

std::array< uint32_t, 2 > PhysicalDev::merge_free_chunks(PhysicalDevChunk* chunk) {
    std::array< uint32_t, 2 > freed_ids = {INVALID_CHUNK_ID, INVALID_CHUNK_ID};
    uint32_t nids = 0;

    // Check if previous and next chunk are free, if so make it contiguous chunk
    PhysicalDevChunk* prev_chunk = chunk->get_prev_chunk();
    PhysicalDevChunk* next_chunk = chunk->get_next_chunk();

    if (prev_chunk && !prev_chunk->is_busy()) {
        // We can merge our space to prev_chunk and remove our current chunk.
        prev_chunk->set_size(prev_chunk->get_size() + chunk->get_size());
        prev_chunk->set_next_chunk(chunk->get_next_chunk());

        // Erase the current chunk entry
        prev_chunk->set_next_chunk(chunk->get_next_chunk());
        if (next_chunk) next_chunk->set_prev_chunk(prev_chunk);

        freed_ids[nids++] = chunk->get_chunk_id();
        chunk = prev_chunk;
    }

    if (next_chunk && !next_chunk->is_busy()) {
        next_chunk->set_size(chunk->get_size() + next_chunk->get_size());
        next_chunk->set_start_offset(chunk->get_start_offset());

        // Erase the current chunk entry
        next_chunk->set_prev_chunk(chunk->get_prev_chunk());
        auto p = chunk->get_prev_chunk();
        if (p) p->set_next_chunk(next_chunk);
        freed_ids[nids++] = chunk->get_chunk_id();
    }
    return freed_ids;
}

pdev_info_block PhysicalDev::get_info_blk() { return m_info_blk; }

PhysicalDevChunk* PhysicalDev::find_free_chunk(uint64_t req_size) {
    // Get the slot with closest size;
    PhysicalDevChunk* closest_chunk = nullptr;

    PhysicalDevChunk* chunk = device_manager()->get_chunk(m_info_blk.first_chunk_id);
    while (chunk) {
        if (!chunk->is_busy() && (chunk->get_size() >= req_size)) {
            if ((closest_chunk == nullptr) || (chunk->get_size() < closest_chunk->get_size())) {
                closest_chunk = chunk;
            }
        }
        chunk = device_manager()->get_chunk(chunk->get_next_chunk_id());
    }

    return closest_chunk;
}

std::string PhysicalDev::to_string() {
    std::stringstream ss;
    ss << "Device name = " << m_devname << "\n";
    ss << "Device ID = " << m_iodev->dev_id() << "\n";
    ss << "Device size = " << m_devsize << "\n";
    ss << "Super Block :\n";
    ss << "\tMagic = " << m_super_blk->magic << "\n";
    ss << "\tProduct Name = " << m_super_blk->product_name << "\n";
    ss << "\tHeader version = " << m_super_blk->version << "\n";
    ss << "\tPdev Id = " << m_info_blk.dev_num << "\n";
    ss << "\tPdev Offset = " << m_info_blk.dev_offset << "\n";
    ss << "\tFirst chunk id = " << m_info_blk.first_chunk_id << "\n";

    PhysicalDevChunk* pchunk = device_manager()->get_chunk(m_info_blk.first_chunk_id);
    while (pchunk) {
        ss << "\t\t" << pchunk->to_string() << "\n";
        pchunk = pchunk->get_next_chunk();
    }

    return ss.str();
}

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
    m_chunk_info->slot_allocated = true;
    m_chunk_info->pdev_id = pdev->get_dev_id();
    m_chunk_info->chunk_start_offset = start_offset;
    m_chunk_info->chunk_size = size;
    m_chunk_info->prev_chunk_id = INVALID_CHUNK_ID;
    m_chunk_info->next_chunk_id = INVALID_CHUNK_ID;
    m_chunk_info->primary_chunk_id = INVALID_CHUNK_ID;
    m_chunk_info->vdev_id = INVALID_VDEV_ID;
    m_chunk_info->is_sb_chunk = false;
    m_chunk_info->end_of_chunk_size = size;
    m_pdev = pdev;
}

PhysicalDevChunk* PhysicalDevChunk::get_next_chunk() const { return device_manager()->get_chunk(get_next_chunk_id()); }

PhysicalDevChunk* PhysicalDevChunk::get_prev_chunk() const { return device_manager()->get_chunk(get_prev_chunk_id()); }

PhysicalDevChunk* PhysicalDevChunk::get_primary_chunk() const {
    return device_manager()->get_chunk(m_chunk_info->primary_chunk_id);
}

DeviceManager* PhysicalDevChunk::device_manager() const { return get_physical_dev()->device_manager(); }
} // namespace homestore
