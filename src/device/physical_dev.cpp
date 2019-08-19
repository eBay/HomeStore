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
#include <endpoint/drive_endpoint.hpp>
#endif
#include "main/homestore_assert.hpp"

SDS_LOGGING_DECL(device)

namespace homestore {
using namespace homeio;

DriveEndPoint* PhysicalDev::m_ep = NULL;

static std::atomic< uint64_t > glob_phys_dev_offset(0);
static std::atomic< uint32_t > glob_phys_dev_ids(0);

PhysicalDev::~PhysicalDev() {
    free(m_super_blk);
    // m_ep will be deleted in iomgr::stop
}

void PhysicalDev::update(uint32_t dev_num, uint64_t dev_offset, uint32_t first_chunk_id) {

    HS_ASSERT_CMP(DEBUG, m_info_blk.get_dev_num(), ==, INVALID_DEV_ID);
    HS_ASSERT_CMP(DEBUG, m_info_blk.get_first_chunk_id(), ==, INVALID_CHUNK_ID);

    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = first_chunk_id;
}

void PhysicalDev::attach_superblock_chunk(PhysicalDevChunk* chunk) {
    if (!m_superblock_valid) {
        HS_ASSERT_NULL(DEBUG, m_dm_chunk[m_cur_indx]);
        HS_ASSERT_CMP(DEBUG, m_cur_indx, <, 2);
        m_dm_chunk[m_cur_indx++] = chunk;
        return;
    }
    if (chunk->get_chunk_id() == m_super_blk->dm_chunk[0].chunk_id) {
        HS_ASSERT_NULL(DEBUG, m_dm_chunk[0]);
        m_dm_chunk[0] = chunk;
    } else {
        HS_ASSERT_CMP(DEBUG, chunk->get_chunk_id(), ==, m_super_blk->dm_chunk[1].get_chunk_id());
        HS_ASSERT_NULL(DEBUG, m_dm_chunk[1]);
        m_dm_chunk[1] = chunk;
    }
}

PhysicalDev::PhysicalDev(DeviceManager* mgr, const std::string& devname, int const oflags,
                         std::shared_ptr< iomgr::ioMgr > iomgr, homeio::comp_callback& cb,
                         boost::uuids::uuid& system_uuid, uint32_t dev_num, uint64_t dev_offset, uint32_t is_file,
                         bool is_init, uint64_t dm_info_size, bool* is_inited) :
        m_mgr(mgr),
        m_devname(devname),
        m_comp_cb(cb),
        m_iomgr(iomgr),
        m_metrics(devname) {

    struct stat stat_buf;
    stat(devname.c_str(), &stat_buf);
    m_devsize = (uint64_t)stat_buf.st_size;

    HS_ASSERT_CMP(LOGMSG, sizeof(super_block), <=, SUPERBLOCK_SIZE, "opening device {} device size {} inited {}",
                  devname, m_devsize, is_init);

    auto ret = posix_memalign((void**)&m_super_blk, HomeStoreConfig::align_size, SUPERBLOCK_SIZE);
    /* super block should always be written atomically. */
    HS_ASSERT_NOTNULL(LOGMSG, m_super_blk);
    HS_ASSERT_CMP(LOGMSG, sizeof(super_block), <=, HomeStoreConfig::atomic_phys_page_size);

    if (!m_ep) {
        m_ep = new DriveEndPoint(iomgr, cb);
    }

    m_info_blk.dev_num = dev_num;
    m_info_blk.dev_offset = dev_offset;
    m_info_blk.first_chunk_id = INVALID_CHUNK_ID;
    m_cur_indx = 0;
    m_superblock_valid = false;

    m_devfd = m_ep->open_dev(devname.c_str(), oflags);

    if (m_devfd == -1
#ifdef _PRERELEASE
      || (homestore_flip->test_flip("device_boot_fail", devname.c_str()))
#endif
    ) {
        
        free(m_super_blk);

   
        HS_LOG(ERROR, device, "device open failed errno {} dev_name {}", errno, devname.c_str());

        throw std::system_error(errno, std::system_category(), "error while opening the device");
    }

    LOGINFO("FD of {} device name {}", m_devfd, m_devname);

    if (is_file) {
        struct stat buf;
        if (fstat(m_devfd, &buf) < 0) {
            free(m_super_blk);
            HS_ASSERT(LOGMSG, 0, "device stat failed errno {} dev_name {}", errno, devname.c_str());
            throw std::system_error(errno, std::system_category(), "error while getting size of the device");
        }
        m_devsize = buf.st_size;
    } else {
        if (ioctl(m_devfd, BLKGETSIZE64, &m_devsize) < 0) {
            free(m_super_blk);
            HS_ASSERT(LOGMSG, 0, "device stat failed errno {} dev_name {}", errno, devname.c_str());
            throw std::system_error(errno, std::system_category(), "error while getting size of the device");
        }
    }
    m_system_uuid = system_uuid;

    HS_ASSERT_CMP(LOGMSG, m_devsize, >, 0);
    m_dm_chunk[0] = m_dm_chunk[1] = nullptr;
    if (is_init) {
        /* create a chunk */
        uint64_t align_size = ALIGN_SIZE(SUPERBLOCK_SIZE, HomeStoreConfig::phys_page_size);
        HS_ASSERT_CMP(LOGMSG, get_size() % HomeStoreConfig::phys_page_size, ==, 0);
        m_mgr->create_new_chunk(this, SUPERBLOCK_SIZE, get_size() - align_size, nullptr);

        /* check for min size */
        uint64_t min_size = SUPERBLOCK_SIZE + 2 * dm_info_size;
        if (m_devsize <= min_size) {
            std::stringstream ss;
            ss << "Min size requiired is " << min_size << " and disk size is " << m_devsize;
            const std::string s = ss.str();
            HS_LOG(ERROR, device, "{}", ss.str());
            throw homestore::homestore_exception(s, homestore_error::min_size_not_avail);
        }

        /* We create two chunks for super blocks. Since writing a sb chunk is not atomic operation,
         * so at any given point only one SB chunk is valid.
         */
        for (int i = 0; i < 2; ++i) {
            uint64_t align_size = ALIGN_SIZE(dm_info_size, HomeStoreConfig::phys_page_size);
            HS_ASSERT_CMP(LOGMSG, align_size, ==, dm_info_size);
            m_dm_chunk[i] = m_mgr->alloc_chunk(this, INVALID_VDEV_ID, align_size, INVALID_CHUNK_ID);
            m_dm_chunk[i]->set_sb_chunk();
        }
        /* super block is written when first DM info block is written. Writing a superblock and making
         * a disk valid before that doesn't make sense as that disk is of no use until DM info is not
         * written.
         */
    } else {
        *is_inited = load_super_block();
        if (*is_inited) {
            /* If it is different then it mean it require upgrade/revert handling */
           HS_ASSERT_CMP(LOGMSG, m_super_blk->dm_chunk[0].get_chunk_size(), ==, dm_info_size);
           HS_ASSERT_CMP(LOGMSG, m_super_blk->dm_chunk[1].get_chunk_size(), ==, dm_info_size);
        }
    }
}

size_t PhysicalDev::get_total_cap() {
    return (m_devsize - (SUPERBLOCK_SIZE + m_dm_chunk[0]->get_size() + m_dm_chunk[1]->get_size()));
}

bool PhysicalDev::load_super_block() {
    memset(m_super_blk, 0, SUPERBLOCK_SIZE);

    read_superblock();

    // Validate if its homestore formatted device

    bool is_omstore_dev = validate_device();
    if (!is_omstore_dev) {
        return false;
    }

    if (m_super_blk->system_uuid != m_system_uuid) {
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
    HS_ASSERT_CMP(DEBUG, m_super_blk->dm_chunk[m_cur_indx % 2].get_chunk_size(), ==, size);
    auto offset = m_super_blk->dm_chunk[m_cur_indx % 2].chunk_start_offset;
    m_ep->sync_read(get_devfd(), mem, size, (off_t)offset);
}

void PhysicalDev::write_dm_chunk(uint64_t gen_cnt, char* mem, uint64_t size) {
    auto offset = m_dm_chunk[(++m_cur_indx) % 2]->get_start_offset();
    m_ep->sync_write(get_devfd(), mem, size, (off_t)offset);
    write_super_block(gen_cnt);
}

uint64_t PhysicalDev::sb_gen_cnt() { return m_super_blk->gen_cnt; }

void PhysicalDev::write_super_block(uint64_t gen_cnt) {

    // Format the super block and this device info structure
    m_super_blk->magic = MAGIC;
    strcpy(m_super_blk->product_name, PRODUCT_NAME);
    m_super_blk->version = CURRENT_SUPERBLOCK_VERSION;

    HS_ASSERT_CMP(DEBUG, m_info_blk.get_dev_num(), !=, INVALID_DEV_ID);
    HS_ASSERT_CMP(DEBUG, m_info_blk.get_first_chunk_id(), !=, INVALID_CHUNK_ID);

    m_super_blk->system_uuid = m_system_uuid;
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

inline bool PhysicalDev::validate_device() {
    return ((m_super_blk->magic == MAGIC) && (strcmp(m_super_blk->product_name, "OmStore") == 0) &&
            (m_super_blk->version == CURRENT_SUPERBLOCK_VERSION));
}

inline void PhysicalDev::write_superblock() {
    ssize_t bytes = pwrite(m_devfd, m_super_blk, SUPERBLOCK_SIZE, 0);
    if (hs_unlikely((bytes < 0) || (size_t)bytes != SUPERBLOCK_SIZE)) {
        throw std::system_error(errno, std::system_category(), "error while writing a superblock" + get_devname());
    }
}

inline void PhysicalDev::read_superblock() {
    memset(m_super_blk, 0, SUPERBLOCK_SIZE);
    ssize_t bytes = pread(m_devfd, m_super_blk, SUPERBLOCK_SIZE, 0);
    if (hs_unlikely((bytes < 0) || ((size_t)bytes != SUPERBLOCK_SIZE))) {
        throw std::system_error(errno, std::system_category(), "error while reading a superblock" + get_devname());
    }
}

void PhysicalDev::write(const char* data, uint32_t size, uint64_t offset, uint8_t* cookie) {
    m_ep->async_write(get_devfd(), data, size, (off_t)offset, cookie);
}

void PhysicalDev::writev(const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset, uint8_t* cookie) {
    m_ep->async_writev(get_devfd(), iov, iovcnt, size, offset, cookie);
}

void PhysicalDev::read(char* data, uint32_t size, uint64_t offset, uint8_t* cookie) {
    m_ep->async_read(get_devfd(), data, size, (off_t)offset, cookie);
}

void PhysicalDev::readv(const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset, uint8_t* cookie) {
    m_ep->async_readv(get_devfd(), iov, iovcnt, size, (off_t)offset, cookie);
}

void PhysicalDev::sync_write(const char* data, uint32_t size, uint64_t offset) {
    try {
        m_ep->sync_write(get_devfd(), data, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << ":" << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
    }
}

void PhysicalDev::sync_writev(const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    try {
        m_ep->sync_writev(get_devfd(), iov, iovcnt, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
    }
}

void PhysicalDev::sync_read(char* data, uint32_t size, uint64_t offset) {
    try {
        m_ep->sync_read(get_devfd(), data, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
    }
}

void PhysicalDev::sync_readv(const struct iovec* iov, int iovcnt, uint32_t size, uint64_t offset) {
    try {
        m_ep->sync_readv(get_devfd(), iov, iovcnt, size, (off_t)offset);
    } catch (const std::system_error& e) {
        std::stringstream ss;
        ss << "dev_name " << get_devname() << e.what() << "\n";
        const std::string s = ss.str();
        device_manager()->handle_error(this);
        throw std::system_error(e.code(), s);
    }
}

void PhysicalDev::attach_chunk(PhysicalDevChunk* chunk, PhysicalDevChunk* after) {
    if (after) {
        chunk->set_next_chunk(after->get_next_chunk());
        chunk->set_prev_chunk(after);

        auto next = after->get_next_chunk();
        if (next)
            next->set_prev_chunk(chunk);
        after->set_next_chunk(chunk);
    } else {
        HS_ASSERT_CMP(DEBUG, m_info_blk.get_first_chunk_id(), ==, INVALID_CHUNK_ID);
        m_info_blk.first_chunk_id = chunk->get_chunk_id();
    }
}

std::array< uint32_t, 2 > PhysicalDev::merge_free_chunks(PhysicalDevChunk* chunk) {
    std::array< uint32_t, 2 > freed_ids = {INVALID_CHUNK_ID, INVALID_CHUNK_ID};
    uint32_t                  nids = 0;

    // Check if previous and next chunk are free, if so make it contiguous chunk
    PhysicalDevChunk* prev_chunk = chunk->get_prev_chunk();
    PhysicalDevChunk* next_chunk = chunk->get_next_chunk();

    if (prev_chunk && !prev_chunk->is_busy()) {
        // We can merge our space to prev_chunk and remove our current chunk.
        prev_chunk->set_size(prev_chunk->get_size() + chunk->get_size());
        prev_chunk->set_next_chunk(chunk->get_next_chunk());

        // Erase the current chunk entry
        prev_chunk->set_next_chunk(chunk->get_next_chunk());
        if (next_chunk)
            next_chunk->set_prev_chunk(prev_chunk);

        freed_ids[nids++] = chunk->get_chunk_id();
        chunk = prev_chunk;
    }

    if (next_chunk && !next_chunk->is_busy()) {
        next_chunk->set_size(chunk->get_size() + next_chunk->get_size());
        next_chunk->set_start_offset(chunk->get_start_offset());

        // Erase the current chunk entry
        next_chunk->set_prev_chunk(chunk->get_prev_chunk());
        auto p = chunk->get_prev_chunk();
        if (p)
            p->set_next_chunk(next_chunk);
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
    ss << "Device fd = " << m_devfd << "\n";
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
    m_pdev = pdev;
}

PhysicalDevChunk* PhysicalDevChunk::get_next_chunk() const { return device_manager()->get_chunk(get_next_chunk_id()); }

PhysicalDevChunk* PhysicalDevChunk::get_prev_chunk() const { return device_manager()->get_chunk(get_prev_chunk_id()); }

PhysicalDevChunk* PhysicalDevChunk::get_primary_chunk() const {
    return device_manager()->get_chunk(m_chunk_info->primary_chunk_id);
}

DeviceManager* PhysicalDevChunk::device_manager() const { return get_physical_dev()->device_manager(); }
} // namespace homestore
