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
#include "homeds/utility/useful_defs.hpp"
#ifdef __linux__
#include <linux/fs.h>
#include <sys/ioctl.h> 
#endif

namespace homestore {

static __thread char hdr_tmp_buf[SUPERBLOCK_MAX_HEADER_SIZE];

#ifdef __APPLE__

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return ::readv(fd, iov, iovcnt);
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    lseek(fd, offset, SEEK_SET);
    return ::writev(fd, iov, iovcnt);
}

#endif

static std::atomic< uint64_t > glob_phys_dev_offset(0);
static std::atomic< uint32_t > glob_phys_dev_ids(0);

/* This method opens the device and tries to load the info from the device. If its unable to load
 * it, formats the device and sets formatted = true. It can throw DeviceException or system_error
 * or std::bad_alloc exception */
std::unique_ptr<PhysicalDev> PhysicalDev::load(DeviceManager *dev_mgr, std::string devname, int oflags, bool *is_new) {
    std::unique_ptr< PhysicalDev > pdev = std::make_unique< PhysicalDev >(dev_mgr, devname, oflags);

    try {
        if (pdev->load_super_block()) {
            *is_new = false;
            LOG(INFO) << "Successfully loaded the device " << devname.c_str() << ", it was already formatted";
            return std::move(pdev);
        }
    } catch (std::exception &e) {
        throw e;
    }

    *is_new = true;
    return std::move(pdev);
}

PhysicalDev::PhysicalDev(DeviceManager *mgr, std::string devname, int oflags) :
        m_mgr(mgr),
        m_devname(devname) {
    struct stat stat_buf;
    stat(devname.c_str(), &stat_buf);
    m_devsize = (uint64_t) stat_buf.st_size;

    // open and load the header block and validate if its a valid device
    folly::checkUnixError(m_devfd = open(devname.c_str(), oflags));
#ifdef __linux__
    if (ioctl(m_devfd,BLKGETSIZE64,&m_devsize) < 0) {
	/* TODO: need better way to handle it */
	assert(0);
    }
    assert(size > 0); 
#endif
}

bool PhysicalDev::load_super_block() {
    memset(&m_super_blk_header, 0, SUPERBLOCK_MAX_HEADER_SIZE);

    try {
        read_superblock_header();
    } catch (std::system_error &e) {
        throw DeviceException("Unable to read the device - read super block header error for device " +
                              get_devname() + " Exception info: " + e.what());
    }

    // Validate if its homestore formatted device
    bool is_omstore_dev = validate_device();
    if (!is_omstore_dev) {
        return false;
    }
    return true;
}

void PhysicalDev::format_super_block(uint32_t dev_id, uint64_t dev_offset) {
    boost::uuids::random_generator generator;

    // Format the super block and this device info structure
    m_super_blk_header.magic = MAGIC;
    strcpy(m_super_blk_header.product_name, PRODUCT_NAME);
    m_super_blk_header.version = CURRENT_SUPERBLOCK_VERSION;
    m_super_blk_header.pdevs_block_offset = SUPERBLOCK_MAX_HEADER_SIZE;
    m_super_blk_header.chunks_block_offset = m_super_blk_header.pdevs_block_offset + PDEVS_BLOCK_MAX_SIZE;
    m_super_blk_header.vdevs_block_offset = m_super_blk_header.chunks_block_offset + CHUNKS_BLOCK_MAX_SIZE;
    m_super_blk_header.this_dev_info.uuid = generator();
    m_super_blk_header.this_dev_info.dev_num = dev_id;
    m_super_blk_header.this_dev_info.first_chunk_id = INVALID_CHUNK_ID;
    m_super_blk_header.this_dev_info.dev_offset = dev_offset;

    // Write the information to the offset
    try {
        write_superblock_header();
    } catch (std::system_error &e) {
        throw DeviceException("Unable to format the device - write header block error for device " +
                              get_devname() + " Exception info: " + e.what());
    }
}

inline bool PhysicalDev::validate_device() {
    return ((m_super_blk_header.magic == MAGIC) &&
            (strcmp(m_super_blk_header.product_name, "OmStore") == 0) &&
            (m_super_blk_header.version == CURRENT_SUPERBLOCK_VERSION));
}

inline void PhysicalDev::write_superblock_header() {
    // Make a temp copy in case of failures
    memcpy(hdr_tmp_buf, &m_super_blk_header, SUPERBLOCK_MAX_HEADER_SIZE);
    ssize_t bytes = pwrite(m_devfd, &m_super_blk_header, SUPERBLOCK_MAX_HEADER_SIZE, 0);
    if (unlikely((bytes < 0) || (bytes != SUPERBLOCK_MAX_HEADER_SIZE))) {
        memcpy(&m_super_blk_header, hdr_tmp_buf, SUPERBLOCK_MAX_HEADER_SIZE);
        folly::throwSystemError("Header block write failed");
    }
}

inline void PhysicalDev::read_superblock_header() {
    memset(&m_super_blk_header, 0, SUPERBLOCK_MAX_HEADER_SIZE);

    ssize_t bytes = pread(m_devfd, &m_super_blk_header, SUPERBLOCK_MAX_HEADER_SIZE, 0);
    if (unlikely((bytes < 0) || (bytes != SUPERBLOCK_MAX_HEADER_SIZE))) {
        folly::throwSystemError("Header block read failed");
    }
}

void PhysicalDev::write(const char *data, uint32_t size, uint64_t offset) {
    ssize_t writtenSize = pwrite(get_devfd(), data, (ssize_t) size, (off_t) offset);
    if (writtenSize != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " << size << " size written = "
           << writtenSize << "\n";
        folly::throwSystemError(ss.str());
    }
}

void PhysicalDev::writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t written_size = pwritev(get_devfd(), iov, iovcnt, offset);
    if (written_size != size) {
        std::stringstream ss;
        ss << "Error trying to write offset " << offset << " size to write = " << size << " size written = "
           << written_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void PhysicalDev::read(char *data, uint32_t size, uint64_t offset) {
    ssize_t read_size = pread(get_devfd(), data, (ssize_t) size, (off_t) offset);
    if (read_size != size) {
        std::stringstream ss;
        ss << "Error trying to read offset " << offset << " size to read = " << size << " size read = "
           << read_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void PhysicalDev::readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t read_size = preadv(get_devfd(), iov, iovcnt, (off_t) offset);
    if (read_size != size) {
        std::stringstream ss;
        ss << "Error trying to read offset " << offset << " size to read = " << size << " size read = "
           << read_size << "\n";
        folly::throwSystemError(ss.str());
    }
}

void PhysicalDev::attach_chunk(PhysicalDevChunk *chunk, PhysicalDevChunk *after) {
    if (after) {
        chunk->set_next_chunk(after->get_next_chunk());
        chunk->set_prev_chunk(after);

        auto next = after->get_next_chunk();
        if (next) next->set_prev_chunk(chunk);
        after->set_next_chunk(chunk);
    } else {
        assert(m_super_blk_header.this_dev_info.first_chunk_id == INVALID_CHUNK_ID);
        m_super_blk_header.this_dev_info.first_chunk_id = chunk->get_chunk_id();
        write_superblock_header();
    }
}

std::array<uint32_t, 2> PhysicalDev::merge_free_chunks(PhysicalDevChunk *chunk) {
    std::array<uint32_t, 2> freed_ids = {INVALID_CHUNK_ID, INVALID_CHUNK_ID};
    uint32_t nids = 0;

    // Check if previous and next chunk are free, if so make it contiguous chunk
    PhysicalDevChunk *prev_chunk = chunk->get_prev_chunk();
    PhysicalDevChunk *next_chunk = chunk->get_next_chunk();

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

PhysicalDevChunk *PhysicalDev::find_free_chunk(uint64_t req_size) {
    // Get the slot with closest size;
    PhysicalDevChunk *closest_chunk = nullptr;

    PhysicalDevChunk *chunk = device_manager()->get_chunk(m_super_blk_header.this_dev_info.first_chunk_id);
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
    ss << "Super Block Header:\n";
    ss << "\tMagic = " << m_super_blk_header.magic << "\n";
    ss << "\tProduct Name = " << m_super_blk_header.product_name << "\n";
    ss << "\tHeader version = " << m_super_blk_header.version << "\n";
    ss << "\tUUID = " << m_super_blk_header.this_dev_info.uuid << "\n";
    ss << "\tPdev Id = " << m_super_blk_header.this_dev_info.dev_num << "\n";
    ss << "\tPdev Offset = " << m_super_blk_header.this_dev_info.dev_offset << "\n";
    ss << "\tFirst chunk id = " << m_super_blk_header.this_dev_info.first_chunk_id << "\n";

    PhysicalDevChunk *pchunk = device_manager()->get_chunk(m_super_blk_header.this_dev_info.first_chunk_id);
    while (pchunk) {
        ss << "\t\t" << pchunk->to_string() << "\n";
        pchunk = pchunk->get_next_chunk();
    }

    return ss.str();
}

/********************* PhysicalDevChunk Section ************************/
PhysicalDevChunk::PhysicalDevChunk(PhysicalDev *pdev, chunk_info_block *cinfo) {
    m_chunk_info = cinfo;
    m_pdev = pdev;
#if 0
    const std::unique_ptr< PhysicalDev > &p =
            (static_cast<const homeds::sparse_vector< std::unique_ptr< PhysicalDev > > &>(device_manager()->m_pdevs))[cinfo->pdev_id];
    m_pdev = p.get();
#endif
}

PhysicalDevChunk::PhysicalDevChunk(PhysicalDev *pdev, uint32_t chunk_id, uint64_t start_offset, uint64_t size,
                                   chunk_info_block *cinfo) {
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
    m_pdev = pdev;
}

PhysicalDevChunk* PhysicalDevChunk::get_next_chunk() const {
    return device_manager()->get_chunk(get_next_chunk_id());
}

PhysicalDevChunk* PhysicalDevChunk::get_prev_chunk() const {
    return device_manager()->get_chunk(get_prev_chunk_id());
}

PhysicalDevChunk* PhysicalDevChunk::get_primary_chunk() const {
    return device_manager()->get_chunk(m_chunk_info->primary_chunk_id);
}

DeviceManager *PhysicalDevChunk::device_manager() const {
    return get_physical_dev()->device_manager();
}
} // namespace homestore
