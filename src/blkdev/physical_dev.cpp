/*
 * PhysicalDev.cpp
 *
 *  Created on: 05-Aug-2016
 *      Author: hkadayam
 */

#include "BlkDev.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <iostream>
#include <folly/Exception.h>
#include <boost/utility.hpp>

namespace omstore {

static __thread char hdr_tmp_buf[PHYS_DEV_PERSISTENT_HEADER_SIZE];

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

PhysicalDev::PhysicalDev(std::string devname, int oflags) :
        m_devname(devname) {
    struct stat stat_buf;
    stat(devname.c_str(), &stat_buf);
    m_devsize = (uint64_t) stat_buf.st_size;

    // open and load the header block and validate if its a valid device
    folly::checkUnixError(m_devfd = open(devname.c_str(), oflags));
    if (load() == false) {
        LOG(INFO) << "The device opened doesn't seemed to have formatted. Doing an auto format now";
        format();
    }
}

PhysicalDev::~PhysicalDev() {
    for (auto it : m_chunks) {
        delete(*it);
    }
}

bool PhysicalDev::load(bool from_persistent_area) {
    // First try reading the header block.
    if (from_persistent_area) {
        try {
            read_header_block();
        } catch (std::system_error &e) {
            // TODO: Add more info on system error to this exception
            throw DeviceException("Unable to load the phys dev header from persistent area for device " + get_devname());
        }

        // Validate if its omstore formatted device
        bool is_omstore_dev = validate_device();
        if (!is_omstore_dev) {
            return false;
        }
    }

    // First wipe up off any in-memory chunks info
    while (!m_chunks.empty()) {
        auto& chunk = m_chunks.front();
        m_chunks.pop_front();
        delete(&chunk);
    }

    uint32_t slot = 0;
    for (auto i = 0; i < m_pers_hdr_block.num_chunks; i++) {
        auto pc = &m_pers_hdr_block.chunks[slot];

        // Create new physical device chunk and add to the slot
        auto chunk = new PhysicalDevChunk(this, pc->chunk_start_offset, pc->chunk_size, pc);
        m_chunks.push_back(*chunk);

        slot = pc->next_chunk_slot;
    }

    return true;
}

void PhysicalDev::format() {
    boost::uuids::random_generator generator;

    // Format the structure
    m_pers_hdr_block.magic = MAGIC;
    strcpy(m_pers_hdr_block.product_name, PRODUCT_NAME);
    m_pers_hdr_block.version = 1;
    m_pers_hdr_block.uuid = generator();
    m_pers_hdr_block.num_chunks = 1;
    m_pers_hdr_block.super_block_chunk_id = 1; // Next chunk to this chunk.

    // Initialize this header block chunk
    m_pers_hdr_block.chunks[0].chunk_start_offset = 0;
    m_pers_hdr_block.chunks[0].chunk_size = PHYS_DEV_PERSISTENT_HEADER_SIZE;
    m_pers_hdr_block.chunks[0].chunk_busy = true;
    m_pers_hdr_block.chunks[0].next_chunk_slot = INVALID_CHUNK_ID;
    m_pers_hdr_block.chunks[0].slot_allocated = true;

    // Write the information to the offset
    try {
        write_header_block();
    } catch (std::system_error &e) {
        load(false); // Reload the buffer from memory
        throw DeviceException("Unable to format the device - write header block error for device " + get_devname());
    }

    // Create the first chunk into the list
    auto chunk = new PhysicalDevChunk(this, 0, PHYS_DEV_PERSISTENT_HEADER_SIZE, &m_pers_hdr_block.chunks[0]);
    m_chunks.push_back(*chunk);

    // Now essential information is present, lets load
    load(false);
}

PhysicalDevChunk *PhysicalDev::alloc_chunk(uint64_t req_size) {
    PhysicalDevChunk *chunk = find_free_chunk(req_size);
    if (chunk == nullptr) {
        // There are no readily available free chunk which has the required space available. Try to create one
        auto &prev_chunk = m_chunks.back();
        uint64_t next_offset = prev_chunk.get_start_offset() + prev_chunk.get_size();
        if (next_offset >= m_devsize) {
            throw DeviceException("No more space available for free chunks on device " + get_devname());
        }

        // We do have some space available, try to get a new slot from persistent area and put the new chunk in the list
        chunk = PhysicalDevChunk::create_new_chunk(this, next_offset, req_size, &prev_chunk);
    } else {
        assert(chunk->get_size() >= req_size);
        chunk->set_busy(true);

        if (chunk->get_size() > req_size) {
            // There is some left over space, create a new chunk and insert it after current chunk
            PhysicalDevChunk::create_new_chunk(this, chunk->get_start_offset() + req_size,
                                               chunk->get_size() - req_size, chunk);
            chunk->set_size(req_size);
        }
    }

    // Persist the header block
    try {
        write_header_block();
    } catch (std::system_error &e) {
        load(false); // Reload the buffer from memory
        throw DeviceException("Unable to commit write header block error for device " + get_devname());
    }
    return chunk;
}

void PhysicalDev::free_chunk(PhysicalDevChunk *chunk) {
    chunk->set_busy(false);

    // Check if previous and next chunk are free, if so make it contiguous chunk
    auto it = m_chunks.iterator_to(*chunk);
    PhysicalDevChunk *prev_chunk = &*(--it);
    if (!prev_chunk->is_busy()) {
        // We can merge our space to prev_chunk and remove our current chunk.
        prev_chunk->set_size(prev_chunk->get_size() + chunk->get_size());
        PhysicalDevChunk::remove_chunk(chunk);
        chunk = prev_chunk;
    }

    it = m_chunks.iterator_to(*chunk);
    PhysicalDevChunk *next_chunk = &*(++it);
    if (!next_chunk->is_busy()) {
        // Next chunk can merge with us and remove the next chunk
        chunk->set_size(chunk->get_size() + next_chunk->get_size());
        PhysicalDevChunk::remove_chunk(next_chunk);
    }

    // Persist the header block
    try {
        write_header_block();
    } catch (std::system_error &e) {
        load(false); // Reload the buffer from memory
        throw DeviceException("Unable to commit write header block error for device " + get_devname());
    }
}

inline void PhysicalDev::write_header_block() {
    // Make a temp copy in case of failures
    memcpy(hdr_tmp_buf, &m_pers_hdr_block, PHYS_DEV_PERSISTENT_HEADER_SIZE);
    ssize_t bytes = pwrite(m_devfd, &m_pers_hdr_block, m_pers_hdr_block.chunks[0].chunk_start_offset,
                           m_pers_hdr_block.chunks[0].chunk_size);
    if (unlikely((bytes < 0) || (bytes != m_pers_hdr_block.chunks[0].chunk_size))) {
        memcpy(&m_pers_hdr_block, hdr_tmp_buf, PHYS_DEV_PERSISTENT_HEADER_SIZE);
        folly::throwSystemError("Header block write failed");
    }
}

inline void PhysicalDev::read_header_block() {
    memset(&m_pers_hdr_block, 0, PHYS_DEV_PERSISTENT_HEADER_SIZE);

    ssize_t bytes = pread(m_devfd, &m_pers_hdr_block, 0, PHYS_DEV_PERSISTENT_HEADER_SIZE);
    if (unlikely((bytes < 0) || (bytes != m_pers_hdr_block.chunks[0].chunk_size))) {
        folly::throwSystemError("Header block read failed");
    }
}

BlkOpStatus PhysicalDev::write(const char *data, uint32_t size, uint64_t offset) {
    ssize_t writtenSize = pwrite(get_devfd(), data, (ssize_t) size, (off_t) offset);
    if (writtenSize != size) {
        perror("PhysicalDev::write error");
        cout << "Error trying to write offset " << offset << " size = " << size << endl;
        return BLK_OP_FAILED;
    }

    return BLK_OP_SUCCESS;
}

BlkOpStatus PhysicalDev::writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t writtenSize = pwritev(get_devfd(), iov, iovcnt, offset);
    if (writtenSize != size) {
        perror("PhysicalDev:writev error");
        cout << "Error trying to write offset " << offset << " size to write = " << size << " size written = "
             << writtenSize << endl;
        return BLK_OP_FAILED;
    }

    return BLK_OP_SUCCESS;
}

BlkOpStatus PhysicalDev::read(char *data, uint32_t size, uint64_t offset) {
    ssize_t readSize = pread(get_devfd(), data, (ssize_t) size, (off_t) offset);
    if (readSize != size) {
        perror("PhysicalDev::read error");
        cout << "Error trying to read offset " << offset << " size = " << size << endl;
        return BLK_OP_FAILED;
    }

    return BLK_OP_SUCCESS;
}

BlkOpStatus PhysicalDev::readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset) {
    ssize_t readSize = preadv(get_devfd(), iov, iovcnt, (off_t) offset);
    if (readSize != size) {
        perror("PhysicalDev::read error");
        cout << "Error trying to read offset " << offset << " size to read = " << size << " size read = " << readSize
             << endl;
        return BLK_OP_FAILED;
    }

    return BLK_OP_SUCCESS;
}

PhysicalDevChunk *PhysicalDev::find_free_chunk(uint64_t req_size) {
    // Get the slot with closest size;
    PhysicalDevChunk *closest_chunk = nullptr;

    for (auto &chunk : m_chunks) {
        if (!chunk.is_busy() && (chunk.get_size() >= req_size)) {
            if ((closest_chunk == nullptr) || (chunk.get_size() < closest_chunk->get_size())) {
                closest_chunk = &chunk;
            }
        }
    }

    return closest_chunk;
}

phys_chunk_header *PhysicalDev::alloc_new_slot(uint32_t *pslot_num) {
    uint32_t start_slot = m_pers_hdr_block.num_chunks;
    uint32_t cur_slot = start_slot;
    do {
        if (!m_pers_hdr_block.chunks[cur_slot].slot_allocated) {
            return &m_pers_hdr_block.chunks[cur_slot];
        }
        cur_slot++;
        if (cur_slot == max_slots()) cur_slot = 0;
    } while (cur_slot != start_slot);

    throw DeviceException("No new slot available in the device allocated.");
}

PhysicalDevChunk *PhysicalDevChunk::create_new_chunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size,
                                     PhysicalDevChunk *prev_chunk) {
    uint32_t slot;
    phys_chunk_header *h = pdev->alloc_new_slot(&slot);

    auto chunk = new PhysicalDevChunk(pdev, start_offset, size, h);
    if (prev_chunk) {
        chunk->set_next_chunk_slot(prev_chunk->get_next_chunk_slot());
        prev_chunk->set_next_chunk_slot(slot);
        auto it = pdev->m_chunks.iterator_to(*prev_chunk);
        pdev->m_chunks.insert(++it, chunk);
    }
    return chunk;
}

void PhysicalDevChunk::remove_chunk(PhysicalDevChunk *chunk) {
    PhysicalDev *pdev = chunk->m_pdev;
    auto it = pdev->m_chunks.iterator_to(*chunk);
    if (it != pdev->m_chunks.begin()) {
        auto prev_chunk = &*(--it);
        prev_chunk->set_next_chunk_slot(chunk->get_next_chunk_slot());
        ++it;
    } else {
        assert(0); // We don't expect first chunk to be deleted.
    }

    chunk->free_slot();
    pdev->m_chunks.erase(it);
    delete(chunk);
}

} // namespace omstore