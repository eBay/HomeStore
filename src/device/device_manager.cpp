/*
 * DeviceManager.cpp
 *
 *  Created on: 20-Aug-2016
 *      Author: hkadayam
 */

#include "device.h"
#include <fcntl.h>
#include <boost/range.hpp>

namespace homestore {

DeviceManager::DeviceManager(NewVDevCallback vcb, uint32_t vdev_metadata_size) :
        m_open_flags(O_RDWR),
        m_new_vdev_cb(vcb) {
    m_pdev_info.num_phys_devs = 0;
    m_last_vdevid = INVALID_VDEV_ID;
    m_vdev_metadata_size = vdev_metadata_size;
}

void DeviceManager::add_devices(std::vector< std::string > &dev_names) {
    std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);

    std::vector< std::unique_ptr< PhysicalDev > > uninit_devs;
    uninit_devs.reserve(dev_names.size());

    uint64_t max_dev_offset = 0;
    for (auto &d : dev_names) {
        std::unique_ptr< PhysicalDev > pdev = std::make_unique< PhysicalDev >(this, d, m_open_flags);
        if (1 || !pdev->load_super_block()) {
            // Super block is not present, possibly a new device, will format the device later
            LOG(INFO) << "Device " << d << " appears to be not formatted. Will format it ";
            uninit_devs.push_back(std::move(pdev));
            continue;
        }

        // TODO: Very important to actually keep track of revision number of super block and validate if all of the
        // devices are in same revision number.
        assert(pdev->get_dev_id() != INVALID_PDEV_ID);
        auto pdev_raw = pdev.get();
        m_pdevs[pdev->get_dev_id()] = std::move(pdev);

        LOG(INFO) << "Device " << d << " is already formatted. Loading the format ";
        // Load all pdev information, if its the first device loading
        if (m_pdev_info.num_phys_devs == 0) {
            read_info_blocks(pdev_raw);

            for (auto i : boost::irange<uint32_t>(0, m_pdev_info.num_phys_devs)) {
                auto *pdinfo = &m_pdev_info.pdev_info_blks[i];
                max_dev_offset = std::max(max_dev_offset, pdinfo->dev_offset + pdev_raw->get_size());
            }
        } else {
            // TODO: Assert if the read blocks from other devices is same as this one or use the one with lowest revision
        }
    }

    // For any of the uninitialized device, look for new pdev id and format them and add it to devices list
    uint32_t pdev_id = m_pdev_info.num_phys_devs;
    for (auto &pdev: uninit_devs) {
        pdev->format_super_block(pdev_id++, max_dev_offset);
        max_dev_offset += pdev->get_size();
    }

    // If info blocks are not loaded at this time, we don't have info blocks at all. Create that and write to all
    // uninitialized physical devices
    if (m_pdev_info.num_phys_devs == 0) {
        // Format the m_pdev_info
        m_pdev_info.version = CURRENT_PDEV_INFO_BLOCK_VERSION;
        m_pdev_info.num_phys_devs = (uint32_t)uninit_devs.size();
        for (auto i = 0; i < uninit_devs.size(); i++) {
            m_pdev_info.pdev_info_blks[i] = uninit_devs[i]->get_super_block_header()->this_dev_info;
        }

        // Create a new chunk info and new single chunk comprising entire device
        m_chunk_info.version = CURRENT_CHUNK_INFO_BLOCK_VERSION;
        m_chunk_info.num_chunks = 0;
        m_chunk_info.revision_num = 1;
        for (auto &d : uninit_devs) {
            create_new_chunk(d.get(), SUPERBLOCK_SIZE, d->get_size() - SUPERBLOCK_SIZE, nullptr);
        }

        // Create a new vdev info
        m_vdev_info.version = CURRENT_VDEV_INFO_BLOCK_VERSION;
        m_vdev_info.num_vdevs = 0;
        m_vdev_info.context_data_size = m_vdev_metadata_size;
        m_vdev_info.first_vdev_id = INVALID_VDEV_ID;
    } else {
        // Add the newly initialized device to the pdev list
        for (auto i = 0; i < uninit_devs.size(); i++) {
            m_pdev_info.pdev_info_blks[m_pdev_info.num_phys_devs + i] =
                    uninit_devs[i]->get_super_block_header()->this_dev_info;
        }
        m_pdev_info.num_phys_devs += uninit_devs.size();
        if (m_vdev_info.context_data_size < m_vdev_metadata_size) {
            throw DeviceException("The metadata size in phys device is not same");
        }
    }

    // Finally move all the uinit_devs into the m_pdevs list
    for (auto &pdev: uninit_devs) {
        m_pdevs[pdev->get_dev_id()] = std::move(pdev);
    }

    // Walk thru list of vdevs and inform about the newly identified vdev device.
    //TODO: for now, don't add the vdev
    uint32_t vid = m_vdev_info.first_vdev_id;
    while (vid != INVALID_VDEV_ID) {
        m_last_vdevid = vid;
        auto vdev = m_new_vdev_cb(this, &m_vdev_info.vdevs[vid]);
        m_vdevs[vid] = vdev;
        vid = m_vdev_info.vdevs[vid].next_vdev_id;
    }

    // Loop through all devices and create a chunks list for that physical device
    for (auto &pdev: m_pdevs) {
        uint32_t cid = pdev->get_super_block_header()->this_dev_info.first_chunk_id;
        while (cid != INVALID_CHUNK_ID) {
            if (!m_chunks[cid]) {
                auto cinfo = &m_chunk_info.chunks[cid];

                // Create new chunk if it does not exist and also inform to vdev thats a new chunk has come for you
                m_chunks[cid] = std::make_unique< PhysicalDevChunk >(pdev.get(), cinfo);
                if (cinfo->vdev_id != INVALID_VDEV_ID) {
                    m_vdevs[cinfo->vdev_id]->add_chunk(m_chunks[cid].get());
                }
            }
            cid = m_chunk_info.chunks[cid].next_chunk_id;
        }

        write_info_blocks(pdev.get());
    }
}

inline void DeviceManager::read_info_blocks(PhysicalDev *pdev) {
    pdev->read((char *)&m_pdev_info, sizeof(m_pdev_info), pdev->get_super_block_header()->pdevs_block_offset);
    pdev->read((char *)&m_chunk_info, sizeof(m_chunk_info), pdev->get_super_block_header()->chunks_block_offset);
    pdev->read((char *)&m_vdev_info, sizeof(m_vdev_info), pdev->get_super_block_header()->vdevs_block_offset);
}

inline void DeviceManager::write_info_blocks(PhysicalDev *pdev) {
    pdev->write((char *)&m_pdev_info, sizeof(m_pdev_info), pdev->get_super_block_header()->pdevs_block_offset);
    pdev->write((char *)&m_chunk_info, sizeof(m_chunk_info), pdev->get_super_block_header()->chunks_block_offset);
    pdev->write((char *)&m_vdev_info, sizeof(m_vdev_info), pdev->get_super_block_header()->vdevs_block_offset);
}

PhysicalDevChunk *DeviceManager::alloc_chunk(PhysicalDev *pdev, uint32_t vdev_id, uint64_t req_size) {
    std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);

    PhysicalDevChunk *chunk = pdev->find_free_chunk(req_size);
    if (chunk == nullptr) {
        std::stringstream ss; ss << "No space available for chunk size = " << req_size << " in pdev id = " << pdev->get_dev_id();
        throw DeviceException(ss.str());
    }
    assert(chunk->get_size() >= req_size);
    chunk->set_vdev_id(vdev_id); // Set the chunk as busy or engaged to a vdev

    if (chunk->get_size() > req_size) {
        // There is some left over space, create a new chunk and insert it after current chunk
        create_new_chunk(pdev, chunk->get_start_offset() + req_size, chunk->get_size() - req_size, chunk);
        chunk->set_size(req_size);
    }

    // Persist the allocation
    for (auto &pd: m_pdevs) {
        pd->write((char *) &m_chunk_info, sizeof(m_chunk_info), pd->get_super_block_header()->chunks_block_offset);
    }
    return chunk;
}

void DeviceManager::free_chunk(PhysicalDevChunk *chunk) {
    std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);
    chunk->set_free();

    PhysicalDev *pdev = chunk->get_physical_dev_mutable();
    auto freed_ids = pdev->merge_free_chunks(chunk);
    for (auto ids : freed_ids) {
        if (ids != INVALID_CHUNK_ID) {
            remove_chunk(ids);
        }
    }

    // Persist the free_chunk
    for (auto &pd: m_pdevs) {
        pd->write((char *) &m_chunk_info, sizeof(m_chunk_info), pd->get_super_block_header()->chunks_block_offset);
    }
}

vdev_info_block *DeviceManager::alloc_vdev(uint64_t req_size, uint32_t nmirrors, uint32_t blk_size) {
    std::lock_guard<decltype(m_vdev_mutex)> lock(m_vdev_mutex);

    vdev_info_block *vb = alloc_new_vdev_slot();
    vb->size = req_size;
    vb->num_mirrors = nmirrors;
    vb->blk_size = blk_size;

    vb->prev_vdev_id = m_last_vdevid;
    if (m_last_vdevid == INVALID_VDEV_ID) {
        // This is the first vdev being created.
        assert(m_vdev_info.first_vdev_id == INVALID_VDEV_ID);
        m_vdev_info.first_vdev_id = vb->vdev_id;
    } else {
        auto prev_vb = get_vdev_info_block(m_last_vdevid);
        prev_vb->next_vdev_id = vb->vdev_id;
    }
    m_last_vdevid = vb->vdev_id;
    vb->next_vdev_id = INVALID_VDEV_ID;

    LOG(INFO) << "Creating vdev id = " << vb->vdev_id << " size = " << vb->size;
    m_vdev_info.num_vdevs++;
    for (auto &pdev: m_pdevs) {
        pdev->write((char *) &m_vdev_info, sizeof(m_vdev_info), pdev->get_super_block_header()->vdevs_block_offset);
    }
    return vb;
}

void DeviceManager::free_vdev(vdev_info_block *vb) {
    std::lock_guard<decltype(m_vdev_mutex)> lock(m_vdev_mutex);

    auto prev_vb = get_prev_info_block(vb);
    auto next_vb = get_next_info_block(vb);

    if (prev_vb) {
        prev_vb->next_vdev_id = vb->next_vdev_id;
    } else {
        m_vdev_info.first_vdev_id = vb->next_vdev_id;
    }

    if (next_vb) next_vb->prev_vdev_id = vb->prev_vdev_id;
    vb->slot_allocated = false;

    m_vdev_info.num_vdevs--;
    for (auto &pdev: m_pdevs) {
        pdev->write((char *) &m_vdev_info, sizeof(m_vdev_info), pdev->get_super_block_header()->vdevs_block_offset);
    }
}

/* This method creates a new chunk for a given physical device and attaches the chunk to the physical device
 * after previous chunk (if non-null) or last if null */
PhysicalDevChunk *DeviceManager::create_new_chunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size,
                                                  PhysicalDevChunk *prev_chunk) {
    uint32_t slot;

    // Allocate a slot for the new chunk (which becomes new chunk id) and create a new PhysicalDevChunk instance
    // and attach it to a physical device
    chunk_info_block *c = alloc_new_chunk_slot(&slot);

    auto chunk = std::make_unique<PhysicalDevChunk>(pdev, slot, start_offset, size, c);
    PhysicalDevChunk *craw = chunk.get();
    pdev->attach_chunk(craw, prev_chunk);

    LOG(INFO) << "Creating chunk: " << chunk->to_string();
    m_chunks[chunk->get_chunk_id()] = std::move(chunk);
    m_chunk_info.num_chunks++;

    return craw;
}

void DeviceManager::remove_chunk(uint32_t chunk_id) {
    assert(m_chunk_info.chunks[chunk_id].slot_allocated);
    m_chunk_info.chunks[chunk_id].slot_allocated = false; // Free up the slot for future allocations
    m_chunk_info.num_chunks--;
}

chunk_info_block *DeviceManager::alloc_new_chunk_slot(uint32_t *pslot_num) {
    uint32_t start_slot = m_chunk_info.num_chunks;
    uint32_t cur_slot = start_slot;
    do {
        if (!m_chunk_info.chunks[cur_slot].slot_allocated) {
            m_chunk_info.chunks[cur_slot].slot_allocated = true;
            *pslot_num = cur_slot;
            return &m_chunk_info.chunks[cur_slot];
        }
        cur_slot++;
        if (cur_slot == max_chunk_slots()) cur_slot = 0;
    } while (cur_slot != start_slot);

    throw DeviceException("No new chunk slot available in the device.");
}

vdev_info_block *DeviceManager::alloc_new_vdev_slot() {
    uint32_t id = 0;

    vdev_info_block *vb = &m_vdev_info.vdevs[0];
    while (vb) {
        if (!vb->slot_allocated) {
            vb->slot_allocated = true;
            vb->vdev_id = id;
            return vb;
        }

        vb = get_next_info_block(vb);
        ++id;
    }

    throw DeviceException("No new slot available in the device allocated.");
}

#if 0
PhysicalDevChunk *PhysicalDev::__alloc_chunk(uint64_t req_size, bool is_super_block) {
    std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);

    PhysicalDevChunk *chunk = find_free_chunk(req_size);
    if (chunk == nullptr) {
        // There are no readily available free chunk which has the required space available. Try to create one
        auto &prev_chunk = m_chunks.back();
        uint64_t next_offset = prev_chunk.get_start_offset() + prev_chunk.get_size();
        if (next_offset >= m_devsize) {
            throw DeviceException("No more space available for free chunks on device " + get_devname());
        }

        // We do have some space available, try to get a new slot from persistent area and put the new chunk in the list
        chunk = DeviceManagerInstance.create_new_chunk(this, next_offset, req_size, &prev_chunk);
    } else {
        assert(chunk->get_size() >= req_size);
        chunk->set_busy(true);

        if (chunk->get_size() > req_size) {
            // There is some left over space, create a new chunk and insert it after current chunk
            DeviceManagerInstance.create_new_chunk(this, chunk->get_start_offset() + req_size,
                                                   chunk->get_size() - req_size, chunk);
            chunk->set_size(req_size);
        }
    }

    if (is_super_block) {
        m_pers_hdr_block.super_block_chunk_id = chunk->get_chunk_id();
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
    std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);
    chunk->set_busy(false);

    // Check if previous and next chunk are free, if so make it contiguous chunk
    auto it = m_chunks.iterator_to(*chunk);
    PhysicalDevChunk *prev_chunk = &*(--it);
    if (!prev_chunk->is_busy()) {
        // We can merge our space to prev_chunk and remove our current chunk.
        prev_chunk->set_size(prev_chunk->get_size() + chunk->get_size());
        DeviceManagerInstance.remove_chunk(chunk);
        chunk = prev_chunk;
    }

    it = m_chunks.iterator_to(*chunk);
    PhysicalDevChunk *next_chunk = (++it == m_chunks.end()) ? nullptr : &*it;
    if (next_chunk && !next_chunk->is_busy()) {
        // Next chunk can merge with us and remove the next chunk
        chunk->set_size(chunk->get_size() + next_chunk->get_size());
        DeviceManagerInstance.remove_chunk(next_chunk);
    }

    // Persist the header block
    try {
        write_header_block();
    } catch (std::system_error &e) {
        load(false); // Reload the buffer from memory
        throw DeviceException("Unable to commit write header block error for device " + get_devname());
    }
}

bool PhysicalDev::try_expand_chunk(PhysicalDevChunk *chunk, uint32_t addln_size) {
    std::lock_guard<decltype(m_chunk_mutex)> lock(m_chunk_mutex);

    bool space_updated = false;
    auto it = m_chunks.iterator_to(*chunk);
    PhysicalDevChunk *next_chunk = (++it == m_chunks.end()) ? nullptr : &*it;

    if (next_chunk == nullptr) {
        // This is the last chunk, if we have space in the device, go for it
        if ((chunk->get_start_offset() + chunk->get_size() + addln_size) <= m_devsize) {
            chunk->set_size(chunk->get_size() + addln_size);
            space_updated = true;
        }
    } else {
        // TODO: We are not the last chunk, but if next chunks are free use it to merge and create one chunk itself
    }

    if (space_updated) {
        try {
            write_header_block();
            return true;
        } catch (std::system_error &e) {
            return false;
        }
    } else {
        return false;
    }
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
            m_pers_hdr_block.chunks[cur_slot].slot_allocated = true;
            *pslot_num = cur_slot;
            return &m_pers_hdr_block.chunks[cur_slot];
        }
        cur_slot++;
        if (cur_slot == max_slots()) cur_slot = 0;
    } while (cur_slot != start_slot);

    throw DeviceException("No new slot available in the device allocated.");
}

std::string PhysicalDev::to_string() {
    std::stringstream ss;
    ss << "Device name = " << m_devname << "\n";
    ss << "Device fd = " << m_devfd << "\n";
    ss << "Device size = " << m_devsize << "\n";
    ss << "Header:\n";
    ss << "\tMagic = " << m_pers_hdr_block.magic << "\n";
    ss << "\tProduct Name = " << m_pers_hdr_block.product_name << "\n";
    ss << "\tHeader version = " << m_pers_hdr_block.version << "\n";
    ss << "\tUUID = " << m_pers_hdr_block.uuid << "\n";
    ss << "\tSuper block chunk id = " << m_pers_hdr_block.super_block_chunk_id << "\n";
    ss << "\tNum of chunks = " << m_pers_hdr_block.num_chunks << "\n";

    auto i = 0;
    for (auto chunk : m_chunks) {
        ss << "\tChunk " << i++ << " Info: \n\t\t" << chunk.to_string();
    }
    return ss.str();
}

PhysicalDevChunk::PhysicalDevChunk(PhysicalDev *pdev, uint64_t start_offset, uint64_t size, phys_chunk_header *hdr) :
        m_pdev(pdev),
        m_header(hdr) {
    hdr->chunk_start_offset = start_offset;
    hdr->chunk_size = size;
    hdr->chunk_busy = true;
    m_chunk_id = (uint16_t)(hdr - &pdev->m_pers_hdr_block.chunks[0]);
}
#endif

#if 0
friend class ChunkCyclicIterator;
    class ChunkCyclicIterator {
    public:
        ChunkCyclicIterator(PhysicalDev *pdev) :
                m_pdev(pdev) {
            m_iter = m_pdev->m_chunks.begin();
        }

        PhysicalDevChunk *&operator *() {
            return *m_iter;
        }

        ChunkCyclicIterator &operator++() {
            if (m_iter == m_pdev->m_chunks.end()) {
                m_iter = m_pdev->m_chunks.begin();
            } else {
                ++m_iter;
            }
            return *this;
        }

        ChunkCyclicIterator operator++(int) {
            if (m_iter == m_pdev->m_chunks.end()) {
                m_iter = m_pdev->m_chunks.begin();
            } else {
                m_iter++;
            }
            return *this;
        }

    private:
        PhysicalDev *m_pdev;
        boost::intrusive::list< PhysicalDevChunk >::iterator m_iter;
    };

    ChunkCyclicIterator begin() {
        return ChunkCyclicIterator(this);
    }
#endif
} // namespace homestore
