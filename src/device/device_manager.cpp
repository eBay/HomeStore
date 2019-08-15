/*
 * DeviceManager.cpp
 *
 *  Created on: 20-Aug-2016
 *      Author: hkadayam
 */

#include "device.h"
#include <fcntl.h>
#include <boost/range.hpp>
#include <iomgr/iomgr.hpp>
#include "main/homestore_assert.hpp"

SDS_LOGGING_DECL(device, DEVICE_MANAGER)

using namespace homeio;
namespace homestore {

DeviceManager::DeviceManager(NewVDevCallback vcb,
                             uint32_t const vdev_metadata_size,
                             std::shared_ptr<iomgr::ioMgr> iomgr,
                             homeio::comp_callback cb, bool is_file, boost::uuids::uuid system_uuid, 
                             vdev_error_callback vdev_error_cb) :
        m_comp_cb(cb),
        m_new_vdev_cb(vcb),
        m_iomgr(iomgr),
        m_gen_cnt(0),
        m_is_file(is_file),
        m_is_read_only(false),
        m_system_uuid(system_uuid),
        m_vdev_error_cb(vdev_error_cb) {

    switch(HomeStoreConfig::open_flag) {
#ifndef NDEBUG
        case BUFFERED_IO : m_open_flags = O_RDWR; break;
#endif
        case READ_ONLY   : m_open_flags = O_RDONLY; break;
        case DIRECT_IO   :
        default          : m_open_flags = O_RDWR | O_DIRECT;
    }
    m_last_vdevid = INVALID_VDEV_ID;
    m_vdev_metadata_size = vdev_metadata_size;
    m_pdev_id = 0;
    m_dm_info_size = ALIGN_SIZE(DM_INFO_BLK_SIZE, HomeStoreConfig::phys_page_size);
    auto ret = posix_memalign((void**)&m_chunk_memory, HomeStoreConfig::align_size, m_dm_info_size);

    HS_ASSERT_NOTNULL(LOGMSG, m_chunk_memory);

    bzero(m_chunk_memory, m_dm_info_size);
    m_dm_info = (dm_info*)m_chunk_memory;

    m_pdev_hdr = &m_dm_info->pdev_hdr;
    m_chunk_hdr = &m_dm_info->chunk_hdr;
    m_vdev_hdr = &m_dm_info->vdev_hdr;
    m_scan_cmpltd = false;

    HS_ASSERT_CMP(LOGMSG, m_vdev_metadata_size, <=, MAX_CONTEXT_DATA_SZ);
}

/* It returns total capacity availble to use by virtual dev. */
size_t DeviceManager::get_total_cap() {
    /* we don't support hetrogenous disks */
    return (m_pdevs.size() * (m_pdevs[0]->get_total_cap()));
}

void DeviceManager::init_devices(std::vector< dev_info >& devices) {
    uint32_t max_dev_offset = 0;

    /* set the offset */
    m_dm_info->magic = MAGIC;
    m_dm_info->version = CURRENT_DM_INFO_VERSION;
    m_dm_info->size = m_dm_info_size;
    m_dm_info->version = CURRENT_DM_INFO_VERSION;

    // Create new vdev info
    m_vdev_hdr->magic = MAGIC;
    m_vdev_hdr->num_vdevs = 0;
    m_vdev_hdr->first_vdev_id = INVALID_VDEV_ID;
    m_vdev_hdr->info_offset = VDEV_INFO_BLK_OFFSET;
    m_vdev_hdr->context_data_size = m_vdev_metadata_size;
    m_vdev_info = (vdev_info_block*)(m_chunk_memory + m_vdev_hdr->info_offset);

    // create new chunk info
    m_chunk_hdr->magic = MAGIC;
    m_chunk_hdr->num_chunks = 0;
    m_chunk_hdr->info_offset = CHUNK_INFO_BLK_OFFSET;
    m_chunk_info = (chunk_info_block*)(m_chunk_memory + m_chunk_hdr->info_offset);
    HS_ASSERT_CMP(LOGMSG, HomeStoreConfig::max_chunks, <=, MAX_CHUNK_ID);

    // create new pdev info
    m_pdev_hdr->magic = MAGIC;
    m_pdev_hdr->num_phys_devs = (uint32_t)devices.size();
    m_pdev_hdr->info_offset = PDEV_INFO_BLK_OFFSET;
    m_pdev_info = (pdev_info_block*)(m_chunk_memory + m_pdev_hdr->info_offset);

    size_t pdev_size = 0;
    for (auto& d : devices) {
        bool                           is_inited;
        std::unique_ptr< PhysicalDev > pdev =
            std::make_unique< PhysicalDev >(this, d.dev_names, m_open_flags, m_iomgr, m_comp_cb, m_system_uuid,
                                            m_pdev_id++, max_dev_offset, m_is_file, true, m_dm_info_size, &is_inited);

        max_dev_offset += pdev->get_size();
        if (!pdev_size) {
            pdev_size = pdev->get_size();
        } else if (pdev_size != pdev->get_size()) {
            std::stringstream ss;
            ss << "heterogenous disks expected size = " << pdev_size << " found size " << pdev->get_size()
               << "disk name: " << pdev->get_devname();
            const std::string s = ss.str();
            throw homestore::homestore_exception(s, homestore_error::hetrogenous_disks);
        }
        auto id = pdev->get_dev_id();
        m_pdevs[id] = std::move(pdev);
        m_pdev_info[id] = m_pdevs[id]->get_info_blk();
    }
    m_scan_cmpltd = true;
    write_info_blocks();
}

DeviceManager::~DeviceManager() {
    free(m_chunk_memory);
    m_dm_info = nullptr;
    m_pdev_hdr = nullptr;
    m_chunk_hdr = nullptr;
    m_vdev_hdr = nullptr;
    m_pdev_info = nullptr;
    m_chunk_info = nullptr;
    m_vdev_info = nullptr;
}

void DeviceManager::update_vb_context(uint32_t vdev_id, uint8_t* blob) {
    std::lock_guard< decltype(m_dev_mutex) > lock(m_dev_mutex);
    memcpy(m_vdev_info[vdev_id].context_data, blob, m_vdev_hdr->context_data_size);
    write_info_blocks();
}

void DeviceManager::load_and_repair_devices(std::vector< dev_info >& devices) {
    std::vector< std::unique_ptr< PhysicalDev > > uninit_devs;
    uninit_devs.reserve(devices.size());
    uint64_t device_id = INVALID_DEV_ID;
    bool     rewrite = false;

    size_t pdev_size = 0;
    for (auto& d : devices) {
        bool                           is_inited;
        std::unique_ptr< PhysicalDev > pdev =
            std::make_unique< PhysicalDev >(this, d.dev_names, m_open_flags, m_iomgr, m_comp_cb, m_system_uuid,
                                            INVALID_DEV_ID, 0, m_is_file, false, m_dm_info_size, &is_inited);
        if (!is_inited) {
            // Super block is not present, possibly a new device, will format the device later
            HS_LOG(CRITICAL, device,
                   "Device {} appears to be not formatted. Will format it and replace it with the failed disks."
                   "Replacing it with the failed disks can cause data loss",
                   d.dev_names);
            uninit_devs.push_back(std::move(pdev));
            continue;
        }

        if (!pdev_size) {
            pdev_size = pdev->get_size();
        }

        HS_ASSERT_CMP(LOGMSG, pdev_size, ==, pdev->get_size());

        if (m_gen_cnt.load() < pdev->sb_gen_cnt()) {
            m_gen_cnt = pdev->sb_gen_cnt();
            device_id = pdev->get_dev_id();
            rewrite   = !m_is_read_only;
        }

        HS_ASSERT_NULL(LOGMSG, m_pdevs[pdev->get_dev_id()].get());

        m_pdevs[pdev->get_dev_id()] = std::move(pdev);
    }

    HS_ASSERT_CMP(LOGMSG, m_gen_cnt.load(), !=, 0, "Couldn't find any valid device.");

    if (m_gen_cnt.load() == 0) {
        std::stringstream ss;
        ss << "No valid device found. line no:" << __LINE__ << "file name:" << __FILE__;
        const std::string s = ss.str();
        throw homestore::homestore_exception(s, homestore_error::no_valid_device_found);
    }

    /* load the info blocks */
    read_info_blocks(device_id);

    /* TODO : If it is different then existing chunk in pdev superblock has to be deleted and new has to be created */
    HS_ASSERT_CMP(LOGMSG, m_dm_info_size, ==, m_dm_info->get_size());
    HS_ASSERT_CMP(LOGMSG, m_dm_info->get_version(), ==, CURRENT_DM_INFO_VERSION);
    /* find the devices which has to be replaced */
    HS_ASSERT_CMP(LOGMSG, m_pdev_hdr->get_num_phys_devs(), <=, HomeStoreConfig::max_pdevs);
    for (uint32_t dev_id = 0; dev_id < m_pdev_hdr->num_phys_devs; ++dev_id) {
        if (m_pdevs[dev_id].get() == nullptr) {
            std::unique_ptr< PhysicalDev > pdev = std::move(uninit_devs.back());
            HS_ASSERT_NOTNULL(LOGMSG, pdev.get());
            if (pdev == nullptr) {
                /* we don't have sufficient disks to replace */
                std::stringstream ss;
                ss << "No spare disk found. line no: " << __LINE__ << "file name:" << __FILE__;
                const std::string s = ss.str();
                throw homestore::homestore_exception(s, homestore_error::no_spare_disk);
                return;
            }
            uninit_devs.pop_back();
            if (pdev_size != pdev->get_size()) {
                std::stringstream ss;
                ss << "heterogenous disks expected size = " << pdev_size << " found size " << pdev->get_size()
                   << "disk name" << pdev->get_devname();
                const std::string s = ss.str();
                throw homestore::homestore_exception(s, homestore_error::hetrogenous_disks);
            }
            pdev->update(dev_id, m_pdev_info[dev_id].dev_offset, m_pdev_info[dev_id].first_chunk_id);
            /* replace this disk with new uuid */
            m_pdevs[dev_id] = std::move(pdev);

            /* mark all the vdevs mounted on this disk to failed state */
            /* TODO:It is ok for now as we have lesser number of chunks. Once we have
             * larger number of chunks, we should optimize it.
             */
            for (uint32_t i = 0; i < HomeStoreConfig::max_chunks; ++i) {
                if (m_chunk_info[i].pdev_id == dev_id) {
                    auto vdev_id = m_chunk_info[i].vdev_id;
                    HS_ASSERT_CMP(LOGMSG, m_vdev_info[vdev_id].get_vdev_id(), ==, vdev_id);
                    /* mark this vdev failed */
                    m_vdev_info[vdev_id].failed = true;
                }
            }
            rewrite = true;
        }
    }

    HS_ASSERT_CMP(LOGMSG, uninit_devs.empty(), ==, true, "Found spare devices which are not added to the system!");

    m_pdev_id = m_pdev_hdr->num_phys_devs;

    /* scan and create all the chunks for all physical devices */
    uint32_t num_chunks = 0;
    for (uint32_t dev_id = 0; dev_id < m_pdev_hdr->num_phys_devs; ++dev_id) {
        uint32_t cid = m_pdevs[dev_id]->get_first_chunk_id();
        while (cid != INVALID_CHUNK_ID) {
            HS_ASSERT_NULL(LOGMSG, m_chunks[cid].get());
            HS_ASSERT_CMP(LOGMSG, cid, <, HomeStoreConfig::max_chunks);
            m_chunks[cid] =
                std::make_unique< PhysicalDevChunk >(m_pdevs[m_chunk_info[cid].pdev_id].get(), &m_chunk_info[cid]);
            if (m_chunk_info[cid].is_sb_chunk) {
                m_pdevs[m_chunk_info[cid].pdev_id]->attach_superblock_chunk(m_chunks[cid].get());
            }
            HS_ASSERT_CMP(LOGMSG, m_chunk_info[cid].get_chunk_id(), ==, cid);
            cid = m_chunk_info[cid].next_chunk_id;
            num_chunks++;
        }
    }

    HS_ASSERT_CMP(LOGMSG, num_chunks, ==, m_chunk_hdr->get_num_chunks());

    m_scan_cmpltd = true;
    /* superblock to all disks is re written if gen cnt mismatches or disks are replaced */
    if (rewrite) {
        /* rewriting superblock */
        write_info_blocks();
    }

    /* create vdevs */
    uint32_t vid = m_vdev_hdr->first_vdev_id;
    uint32_t num_vdevs = 0;
    while (vid != INVALID_VDEV_ID) {
        HS_ASSERT_CMP(LOGMSG, vid, <, HomeStoreConfig::max_vdevs);
        m_last_vdevid = vid;
        m_new_vdev_cb(this, &m_vdev_info[vid]);
        HS_ASSERT_CMP(LOGMSG, m_vdev_info[vid].slot_allocated, ==, true);
        HS_ASSERT_CMP(LOGMSG, m_vdev_info[vid].get_vdev_id(), ==, vid);
        vid = m_vdev_info[vid].next_vdev_id;
        num_vdevs++;
    }
    HS_ASSERT_CMP(LOGMSG, num_vdevs, ==, m_vdev_hdr->get_num_vdevs());
}

void DeviceManager::handle_error(PhysicalDev* pdev) {
    int cnt = pdev->inc_error_cnt();

    /* When cnt reaches MAX_ERROR_CNT we notify only once until
     * we reset the cnt to zero.
     */
    if (cnt != MAX_ERROR_CNT
#ifdef _PRERELEASE
        && !(homestore_flip->test_flip("device_fail", pdev->get_devname()))
#endif
    ) {
        return;
    }

    /* send errors on all vdev in this pdev */
    for (uint32_t i = 0; i < HomeStoreConfig::max_chunks; ++i) {
        if (m_chunk_info[i].pdev_id == pdev->get_dev_id()) {
            auto vdev_id = m_chunk_info[i].vdev_id;
            m_vdev_error_cb(&m_vdev_info[vdev_id]);
        }
    }
}

void DeviceManager::add_chunks(uint32_t vid, chunk_add_callback cb) {
    for (uint32_t dev_id = 0; dev_id < m_pdev_hdr->num_phys_devs; ++dev_id) {
        uint32_t cid = m_pdevs[dev_id]->get_first_chunk_id();
        while (cid != INVALID_CHUNK_ID) {
            HS_ASSERT_NOTNULL(DEBUG, m_chunks[cid].get());
            if (m_chunks[cid]->get_vdev_id() == vid) {
                cb(m_chunks[cid].get());
            }
            cid = m_chunks[cid]->get_next_chunk_id();
        }
    }
}

void DeviceManager::inited() {
    for (uint32_t dev_id = 0; dev_id < m_pdev_hdr->num_phys_devs; ++dev_id) {
        uint32_t cid = m_pdevs[dev_id]->get_first_chunk_id();
        while (cid != INVALID_CHUNK_ID) {
            if (m_chunks[cid]->get_vdev_id() == INVALID_VDEV_ID) {
                cid = m_chunks[cid]->get_next_chunk_id();
                continue;
            }
            HS_ASSERT_NOTNULL(DEBUG, m_chunks[cid]->get_blk_allocator().get());
            m_chunks[cid]->get_blk_allocator()->inited();
            cid = m_chunks[cid]->get_next_chunk_id();
        }
    }
}

/* add constant */
void DeviceManager::add_devices(std::vector< dev_info >& devices, bool is_init) {
    uint64_t max_dev_offset = 0;
    if (is_init) {
        init_devices(devices);
        return;
    }

    load_and_repair_devices(devices);
    return;
}

/* Note: Whosoever is calling this function should take the mutex. We don't allow multiple reads */
void DeviceManager::read_info_blocks(uint32_t dev_id) {
    m_pdevs[dev_id]->read_dm_chunk(m_chunk_memory, m_dm_info_size);

    auto dm = (dm_info*)m_chunk_memory;
    HS_ASSERT_CMP(DEBUG, dm->get_magic(), ==, MAGIC);
#ifndef NO_CHECKSUM
    auto crc = crc16_t10dif(init_crc_16, (const unsigned char*)(m_chunk_memory + DM_PAYLOAD_OFFSET),
                            m_dm_info_size - DM_PAYLOAD_OFFSET);
    HS_ASSERT_CMP(DEBUG, dm->get_checksum(), ==, crc);
#endif

    HS_ASSERT_CMP(DEBUG, m_vdev_hdr->get_magic(), ==, MAGIC);
    HS_ASSERT_CMP(DEBUG, m_chunk_hdr->get_magic(), ==, MAGIC);
    HS_ASSERT_CMP(DEBUG, m_pdev_hdr->get_magic(), ==, MAGIC);

    m_vdev_info = (vdev_info_block*)(m_chunk_memory + m_vdev_hdr->info_offset);
    m_chunk_info = (chunk_info_block*)(m_chunk_memory + m_chunk_hdr->info_offset);
    m_pdev_info = (pdev_info_block*)(m_chunk_memory + m_pdev_hdr->info_offset);
}

/* Note: Whosoever is calling this function should take the mutex. We don't allow multiple writes */
void DeviceManager::write_info_blocks() {
    /* we don't write anything until all the devices are not scanned. Only write that can
     * happen before scanning of device is completed is allocation of chunks.
     */
    if (!m_scan_cmpltd) {
        return;
    }
    m_gen_cnt++;

#ifndef NO_CHECKSUM
    m_dm_info->checksum = crc16_t10dif(init_crc_16, (const unsigned char*)(m_chunk_memory + DM_PAYLOAD_OFFSET),
                                       m_dm_info_size - DM_PAYLOAD_OFFSET);
#endif

    for (uint32_t i = 0; i < m_pdev_hdr->num_phys_devs; i++) {
        m_pdevs[i]->write_dm_chunk(m_gen_cnt, m_chunk_memory, m_dm_info_size);
    }

    HS_ASSERT_CMP(DEBUG, m_vdev_hdr->get_magic(), ==, MAGIC);
    HS_ASSERT_CMP(DEBUG, m_chunk_hdr->get_magic(), ==, MAGIC);
    HS_ASSERT_CMP(DEBUG, m_pdev_hdr->get_magic(), ==, MAGIC);
}

PhysicalDevChunk* DeviceManager::alloc_chunk(PhysicalDev* pdev, uint32_t vdev_id, uint64_t req_size,
                                             uint32_t primary_id) {
    std::lock_guard< decltype(m_dev_mutex) > lock(m_dev_mutex);

    HS_ASSERT_CMP(DEBUG, req_size % HomeStoreConfig::phys_page_size, ==, 0);
    PhysicalDevChunk* chunk = pdev->find_free_chunk(req_size);
    if (chunk == nullptr) {
        std::stringstream ss;
        ss << "No space available for chunk size = " << req_size << " in pdev id = " << pdev->get_dev_id();
        const std::string s = ss.str();
        throw homestore::homestore_exception(s, homestore_error::no_space_avail);
    }
    HS_ASSERT_CMP(DEBUG, chunk->get_size(), >=, req_size);
    chunk->set_vdev_id(vdev_id); // Set the chunk as busy or engaged to a vdev
    chunk->set_primary_chunk_id(primary_id);

    if (chunk->get_size() > req_size) {
        // There is some left over space, create a new chunk and insert it after current chunk
        create_new_chunk(pdev, chunk->get_start_offset() + req_size, chunk->get_size() - req_size, chunk);
        chunk->set_size(req_size);
    }

    write_info_blocks();
    return chunk;
}

void DeviceManager::free_chunk(PhysicalDevChunk* chunk) {
    std::lock_guard< decltype(m_dev_mutex) > lock(m_dev_mutex);
    chunk->set_free();

    PhysicalDev* pdev = chunk->get_physical_dev_mutable();
    auto         freed_ids = pdev->merge_free_chunks(chunk);
    for (auto ids : freed_ids) {
        if (ids != INVALID_CHUNK_ID) {
            remove_chunk(ids);
        }
    }
    write_info_blocks();
}

vdev_info_block* DeviceManager::alloc_vdev(uint32_t req_size, uint32_t nmirrors, uint32_t page_size, uint32_t nchunks,
                                           char* blob, uint64_t size) {
    std::lock_guard< decltype(m_dev_mutex) > lock(m_dev_mutex);

    vdev_info_block* vb = alloc_new_vdev_slot();
    if (vb == nullptr) {
        std::stringstream ss;
        ss << "No free slot available for virtual device creation";
        const std::string s = ss.str();
        throw homestore::homestore_exception(s, homestore_error::no_space_avail);
    }
    vb->size = size;
    vb->num_mirrors = nmirrors;
    vb->page_size = page_size;
    vb->num_primary_chunks = nchunks;
    memcpy(vb->context_data, blob, req_size);

    vb->prev_vdev_id = m_last_vdevid;
    if (m_last_vdevid == INVALID_VDEV_ID) {
        // This is the first vdev being created.
        HS_ASSERT_CMP(DEBUG, m_vdev_hdr->get_first_vdev_id(), ==, INVALID_VDEV_ID);
        m_vdev_hdr->first_vdev_id = vb->vdev_id;
    } else {
        auto prev_vb = &m_vdev_info[m_last_vdevid];
        prev_vb->next_vdev_id = vb->vdev_id;
    }
    m_last_vdevid = vb->vdev_id;
    vb->next_vdev_id = INVALID_VDEV_ID;

    HS_LOG(DEBUG, device, "Creating vdev id = {} size = {}", vb->get_vdev_id(), vb->get_size());
    m_vdev_hdr->num_vdevs++;
    write_info_blocks();
    return vb;
}

void DeviceManager::free_vdev(vdev_info_block* vb) {
    std::lock_guard< decltype(m_dev_mutex) > lock(m_dev_mutex);

    auto prev_vb_id = vb->prev_vdev_id;
    auto next_vb_id = vb->next_vdev_id;

    if (prev_vb_id != INVALID_VDEV_ID) {
        m_vdev_info[prev_vb_id].next_vdev_id = next_vb_id;
    } else {
        m_vdev_hdr->first_vdev_id = vb->next_vdev_id;
    }

    if (next_vb_id != INVALID_VDEV_ID)
        m_vdev_info[next_vb_id].prev_vdev_id = prev_vb_id;
    vb->slot_allocated = false;

    m_vdev_hdr->num_vdevs--;
    write_info_blocks();
}

/* This method creates a new chunk for a given physical device and attaches the chunk to the physical device
 * after previous chunk (if non-null) or last if null */
PhysicalDevChunk* DeviceManager::create_new_chunk(PhysicalDev* pdev, uint64_t start_offset, uint64_t size,
                                                  PhysicalDevChunk* prev_chunk) {
    uint32_t slot;

    // Allocate a slot for the new chunk (which becomes new chunk id) and create a new PhysicalDevChunk instance
    // and attach it to a physical device
    chunk_info_block* c = alloc_new_chunk_slot(&slot);
    if (c == nullptr) {
        std::stringstream ss;
        ss << "No free slot available for chunk creation";
        const std::string s = ss.str();
        throw homestore::homestore_exception(s, homestore_error::no_space_avail);
    }

    auto              chunk = std::make_unique< PhysicalDevChunk >(pdev, slot, start_offset, size, c);
    PhysicalDevChunk* craw = chunk.get();
    pdev->attach_chunk(craw, prev_chunk);

    HS_LOG(DEBUG, device, "Creating chunk: {}", chunk->to_string());
    m_chunks[chunk->get_chunk_id()] = std::move(chunk);
    m_chunk_hdr->num_chunks++;

    return craw;
}

void DeviceManager::remove_chunk(uint32_t chunk_id) {
    HS_ASSERT_CMP(DEBUG, m_chunk_info[chunk_id].is_slot_allocated(), ==, true);
    m_chunk_info[chunk_id].slot_allocated = false; // Free up the slot for future allocations
    m_chunk_hdr->num_chunks--;
}

chunk_info_block* DeviceManager::alloc_new_chunk_slot(uint32_t* pslot_num) {
    uint32_t start_slot = m_chunk_hdr->num_chunks;
    uint32_t cur_slot = start_slot;
    do {
        if (!m_chunk_info[cur_slot].slot_allocated) {
            m_chunk_info[cur_slot].slot_allocated = true;
            *pslot_num = cur_slot;
            return &m_chunk_info[cur_slot];
        }
        cur_slot++;
        if (cur_slot == HomeStoreConfig::max_chunks)
            cur_slot = 0;
    } while (cur_slot != start_slot);

    return nullptr;
}

vdev_info_block* DeviceManager::alloc_new_vdev_slot() {

    vdev_info_block* vb = &m_vdev_info[0];
    for (uint32_t id = 0; id < HomeStoreConfig::max_vdevs; id++) {
        vdev_info_block* vb = &m_vdev_info[id];

        if (!vb->slot_allocated) {
            vb->slot_allocated = true;
            vb->vdev_id = id;
            return vb;
        }
    }

    return nullptr;
}

} // namespace homestore
