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
#pragma once

#define BOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX 1

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <iomgr/iomgr.hpp>
#include <sisl/logging/logging.h>
#include <sisl/fds/sparse_vector.hpp>
#include <sisl/fds/utils.hpp>

#include <homestore/homestore_decl.hpp>

using namespace iomgr;
SISL_LOGGING_DECL(device, DEVICE_MANAGER)

namespace homestore {
// forward declarations
class BlkAllocator;
struct blkalloc_cp;
struct dm_info;
struct pdevs_block;
struct chunks_block;
struct vdevs_block;
struct pdev_info_block;
struct chunk_info_block;
struct vdev_info_block;
class VirtualDev;
class PhysicalDevChunk;
class PhysicalDev;
struct meta_blk;

class DeviceManager {
    // forward declarations
    struct dm_derived_type;

    // typedef's
    typedef std::function< void(DeviceManager*, vdev_info_block*) > NewVDevCallback;
    typedef std::function< void(PhysicalDevChunk*) > chunk_add_callback;
    typedef std::function< void(vdev_info_block*) > vdev_error_callback;

    // friend classes
    friend class PhysicalDev;
    friend class PhysicalDevChunk;

public:
    DeviceManager(const std::vector< dev_info >& data_devices, NewVDevCallback vcb, uint32_t vdev_metadata_size,
                  vdev_error_callback vdev_error_cb);

    DeviceManager(const DeviceManager& other) = delete;
    DeviceManager& operator=(const DeviceManager& other) = delete;
    DeviceManager(DeviceManager&&) noexcept = delete;
    DeviceManager& operator=(DeviceManager&&) noexcept = delete;
    ~DeviceManager();

    /**
     * @brief : Initial routine to call upon bootup or everytime new physical devices to be added dynamically
     * @param devices
     *
     * @return :
     *  true if it is first time boot, meaning there is no valid sb on device
     *  false if it is recovery reboot, meaning there is valid sb found on device
     */
    bool init();
    size_t total_cap() const;
    size_t total_cap(PhysicalDevGroup pdev_group) const;
    uint32_t phys_page_size(PhysicalDevGroup pdev_group) const;
    uint32_t atomic_page_size(PhysicalDevGroup pdev_group) const;
    void handle_error(PhysicalDev* pdev);

    /* This is not very efficient implementation of get_all_devices(), however, this is expected to be called during
     * the start of the devices and for that purpose its efficient enough */
    // TO DO: Possibly make two functions or return std::pair if not sufficient
    std::vector< PhysicalDev* > get_all_devices() const {
        std::vector< PhysicalDev* > vec;
        {
            std::lock_guard< decltype(m_dev_mutex) > lock{m_dev_mutex};
            vec.reserve(m_data_pdevs.size());
            for (auto& pdev : m_data_pdevs) {
                if (pdev) { vec.push_back(pdev.get()); }
            }
        }
        return vec;
    }

    /* Allocate a chunk for required size on the given physical dev and associate the chunk to provide virtual device.
     * Returns the allocated PhysicalDevChunk */
    PhysicalDevChunk* alloc_chunk(PhysicalDev* pdev, uint32_t vdev_id, uint64_t req_size, uint32_t primary_id);

    /* Free the chunk for later user */
    void free_chunk(PhysicalDevChunk* chunk);

    /* Allocate a new vdev for required size */
    vdev_info_block* alloc_vdev(uint32_t req_size, uint32_t nmirrors, uint32_t blk_size, uint32_t nchunks, char* blob,
                                uint64_t size);

    /* Free up the vdev_id */
    void free_vdev(vdev_info_block* vb);

    /* Given an ID, get the chunk */
    const PhysicalDevChunk* get_chunk(uint32_t chunk_id) const;
    PhysicalDevChunk* get_chunk_mutable(uint32_t chunk_id);
    PhysicalDev* get_pdev(uint32_t pdev_id);

    dm_derived_type& get_dm_derived() { return m_data_dm_derived; }
    const dm_derived_type& get_dm_derived_const() const { return m_data_dm_derived; }

    void add_chunks(uint32_t vid, const chunk_add_callback& cb);
    void inited();
    void write_info_blocks();
    void update_vb_context(uint32_t vdev_id, const sisl::blob& ctx_data);
    void get_vb_context(uint32_t vdev_id, const sisl::blob& ctx_data) const;
    void update_end_of_chunk(PhysicalDevChunk* chunk, off_t offset);
    void update_chunk_user_data(PhysicalDevChunk* chunk, uint8_t* user_data, uint8_t user_data_size);
    void init_done();
    void close_devices();
    bool is_first_time_boot() const { return m_first_time_boot; }
    std::vector< PhysicalDev* > get_devices(PhysicalDevGroup pdev_group) const;
    // void zero_pdev_sbs();

    bool is_hdd(const std::string& devname) const;
    uint32_t num_sys_chunks() const;
    void incr_num_sys_chunks();

public:
    static void zero_boot_sbs(const std::vector< dev_info >& devices);
    static iomgr::drive_type get_drive_type(const std::vector< dev_info >& devices);
    static bool is_hdd_direct_io_mode();

private:
    void load_and_repair_devices(const hs_uuid_t& system_uuid);
    void init_devices();
    void read_info_blocks(uint32_t dev_id);

    auto& get_last_vdev_id() { return m_last_data_vdev_id; }
    uint8_t* get_chunk_memory() { return m_data_chunk_memory; }
    auto& get_gen_count() { return m_data_gen_cnt; }

    chunk_info_block* alloc_new_chunk_slot(uint32_t* pslot_num);
    vdev_info_block* alloc_new_vdev_slot();

    PhysicalDevChunk* create_new_chunk(PhysicalDev* pdev, uint64_t start_offset, uint64_t size,
                                       PhysicalDevChunk* prev_chunk);
    void remove_chunk(uint32_t chunk_id);
    void blk_alloc_meta_blk_found_cb(meta_blk* mblk, sisl::byte_view buf, size_t size);
    uint32_t get_common_phys_page_sz() const;
    uint32_t get_common_align_sz() const;
    int get_device_open_flags(const std::string& devname) const;

    static int get_open_flags(io_flag oflags);

private:
    int m_hdd_open_flags;
    int m_ssd_open_flags;
    NewVDevCallback m_new_vdev_cb;
    std::atomic< uint64_t > m_data_gen_cnt{0};
    uint8_t* m_data_chunk_memory{nullptr};
    const std::vector< dev_info > m_data_devices;

    /* This memory is carved out of chunk memory. Any changes in any of the block should end up writing all the
     * blocks on disk.
     */
    uint64_t m_data_dm_info_size{0};
    typedef struct dm_derived_type {
        uint64_t info_size{0};
        dm_info* info{nullptr};
        pdevs_block* pdev_hdr{nullptr};
        chunks_block* chunk_hdr{nullptr};
        vdevs_block* vdev_hdr{nullptr};
        pdev_info_block* pdev_info{nullptr};
        chunk_info_block* chunk_info{nullptr};
        vdev_info_block* vdev_info{nullptr};
    } dm_derived_type;
    dm_derived_type m_data_dm_derived;

    mutable std::mutex m_dev_mutex;

    sisl::sparse_vector< std::unique_ptr< PhysicalDev > > m_data_pdevs;
    sisl::sparse_vector< std::unique_ptr< PhysicalDevChunk > > m_data_chunks;
    sisl::sparse_vector< VirtualDev* > m_vdevs;
    uint32_t m_last_data_vdev_id{INVALID_VDEV_ID};
    uint32_t m_vdev_metadata_size; // Appln metadata size for vdev
    uint32_t m_pdev_id{0};
    uint32_t m_last_data_pdev_id{0}; // pdev_id's above this value are fast pdevs
    bool m_scan_cmpltd{false};
    vdev_error_callback m_vdev_error_cb;
    bool m_first_time_boot{true};
    hs_uuid_t m_data_system_uuid{INVALID_SYSTEM_UUID};
    uint32_t m_num_sys_chunks{0};
}; // class DeviceManager

} // namespace homestore
