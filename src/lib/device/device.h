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
#pragma once

#include <map>
#include <vector>

#include <homestore/crc.h>
#include <iomgr/iomgr.hpp>
#include <sisl/fds/sparse_vector.hpp>
#include <homestore/homestore_decl.hpp>
#include "device/hs_super_blk.h"

namespace homestore {

VENUM(vdev_multi_pdev_opts_t, uint8_t, // Indicates the style of vdev when multiple pdevs are available
      ALL_PDEV_STRIPED = 0,            // vdev data is striped across all pdevs
      ALL_PDEV_MIRRORED = 1,           // vdev data is mirrored on all pdevs
      SINGLE_FIRST_PDEV = 2,           // vdev data is placed only on the first pdev
      SINGLE_ANY_PDEV = 3,             // vdev data is placed on only 1 pdev, but any of the pdev
);

#pragma pack(1)
struct vdev_info {
    static constexpr size_t size = 512;
    static constexpr size_t user_private_size = 256;
    static constexpr size_t max_name_len = 64;

    uint64_t vdev_size{0};                     // 0: Size of the vdev
    uint32_t vdev_id{0};                       // 8: Id for this vdev. It is unique per homestore instance
    uint32_t num_mirrors{0};                   // 12: Total number of mirrors
    uint32_t blk_size{0};                      // 16: IO block size for this vdev
    uint32_t num_primary_chunks{0};            // 20: number of primary chunks
    uint32_t chunk_size{0};                    // 24: chunk size used in vdev.
    vdev_size_type_t size_type{};              // 28: Whether its a static or dynamic type.
    uint8_t slot_allocated{0};                 // 29: Is this current slot allocated
    uint8_t failed{0};                         // 30: set to true if disk is replaced
    uint8_t hs_dev_type{0};                    // 31: PDev dev type (as in fast or data)
    uint8_t multi_pdev_choice{0};              // 32: Choice when multiple pdevs are present (vdev_multi_pdev_opts_t)
    char name[max_name_len];                   // 33: Name of the vdev
    uint16_t checksum{0};                      // 97: Checksum of this entire Block
    uint8_t alloc_type;                        // 98: Allocator type of this vdev
    uint8_t chunk_sel_type;                    // 99: Chunk Selector type of this vdev_id
    uint8_t use_slab_allocator{0};             // 100: Use slab allocator for this vdev
    uint8_t padding[154]{};                    // 101: Padding to make it 256 bytes
    uint8_t user_private[user_private_size]{}; // 128: User sepcific information

    uint32_t get_vdev_id() const { return vdev_id; }
    uint64_t get_size() const { return vdev_size; }

    void set_name(const std::string& n) {
        std::strncpy(charptr_cast(name), n.c_str(), max_name_len - 1);
        name[max_name_len - 1] = '\0';
    }
    std::string get_name() const { return std::string{c_charptr_cast(name)}; }

    void set_allocated() { slot_allocated = s_cast< uint8_t >(0x01); };
    void set_free() { slot_allocated = s_cast< uint8_t >(0x00); }
    bool is_allocated() const { return (slot_allocated == 0x01); }

    void mark_failed() { failed = s_cast< uint8_t >(0x01); }
    void unfail() { failed = s_cast< uint8_t >(0x00); }
    bool is_failed() const { return (failed == 0x01); }

    void set_dev_type(HSDevType dtype) { hs_dev_type = enum_value(dtype); }
    void set_pdev_choice(vdev_multi_pdev_opts_t opts) { multi_pdev_choice = enum_value(opts); }

    void set_user_private(const sisl::blob& data) {
        std::memcpy(&user_private, data.cbytes(), std::min(data.size(), uint32_cast(user_private_size)));
    }
    uint8_t* get_user_private_mutable() { return &(user_private[0]); }
    const uint8_t* get_user_private() const { return &(user_private[0]); }

    void compute_checksum() {
        checksum = 0;
        checksum = crc16_t10dif(hs_init_crc_16, r_cast< const unsigned char* >(this), sizeof(vdev_info));
    }
};
#pragma pack()

static_assert(sizeof(vdev_info) <= vdev_info::size, "VDev info sizeof() mismatch");

ENUM(chunk_selector_t, uint8_t, // What are the options to select chunk to allocate a block
     ROUND_ROBIN,               // Pick round robin
     RANDOM,                    // Pick any chunk in uniformly random fashion
     MOST_AVAILABLE_SPACE,      // Pick the most available space
     ALWAYS_CALLER_CONTROLLED   // Expect the caller to always provide the specific chunkid
);

struct vdev_parameters {
    std::string vdev_name;                  // Name of the vdev
    vdev_size_type_t size_type{};           // Wether size is static or dynamic.
    uint64_t vdev_size;                     // Current Vdev size.
    uint32_t num_chunks{};                  // Total number of primary chunks.
                                            // NOTE: If pdev opts is ALL_PDEV_STRIPED, then num_chunks would round off
                                            // to number of pdevs evenly
    uint32_t blk_size;                      // Block size vdev operates on
    uint32_t chunk_size{};                  // Chunk size provided for dynamic vdev.
    HSDevType dev_type;                     // Which physical device type this vdev belongs to (FAST or DATA)
    blk_allocator_type_t alloc_type;        // which allocator type this vdev wants to be with;
    chunk_selector_type_t chunk_sel_type;   // which chunk selector type this vdev wants to be with;
    vdev_multi_pdev_opts_t multi_pdev_opts; // How data to be placed on multiple vdevs
    sisl::blob context_data;                // Context data about this vdev
    bool use_slab_allocator{false};         // Use slab allocator for this vdev
};

class VirtualDev;
class PhysicalDev;
class Chunk;

class DeviceManager {
    using vdev_create_cb_t = std::function< shared< VirtualDev >(const vdev_info&, bool) >;

private:
    std::vector< dev_info > m_dev_infos;
    int m_hdd_open_flags;
    int m_ssd_open_flags;
    first_block_header m_first_blk_hdr;
    bool m_first_time_boot{false};
    bool m_boot_in_degraded_mode{false};

    sisl::sparse_vector< std::unique_ptr< PhysicalDev > > m_all_pdevs;
    std::map< HSDevType, std::vector< PhysicalDev* > > m_pdevs_by_type;
    uint32_t m_cur_pdev_id{0}; // This is a monotonically increasing value. In case of disk replacement, this value is
                               // not inherited, new device will get a new id.

    std::map< uint16_t, shared< Chunk > > m_chunks;                 // Chunks organized as array (indexed on chunk id)
    sisl::Bitset m_chunk_id_bm{hs_super_blk::MAX_CHUNKS_IN_SYSTEM}; // Bitmap to keep track of chunk ids available

    std::mutex m_vdev_mutex;                                      // Create/Remove operation of vdev synchronization
    sisl::sparse_vector< shared< VirtualDev > > m_vdevs;          // VDevs organized in array for quick lookup
    sisl::Bitset m_vdev_id_bm{hs_super_blk::MAX_VDEVS_IN_SYSTEM}; // Bitmap to keep track of vdev ids available
    vdev_create_cb_t m_vdev_create_cb;
    // std::unique_ptr< ChunkManager > m_chunk_mgr;

public:
    DeviceManager(const std::vector< dev_info >& devs, vdev_create_cb_t vdev_create_cb);

    DeviceManager(const DeviceManager& other) = delete;
    DeviceManager& operator=(const DeviceManager& other) = delete;
    DeviceManager(DeviceManager&&) noexcept = delete;
    DeviceManager& operator=(DeviceManager&&) noexcept = delete;
    ~DeviceManager() = default;

    bool is_first_time_boot() const { return m_first_time_boot; }
    void format_devices();
    uint32_t format_single_device(dev_info& dinfo);
    void commit_formatting();
    void load_devices();
    void close_devices();
    bool is_boot_in_degraded_mode() const { return m_boot_in_degraded_mode; }

    /// @brief Create a VirtualDev based on input parameters
    /// @param vdev_param Parameters defining all the essential inputs to create virtual device
    /// @param event_cb Event handler in case of
    /// @return
    shared< VirtualDev > create_vdev(vdev_parameters&& vdev_param);
    void compose_vparam(uint64_t vdev_id, vdev_parameters& vparam, std::vector< PhysicalDev* > pdevs);
    std::map< PhysicalDev*, uint32_t > calculate_vdev_chunk_num_on_new_pdevs(shared< VirtualDev > vdev,
                                                                             std::vector< PhysicalDev* > pdevs,
                                                                             uint64_t total_chunk_num);
    void add_pdev_to_vdev(shared< VirtualDev > vdev, PhysicalDev* pdev, uint32_t total_chunk_num_in_pdev);
    const Chunk* get_chunk(uint16_t chunk_id) { return get_chunk_mutable(chunk_id); }

    Chunk* get_chunk_mutable(uint16_t chunk_id) {
        std::unique_lock lg{m_vdev_mutex};
        // if a pdev is misssing when restart, chunk_id from client might be larger than m_chunks.size()
        if (!m_chunks.contains(chunk_id)) return nullptr;
        return m_chunks[chunk_id].get();
    }

    uint32_t atomic_page_size(HSDevType dtype) const;
    uint32_t optimal_page_size(HSDevType dtype) const;
    uint32_t align_size(HSDevType dtype) const;

    std::vector< PhysicalDev* > get_pdevs_by_dev_type(HSDevType dtype) const;
    std::vector< shared< VirtualDev > > get_vdevs() const;
    std::vector< shared< Chunk > > get_chunks() const;

    uint64_t total_capacity() const;
    uint64_t total_capacity(HSDevType dtype) const;

    shared< Chunk > create_chunk(HSDevType dev_type, uint32_t vdev_id, uint64_t chunk_size, const sisl::blob& data);
    void remove_chunk(shared< Chunk > chunk);
    void remove_chunk_locked(shared< Chunk > chunk);

private:
    void load_vdevs();
    int device_open_flags(const std::string& devname) const;

    std::vector< vdev_info > read_vdev_infos(const std::vector< PhysicalDev* >& pdevs);
    uint32_t populate_pdev_info(const dev_info& dinfo, const iomgr::drive_attributes& attr, const uuid_t& uuid,
                                pdev_info_header& pinfo);

    const std::vector< PhysicalDev* >& pdevs_by_type_internal(HSDevType dtype) const;
}; // class DeviceManager

// Chunk pool is used to get chunks when there is no space
// and its cheaper compared to create a chunk on the fly.
// Creating chunk on the fly causes sync write.
class ChunkPool {
public:
    struct Params {
        uint64_t pool_capacity;
        // Private data used when creating chunks.
        std::function< sisl::blob() > init_private_data_cb;
        uint8_t hs_dev_type;
        uint32_t vdev_id;
        uint64_t chunk_size;
    };

    ChunkPool(DeviceManager& dmgr, Params&& param);
    ~ChunkPool();

    // Start the chunk pool.
    void start();

    // Add chunk to the pool. If the queue is full,
    // chunk removed from the system. Returns if
    // if we could reuse chunk by adding back to pool.
    bool enqueue(shared< Chunk >& chunk);

    // Get a chunk from the pool.
    shared< Chunk > dequeue();

    // Returns the capacity of the chunk pool.
    uint64_t capacity() { return m_params.pool_capacity; }
    uint64_t size() { return m_pool.size(); }

private:
    // Producer thread.
    void producer();

private:
    DeviceManager& m_dmgr;
    Params m_params;
    std::list< shared< Chunk > > m_pool;
    uint32_t m_pool_capacity;
    std::condition_variable m_pool_cv;
    std::mutex m_pool_mutex;
    std::thread m_producer_thread;
    bool m_run_pool{false};
    folly::Promise< folly::Unit > m_pool_halt;
};

} // namespace homestore
