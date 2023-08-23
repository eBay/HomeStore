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

#include <isa-l/crc.h>
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

    uint64_t vdev_size{0};                     // 0: Size of the vdev
    uint32_t vdev_id{0};                       // 8: Id for this vdev. It is unique per homestore instance
    uint32_t num_mirrors{0};                   // 12: Total number of mirrors
    uint32_t blk_size{0};                      // 16: IO block size for this vdev
    uint32_t num_primary_chunks{0};            // 20: number of primary chunks
    uint8_t slot_allocated{0};                 // 24: Is this current slot allocated
    uint8_t failed{0};                         // 25: set to true if disk is replaced
    uint8_t hs_dev_type{0};                    // 26: PDev dev type (as in fast or data)
    uint8_t multi_pdev_choice{0};              // 27: Choice when multiple pdevs are present (vdev_multi_pdev_opts_t)
    char name[64];                             // 28: Name of the vdev
    uint16_t checksum{0};                      // 92: Checksum of this entire Block
    uint8_t alloc_type;                        // 94: Allocator type of this vdev
    uint8_t padding[162]{};                    // 95: Pad to make it 256 bytes total
    uint8_t user_private[user_private_size]{}; // 128: User specific information

    uint32_t get_vdev_id() const { return vdev_id; }
    uint64_t get_size() const { return vdev_size; }

    void set_name(const std::string& n) { std::strncpy(charptr_cast(name), n.c_str(), 63); }
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
        std::memcpy(&user_private, data.bytes, std::min(data.size, uint32_cast(user_private_size)));
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

struct vdev_parameters {
    std::string vdev_name;                  // Name of the vdev
    uint64_t vdev_size;                     // Current Vdev size.
    uint32_t num_chunks;                    // Total number of primary chunks.
                                            // NOTE: If pdev opts is ALL_PDEV_STRIPED, then num_chunks would round off
                                            // to number of pdevs evenly
    uint32_t blk_size;                      // Block size vdev operates on
    HSDevType dev_type;                     // Which physical device type this vdev belongs to (FAST or DATA)
    blk_allocator_type_t alloc_type;        // which allocator type this vdev wants to be with;
    vdev_multi_pdev_opts_t multi_pdev_opts; // How data to be placed on multiple vdevs
    sisl::blob context_data;                // Context data about this vdev
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

    sisl::sparse_vector< std::unique_ptr< PhysicalDev > > m_all_pdevs;
    std::map< HSDevType, std::vector< PhysicalDev* > > m_pdevs_by_type;
    uint32_t m_cur_pdev_id{0};

    sisl::sparse_vector< shared< Chunk > > m_chunks;                // Chunks organized as array (indexed on chunk id)
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
    void load_devices();
    void close_devices();

    /// @brief Create a VirtualDev based on input parameters
    /// @param vdev_param Parameters defining all the essential inputs to create virtual device
    /// @param event_cb Event handler in case of
    /// @return
    shared< VirtualDev > create_vdev(vdev_parameters&& vdev_param);

    const Chunk* get_chunk(uint32_t chunk_id) const {
        return (chunk_id == INVALID_CHUNK_ID) ? nullptr : m_chunks[chunk_id].get();
    }

    Chunk* get_chunk_mutable(uint32_t chunk_id) {
        return (chunk_id == INVALID_CHUNK_ID) ? nullptr : m_chunks[chunk_id].get();
    }

    uint32_t atomic_page_size(HSDevType dtype) const;
    uint32_t optimal_page_size(HSDevType dtype) const;

    std::vector< PhysicalDev* > get_pdevs_by_dev_type(HSDevType dtype) const;
    std::vector< shared< VirtualDev > > get_vdevs() const;

    uint64_t total_capacity() const;
    uint64_t total_capacity(HSDevType dtype) const;

private:
    void load_vdevs();
    int device_open_flags(const std::string& devname) const;

    std::vector< vdev_info > read_vdev_infos(const std::vector< PhysicalDev* >& pdevs);
    uint32_t populate_pdev_info(const dev_info& dinfo, const iomgr::drive_attributes& attr, const uuid_t& uuid,
                                pdev_info_header& pinfo);

    const std::vector< PhysicalDev* >& pdevs_by_type_internal(HSDevType dtype) const;
}; // class DeviceManager

} // namespace homestore
