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

#include <iomgr/iomgr.hpp>
#include <sisl/fds/sparse_vector.hpp>
#include <homestore/homestore_decl.hpp>
#include "new_device/hs_super_blk.h"

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
    static constexpr size_t user_private_size = 128;

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
    uint16_t checksum{0};                      // 94: Checksum of this entire block
    uint8_t padding[32]{};                     // 96: Pad to make it 256 bytes total
    uint8_t user_private[user_private_size]{}; // 128: User specific information

    uint32_t get_vdev_id() const { return vdev_id; }
    uint64_t get_size() const { return vdev_size; }

    void set_name(const std::string& n) { std::strncpy(charptr_cast(name), n.c_str(), 64); }
    std::string get_name() const { return std::string{c_charptr_cast(name)}; }

    void set_allocated() { slot_allocated = s_cast< uint8_t >(0x01); };
    void set_free() { slot_allocated = s_cast< uint8_t >(0x00); }
    bool is_allocated() const { return (slot_allocated == 0x01); }

    void mark_failed() { failed = s_cast< uint8_t >(0x01); }
    void unfail() { failed = s_cast< uint8_t >(0x00); }
    bool is_failed() const { return (failed == 0x01); }

    void set_dev_type(HSDevType dtype) { hs_dev_type = enum_value(dtype); }
    void set_pdev_choice(vdev_multi_pdev_opts_t opts) { multi_pdev_choice = enum_value(opts); }

    void set_user_private(const uint8_t* private_data) { std::memcpy(&user_private, private_data, user_private_size); }
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
    vdev_multi_pdev_opts_t multi_pdev_opts; // How data to be placed on multiple vdevs
    uint8_t context_data[vdev_info::user_private_size]; // Context data about this vdev
};

ENUM(chunk_selector_t, uint8_t, // What are the options to select chunk to allocate a block
     ROUND_ROBIN,               // Pick round robin
     RANDOM,                    // Pick any chunk in uniformly random fashion
     MOST_AVAILABLE_SPACE,      // Pick the most available space
     ALWAYS_CALLER_CONTROLLED   // Expect the caller to always provide the specific chunkid
);

ENUM(vdev_event_t, uint8_t, SIZE_THRESHOLD_REACHED, VDEV_ERRORED_OUT);

class VirtualDev;
class PhysicalDev;
class Chunk;

class DeviceManager {
    using new_vdev_cb_t = std::function< shared< VirtualDev >(DeviceManager&, const vdev_info&) >;
    using vdev_event_cb_t = std::function< void(VirtualDev&, vdev_event_t, const std::string&) >;

private:
    std::vector< dev_info > m_dev_infos;
    int m_hdd_open_flags;
    int m_ssd_open_flags;
    first_block_header m_first_blk_hdr;

    sisl::sparse_vector< std::unique_ptr< PhysicalDev > > m_all_pdevs;
    std::map< HSDevType, std::vector< PhysicalDev* > > m_pdevs_by_type;
    uint32_t m_cur_pdev_id{0};

    sisl::sparse_vector< std::unique_ptr< Chunk > > m_chunks;       // Chunks organized as array (indexed on chunk id)
    sisl::Bitset m_chunk_id_bm{hs_super_blk::MAX_CHUNKS_IN_SYSTEM}; // Bitmap to keep track of chunk ids available

    std::mutex m_vdev_mutex;                                        // Create/Remove operation of vdev synchronization
    sisl::sparse_vector< shared< VirtualDev > > m_vdevs;            // VDevs organized in array for quick lookup
    sisl::Bitset m_vdev_id_bm{hs_super_blk::MAX_VDEVS_IN_SYSTEM};   // Bitmap to keep track of vdev ids available
    new_vdev_cb_t m_new_vdev_cb;

    // std::unique_ptr< ChunkManager > m_chunk_mgr;

public:
    DeviceManager(const std::vector< dev_info >& devs, new_vdev_cb_t new_vdev_cb);

    DeviceManager(const DeviceManager& other) = delete;
    DeviceManager& operator=(const DeviceManager& other) = delete;
    DeviceManager(DeviceManager&&) noexcept = delete;
    DeviceManager& operator=(DeviceManager&&) noexcept = delete;
    ~DeviceManager() = default;

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

    std::vector< PhysicalDev* > get_pdevs_by_dev_type(HSDevType dtype) const;
    std::vector< shared< VirtualDev > > get_vdevs() const;

private:
    void format_devices();
    void load_devices();
    void load_vdevs();
    int device_open_flags(const std::string& devname) const;

    std::vector< vdev_info > read_vdev_infos(const std::vector< PhysicalDev* >& pdevs);
    void populate_pdev_info(const dev_info& dinfo, const iomgr::drive_attributes& attr, pdev_info_header& pinfo);

}; // class DeviceManager

} // namespace homestore