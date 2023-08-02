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
#include "new_device/physical_dev.hpp"

// Header to the chunk super blk. The format of the chunk super block is
//  ________________________________________________________________________________________
//  | H |                    | H |                        |     | H |                      |
//  | D | chunk_info[1 to M] | D | chunk_info[M+1 to M*2] | ... | D | chunk_info[N-M to N] |
//  |_R_|____________________|_R_|________________________|_____|_R_|______________________|
//
//
//  where:
//    M = max number of chunk_info we can fit in atomic page. Typically (4096 - 64)/72
//    N = max number of chunks homestore supported
//

namespace homestore {
#if 0
#pragma pack(1)
static constexpr uint32_t CHUNK_INFO_BLOCK_MAGIC = 0xDABAF00D;
static constexpr uint32_t CHUNK_INFO_BLOCK_VERSION = 1;

struct chunk_info_block {
    uint32_t magic{0};               // Header magic expected to be at the top of block
    uint32_t version{0};             // Version of this structure
    uint32_t checksum{0};            // Checksum for this block
    uint32_t num_chunks_in_block{0}; // Total number of alloced chunks in this block
    uint8_t pad[48]{0};              // Pad to make it 64 bytes

    uint64_t get_magic() const { return magic; }

    // Followed by array of chunk_info
};
#pragma pack()

#pragma pack(1)
struct chunk_info {
    uint64_t chunk_start_offset{0};  // Start offset of the chunk within a pdev
    uint64_t chunk_size{0};          // Chunk size
    uint32_t pdev_id{0};             // Physical device id this chunk is hosted on
    uint32_t vdev_id{0};             // Virtual device id this chunk hosts. UINT32_MAX if chunk is free
    int64_t end_of_chunk_size{0};    // The offset indicates end of chunk. off_t is ambiguous size
    uint32_t chunk_id{0};            // ID for this chunk
    uint8_t chunk_allocated{0x00};   // Is chunk allocated or free
    uint8_t pad[19]{};               // pad to make it 72 bytes total
    uint8_t user_specifc_info[16]{}; // Opaque user of the chunk information

    uint64_t get_chunk_size() const { return chunk_size; }
    uint32_t get_chunk_id() const { return chunk_id; }
    bool is_allocated() const { return (chunk_allocated != 0x00); }
    void set_allocated() { chunk_allocated = 0x01; }

    void update_start_offset(uint64_t offset) {
        HS_REL_ASSERT_GE(offset, chunk_start_offset);
        chunk_size -= (offset - chunk_start_offset);
        HS_REL_ASSERT_GT(chunk_size, 0);
        chunk_start_offset = offset;
    }
};
#pragma pack()

using IntervalSet = boost::icl::split_interval_set< uint64_t >;
using ChunkInterval = IntervalSet::interval_type;

class DeviceManager;
class PhysicalDev;
class Chunk;

class ChunkManager {
private:
    DeviceManager& m_dmgr;

    uint32_t m_num_chunks{0};
    uint32_t m_chunk_block_size{0};
    uint32_t m_chunks_per_block{0};
    uint32_t m_chunk_sb_size{0};
    uint8_t* m_chunk_sb;

    std::shared_mutex m_mtx;                                  // Shared mutex to protect chunk creation

    sisl::Bitset m_chunk_id_bm;                               // Bitmap to keep track of chunk ids available
    sisl::sparse_vector< std::unique_ptr< Chunk > > m_chunks; // Chunks organized as array (indexed on chunk id)
    std::map< const PhysicalDev*, std::vector< Chunk* > > m_chunks_in_pdev; // Chunks organized per physical device
    std::map< const PhysicalDev*, IntervalSet > > m_chunk_slots_map; // Chunks within each pdev organized as intervals
    std::map< uint64_t, std::vector< Chunk* > > m_chunks_in_vdev;    // Chunks organized per virtual device

public:
    ChunkManager(DeviceManager& dmgr, bool format, uint64_t chunk_sb_offset);

    const Chunk& create_chunk(PhysicalDev& pdev, uint32_t vdev_id, uint64_t size);
    void free_chunk(uint32_t chunk_id);
    const Chunk& get_chunk(uint32_t chunk_id) const;
    Chunk& get_chunk_mutable(uint32_t chunk_id);

    static uint32_t chunk_super_block_size(uint32_t atomic_page_size);
    uint32_t num_chunks() const { return m_num_chunks; }
};
#endif

class BlkAllocator;

class Chunk {
private:
    chunk_info m_chunk_info;
    PhysicalDev* const m_pdev;
    const uint32_t m_chunk_slot;
    const uint32_t m_stream_id;
    shared< BlkAllocator > m_blk_allocator;

public:
    friend class DeviceManager;

    Chunk(PhysicalDev* pdev, const chunk_info& cinfo, uint32_t chunk_slot);
    Chunk(const Chunk&) = delete;
    Chunk(Chunk&&) noexcept = delete;
    Chunk& operator=(const Chunk&) = delete;
    Chunk& operator=(Chunk&&) noexcept = delete;
    virtual ~Chunk() = default;

    void cp_flush();

    /////////////// Pointer Getters ////////////////////
    const PhysicalDev* physical_dev() const { return m_pdev; }
    PhysicalDev* physical_dev_mutable() { return m_pdev; };
    const chunk_info& info() const { return m_chunk_info; }

    /////////////// Getters ////////////////////
    uint64_t start_offset() const { return m_chunk_info.chunk_start_offset; }
    uint64_t size() const { return m_chunk_info.chunk_size; }
    bool is_busy() const { return m_chunk_info.is_allocated(); }
    uint32_t vdev_id() const { return m_chunk_info.vdev_id; }
    uint16_t chunk_id() const { return static_cast< uint16_t >(m_chunk_info.chunk_id); }
    off_t end_of_chunk() const { return s_cast< off_t >(m_chunk_info.end_of_chunk_size); }
    uint32_t ordinal() const { return m_chunk_info.chunk_ordinal; }
    uint8_t* user_private() { return &m_chunk_info.user_private[0]; }
    uint32_t stream_id() const { return m_stream_id; }
    uint32_t slot_number() const { return m_chunk_slot; }

    std::string to_string() const;
    nlohmann::json get_status([[maybe_unused]] int log_level) const;
    const BlkAllocator* blk_allocator() const { return m_blk_allocator.get(); }
    BlkAllocator* blk_allocator_mutable() { return m_blk_allocator.get(); }

    ////////////// Setters /////////////////////
    void set_user_private(uint8_t* private_data) { m_chunk_info.set_user_private(private_data); }
    void set_block_allocator(cshared< BlkAllocator >& blkalloc) { m_blk_allocator = blkalloc; }
};
} // namespace homestore