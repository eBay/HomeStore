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
#include "device/physical_dev.hpp"

namespace homestore {
class BlkAllocator;

class Chunk {
private:
    std::mutex m_mgmt_mutex;
    chunk_info m_chunk_info;
    PhysicalDev* const m_pdev;
    const uint32_t m_chunk_slot;
    const uint32_t m_stream_id;
    uint32_t m_vdev_ordinal{0};
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
    uint64_t end_of_chunk() const { return m_chunk_info.end_of_chunk_size; }
    uint32_t pdev_ordinal() const { return m_chunk_info.chunk_ordinal; }
    uint8_t* user_private() { return &m_chunk_info.user_private[0]; }
    uint32_t stream_id() const { return m_stream_id; }
    uint32_t slot_number() const { return m_chunk_slot; }
    uint32_t vdev_ordinal() const { return m_vdev_ordinal; }

    std::string to_string() const;
    nlohmann::json get_status([[maybe_unused]] int log_level) const;
    const BlkAllocator* blk_allocator() const { return m_blk_allocator.get(); }
    BlkAllocator* blk_allocator_mutable() { return m_blk_allocator.get(); }

    ////////////// Setters /////////////////////
    void update_end_of_chunk(uint64_t end_offset);
    void set_user_private(const sisl::blob& data);
    void set_block_allocator(cshared< BlkAllocator >& blkalloc) { m_blk_allocator = blkalloc; }
    void set_vdev_ordinal(uint32_t vdev_ordinal) { m_vdev_ordinal = vdev_ordinal; }

private:
    void write_chunk_info();
};
} // namespace homestore
