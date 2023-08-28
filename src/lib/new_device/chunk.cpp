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
#include "new_device/chunk.h"
#include "new_device/new_device.h"
#include "new_device/physical_dev.hpp"

namespace homestore {
Chunk::Chunk(PhysicalDev* pdev, const chunk_info& cinfo, uint32_t chunk_slot) :
        m_chunk_info{cinfo}, m_pdev{pdev}, m_chunk_slot{chunk_slot}, m_stream_id{pdev->chunk_to_stream_id(cinfo)} {}

void Chunk::cp_flush() { m_blk_allocator->cp_flush(); }

std::string Chunk::to_string() const {
    return fmt::format("chunk_id={}, vdev_id={}, start_offset={}, size={}, end_of_chunk={}, slot_num_in_pdev={} "
                       "ordinal_in_vdev={} stream_id={}",
                       chunk_id(), vdev_id(), start_offset(), in_bytes(size()), end_of_chunk(), slot_number(),
                       ordinal(), stream_id());
}

nlohmann::json Chunk::get_status([[maybe_unused]] int log_level) const {
    nlohmann::json j;
    j["chunk_id"] = chunk_id();
    j["vdev_id"] = vdev_id();
    j["start_offset"] = start_offset();
    j["size"] = size();
    j["end_of_chunk_size"] = end_of_chunk();
    j["slot_alloced?"] = is_busy();
    return j;
}

#if 0
ChunkManager::ChunkManager(DeviceManager& dmgr, uint64_t chunk_sb_offset) :
        m_dmgr{dmgr}, m_sb_offset{chunk_sb_offset}, m_chunk_id_bm{dmgr.max_chunks()} {
    m_chunk_block_size = m_dmgr.atomic_page_size(PhysicalDevGroup::META);
    m_chunks_per_block = (m_chunk_block_size - sizeof(chunk_info_block)) / sizeof(chunk_info);
    m_chunk_sb_size = ((m_dmgr.max_chunks - 1) / per_block_nchunks + 1) * chunk_block_size;
    m_chunk_sb =
        hs_utils::iobuf_alloc(m_chunk_sb_size, sisl::buftag::superblk, m_dmgr.align_size(PhysicalDevGroup::META));
}

ChunkManager::~ChunkManager() { hs_utils::iobuf_free(m_chunk_sb, sisl::buftag::superblk); }

void ChunkManager::init(bool format) {
    auto devices = m_dmgr.get_all_devices();
    for (auto& dev : devices) {
        m_chunks_in_pdev.insert(std::make_pair(dev, std::vector< Chunk* >{}));
        m_chunk_slots_map.insert(std::make_pair(dev, IntervalSet{}));
    }

    if (format) {
        std::memset(m_chunk_sb, 0, m_chunk_sb_size);
        m_dmgr.write_super_blk(m_chunk_sb, m_chunk_sb_size, m_sb_offset);
    } else {
        m_dmgr.read_super_blk(m_chunk_sb, m_chunk_sb_size, m_sb_offset);

        uint32_t chunk_id{0};
        uint32_t num_blocks = m_chunk_sb_size / m_chunk_block_size;

        // Walk through each chunk info block and gather the chunk information
        for (uint32_t b{0}; b < num_blocks; ++b) {
            uint8_t* cursor_ptr = m_chunk_sb + (m_chunk_block_size * b);
            auto* cib = r_cast< chunk_info_block* >(cursor_ptr);
            validate_chunk_info_block(cib, b);

            cursor_ptr += sizeof(chunk_info_block);
            if (cib->num_chunks_in_block > 0) {
                // There are some chunks in the block, scan and create chunk instance
                for (uint32_t c{0}; c < m_chunks_per_block; ++c, ++chunk_id) {
                    auto* ci = r_cast< chunk_info* >(cursor_ptr);
                    if (ci->is_slot_allocated()) { add_chunk(ci, chunk_id); }
                    cursor_ptr += sizeof(chunk_info);
                }
            } else {
                chunk_id += m_chunks_per_block;
            }
        }
    }
}

const Chunk& ChunkManager::create_chunk(const PhysicalDev* pdev, uint32_t vdev_id, uint64_t size) {
    std::unique_lock lk(m_mtx);
    return do_create_chunk(pdev, vdev_id, size, true /* persist_now*/);
}

void ChunkManager::remove_chunk(const Chunk& chunk) {
    std::unique_lock lk(m_mtx);
    do_remove_chunk(chunk, true /* persist_now */);
}

const Chunk& ChunkManager::do_create_chunk(const PhysicalDev* pdev, uint32_t vdev_id, uint64_t size, bool persist_now) {
    // Assign a chunk id
    auto chunk_id = m_chunk_id_bm.get_next_reset_bit(0u);
    if (chunk_id == sisl::Bitset::npos) { throw std::out_of_range("System has no room for additional chunk"); }

    // Now look for free location in the pdev and insert into the slot
    auto it = m_chunk_slots_map.find(pdev);
    if (it == m_chunk_slots_map.end()) {
        throw std::runtime_error("Attempting to create a chunk on pdev which was not added");
    }
    auto ival = find_next_slot(it->second, size, m_dmgr.device_usable_size(pdev));

    // Create chunk_info structure and persist that, if required
    auto cinfo = to_chunk_info(chunk_id);
    cinfo->chunk_start_offset = ival.lower();
    cinfo->chunk_size = size;
    cinfo->pdev_id = pdev->dev_id();
    cinfo->vdev_id = vdev_id;
    cinfo->chunk_id = chunk_id;
    cinfo->set_allocated();

    // Chunk info block header structure update
    auto cblk = to_chunk_info_block(chunk_id);
    cblk->magic = CHUNK_INFO_BLOCK_MAGIC;
    cblk->version = CHUNK_INFO_BLOCK_VERSION;
    ++cblk->num_chunks_in_block;
    cblk->checksum = crc16_t10dif(hs_init_crc_16, uintptr_cast(cblk), m_chunk_block_size);

    if (persist_now) {
        m_dmgr.write_super_blk(uintptr_cast(cblk), m_chunk_block_size, m_sb_offset + chunk_info_block_offset(chunk_id));
    }

    return add_chunk(cinfo, chunk_id);
}

const Chunk& ChunkManager::add_chunk(chunk_info* cinfo, uint64_t chunk_id) {
    // Reserve the chunk_id bit
    m_chunk_id_bm.set_bits(chunk_id);

    // Put the created Chunk on chunk array for quick indexing
    m_chunks[chunk_id] = std::make_unique< Chunk >(cinfo, chunk_id);

    // Put it on the pdev organized map
    auto* pdev = m_dmgr.get_pdev(cinfo->pdev_id);
    auto it1 = m_chunks_in_pdev.find(pdev);
    if (it1 == m_chunks_in_pdev.end()) {
        throw std::runtime_error("Attempting to add a chunk on pdev which was not added");
    }
    it1->second->push_back(m_chunks[chunk_id].get());

    // Put the chunk interval to the slots map
    auto it2 = m_chunk_slots_map.find(pdev);
    if (it2 == m_chunk_slots_map.end()) {
        throw std::runtime_error("Attempting to add a chunk on pdev which was not added");
    }
    it2->second.add(
        ChunkInterval::right_open(cinfo->chunk_start_offset, cinfo->chunk_start_offset + cinfo->chunk_size));

    // Put it on the vdev organized map
    auto [it3, inserted] = m_chunks_in_vdev.insert(std::make_pair(cinfo->vdev_id, std::vector< Chunk* >()));
    it3->second->push_back(m_chunks[chunk_id].get());

    ++m_num_chunks;
    return *m_chunks[chunk_id];
}

void ChunkManager::do_remove_chunk(uint64_t chunk_id) {
    Chunk* pchunk = m_chunks[chunk_id].get();
    if (pchunk == nullptr) { throw std::runtime_error("Attempting to remove an non-existing chunk id={}", chunk_id); }
    chunk_info* cinfo = pchunk->chunk_info;

    // Remove from the vdev organized map
    if (auto it = m_chunks_in_vdev.find(cinfo->vdev_id); it != m_chunks_in_vdev.end()) {
        auto& cvec = it->second;
        for (auto cit = cvec.rbegin(); cit != cvec.rend(); ++cit) {
            if (*cit == pchunk) {
                cvec.erase(cit);
                break;
            }
        }
    } else {
        throw std::runtime_error("Attempting to remove an non-existing chunk from vdev map id={}", chunk_id);
    }

    // Remove the chunk interval to the slots map
    if (auto it = m_chunk_slots_map.find(pdev); (it != m_chunk_slots_map.end())) {
        it->second.erase(
            ChunkInterval::right_open(cinfo->chunk_start_offset, cinfo->chunk_start_offset + cinfo->chunk_size));
    } else {
        throw std::runtime_error("Attempting to add a chunk on pdev which was not added");
    }

    // Remove the chunk from pdev map
    if (auto it = m_chunks_in_pdev.find(m_dmgr.get_pdev(cinfo->pdev_id)); it != m_chunks_in_pdev.end()) {
        auto& cvec = it->second;
        for (auto cit = cvec.rbegin(); cit != cvec.rend(); ++cit) {
            if (*cit == pchunk) {
                cvec.erase(cit);
                break;
            }
        }
    } else {
        throw std::runtime_error("Attempting to remove an non-existing chunk from vdev map id={}", chunk_id);
    }

    // Remove finally from the chunk array itself
    pchunk = nullptr;
    m_chunks[chunk_id].reset();

    // Reclaim the chunk id itself
    m_chunk_id_bm.set_bits(chunk_id);
    --m_num_chunks;
}

chunk_info* ChunkManager::to_chunk_info(uint32_t chunk_id) const {
    // Locate the chunk block
    auto blk_num = chunk_id / m_chunks_per_block;
    auto chunk_slot_offset = chunk_id % m_chunks_per_block;

    return r_cast< chunk_info* >(m_chunk_sb + (m_chunk_block_size * blk_num) + sizeof(chunk_info_block) +
                                 (sizeof(chunk_info) * chunk_slot_offset));
}

chunk_info_block* ChunkManager::to_chunk_info_block(uint32_t chunk_id) const {
    auto blk_num = chunk_id / m_chunks_per_block;
    return r_cast< chunk_info_block* >(m_chunk_sb + (m_chunk_block_size * blk_num));
}

uint64_t ChunkManager::chunk_info_block_offset(uint32_t chunk_id) const {
    auto blk_num = chunk_id / m_chunks_per_block;
    return (m_chunk_block_size * blk_num);
}

void ChunkManager::validate_chunk_info_block(chunk_info_block* cib, uint32_t blk_num) const {
    RELEASE_ASSERT_EQ(cib->magic, CHUNK_INFO_BLOCK_MAGIC, "Mismatch magic for cib at blk_num={}", blk_num);
    RELEASE_ASSERT_EQ(cib->version, CHUNK_INFO_BLOCK_VERSION, "Unsupported version for cib at blk_num={}", blk_num);
    if (cib->checksum != 0) {
        auto const crc = crc16_t10dif(hs_init_crc_16, uintptr_cast(cib), m_chunk_block_size);
        RELEASE_ASSERT_EQ(crc, cib->checksum, "Checksum mismatch on cib at blk_num={}", blk_num);
    } else {
        RELEASE_ASSERT_EQ(cib->num_chunks_in_block, 0,
                          "Checksum in cib without num_chunks_in_block, possible corruption?");
    }
}

ChunkInterval ChunkManager::find_next_slot(IntervalSet& chunks, uint64_t size, uint64_t max_size) const {
    auto ins_ival = ChunkInterval::right_open(0u, size);
    for (auto& exist_ival : chunks) {
        if (ins_ival.upper() <= exist_ival.lower()) { break; }
        ins_ival = ChunkInterval::right_open(exist_ival.upper(), exist_ival.upper() + size);
    }

    if (ins_ival.upper() > max_size) { throw std::out_of_range("System has no room for additional chunk"); }
    return ins_ival;
}
#endif
} // namespace homestore
