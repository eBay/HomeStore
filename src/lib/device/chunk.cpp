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
#include "device/chunk.h"
#include "device/device.h"
#include "device/physical_dev.hpp"
#include "common/homestore_utils.hpp"
#include "blkalloc/blk_allocator.h"

namespace homestore {
Chunk::Chunk(PhysicalDev* pdev, const chunk_info& cinfo, uint32_t chunk_slot) :
        m_chunk_info{cinfo}, m_pdev{pdev}, m_chunk_slot{chunk_slot}, m_stream_id{pdev->chunk_to_stream_id(cinfo)} {}

std::string Chunk::to_string() const {
    return fmt::format("chunk_id={}, vdev_id={}, start_offset={}, size={}, slot_num_in_pdev={} "
                       "pdev_ordinal={} vdev_ordinal={} stream_id={}",
                       chunk_id(), vdev_id(), start_offset(), in_bytes(size()), slot_number(), pdev_ordinal(),
                       vdev_ordinal(), stream_id());
}

void Chunk::set_user_private(const sisl::blob& data) {
    std::unique_lock lg{m_mgmt_mutex};
    m_chunk_info.set_user_private(data);
    m_chunk_info.compute_checksum();
    write_chunk_info();
}

void Chunk::write_chunk_info() {
    auto buf = hs_utils::iobuf_alloc(chunk_info::size, sisl::buftag::superblk, physical_dev()->align_size());
    auto cinfo = new (buf) chunk_info();
    *cinfo = m_chunk_info;
    physical_dev_mutable()->write_super_block(buf, chunk_info::size,
                                              physical_dev()->chunk_info_offset_nth(slot_number()));
    cinfo->~chunk_info();
    hs_utils::iobuf_free(buf, sisl::buftag::superblk);
}

nlohmann::json Chunk::get_status([[maybe_unused]] int log_level) const {
    nlohmann::json j;
    j["chunk_id"] = chunk_id();
    j["vdev_id"] = vdev_id();
    j["start_offset"] = start_offset();
    j["size"] = size();
    j["slot_alloced?"] = is_busy();
    return j;
}
} // namespace homestore
