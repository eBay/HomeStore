/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 * *
 * *********************************************************************************/
#pragma once

#include <sisl/logging/logging.h>
#include <homestore/blk.h>
#include "blk_allocator.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"

namespace homestore {
static constexpr uint64_t append_blkalloc_sb_magic{0xd0d0d02b};
static constexpr uint64_t append_blkalloc_sb_version{0x1};

#pragma pack(1)
struct append_blkalloc_sb {
    uint64_t magic{append_blkalloc_sb_magic};
    uint32_t version{append_blkalloc_sb_version};
    uint64_t chunk_id;
    uint64_t last_append_offset;
};
#pragma pack()

// TODO: add metrics
class AppendBlkAllocator : public BlkAllocator {
public:
    AppendBlkAllocator(const BlkAllocConfig& cfg, bool first_time_boot, chunk_num_t id = 0);

    AppendBlkAllocator(const AppendBlkAllocator&) = delete;
    AppendBlkAllocator(AppendBlkAllocator&&) noexcept = delete;
    AppendBlkAllocator& operator=(const AppendBlkAllocator&) = delete;
    AppendBlkAllocator& operator=(AppendBlkAllocator&&) noexcept = delete;
    virtual ~AppendBlkAllocator() = default;

    BlkAllocStatus alloc(BlkId& bid) override;
    BlkAllocStatus alloc(blk_count_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) override;

    void free(const std::vector< BlkId >& blk_ids) override;
    void free(const BlkId& b) override;

    blk_cap_t available_blks() const override;
    blk_cap_t get_used_blks() const override;

    bool is_blk_alloced(const BlkId& in_bid, bool use_lock = false) const override;
    std::string to_string() const override;

    void set_dirty_offset();

    /// @brief : clear dirty is best effort;
    /// offset flush is idempotent;
    void clear_dirty_offset();

    void cp_flush(CP* cp);

private:
    void on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);

private:
    std::atomic< uint64_t > last_append_offset; // last appended offset in blocks;
    std::atomic< bool > m_is_dirty{false};
    superblk< append_blkalloc_sb > m_sb;
};

} // namespace homestore
