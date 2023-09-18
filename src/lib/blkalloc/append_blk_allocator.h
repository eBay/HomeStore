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
#include "blk_allocator.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include <homestore/blk.h>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/homestore.hpp>
#include <homestore/superblk_handler.hpp>

namespace homestore {
static constexpr uint64_t append_blkalloc_sb_magic{0xd0d0d02b};
static constexpr uint64_t append_blkalloc_sb_version{0x1};

#pragma pack(1)
struct append_blkalloc_ctx {
    uint64_t magic{append_blkalloc_sb_magic};
    uint32_t version{append_blkalloc_sb_version};
    bool is_dirty; // this field is needed for cp_flush, but not necessarily needed for persistence;
    allocator_id_t allocator_id;
    uint64_t freeable_nblks;
    uint64_t last_append_offset;
};
#pragma pack()

class AppendBlkAllocMetrics : public sisl::MetricsGroup {
public:
    explicit AppendBlkAllocMetrics(const char* inst_name) : sisl::MetricsGroup("AppendBlkAlloc", inst_name) {
        REGISTER_COUNTER(num_alloc, "Number of blks alloc attempts");
        REGISTER_COUNTER(num_alloc_failure, "Number of blk alloc failures");

        register_me_to_farm();
    }

    AppendBlkAllocMetrics(const AppendBlkAllocMetrics&) = delete;
    AppendBlkAllocMetrics(AppendBlkAllocMetrics&&) noexcept = delete;
    AppendBlkAllocMetrics& operator=(const AppendBlkAllocMetrics&) = delete;
    AppendBlkAllocMetrics& operator=(AppendBlkAllocMetrics&&) noexcept = delete;
    ~AppendBlkAllocMetrics() { deregister_me_from_farm(); }
};

//
// The assumption for AppendBlkAllocator:
// 1. Operations (alloc/free) are being called multiple threadeds
// 2. cp_flush will be triggered in a different thread
//
// Why do we want thread-safe AppendBlkAllocator:
// 1. one reason is it makes sense for AppendBlkAllocator to work on a nvme drive
// 2. for HDD, performance will drop significantly if alloc/write is being done in multi-threaded model, it is left for
// consumer to make choice;
//
class AppendBlkAllocator : public BlkAllocator {
public:
    AppendBlkAllocator(const BlkAllocConfig& cfg, bool need_format, allocator_id_t id = 0);

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
    blk_cap_t get_freeable_nblks() const;

    bool is_blk_alloced(const BlkId& in_bid, bool use_lock = false) const override;
    std::string to_string() const override;

    /// @brief : needs to be called with cp_guard();
    void set_dirty_offset(const uint8_t idx);

    /// @brief : clear dirty is best effort;
    /// offset flush is idempotent;
    void clear_dirty_offset(const uint8_t idx);

    void cp_flush(CP* cp) override;

private:
    std::string get_name() const;
    void on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);

private:
    std::mutex m_mtx;                 // thread_safe, TODO: open option for consumer to choose to go lockless;
    uint64_t m_last_append_offset{0}; // last appended offset in blocks;
    uint64_t m_freeable_nblks{0};
    AppendBlkAllocMetrics m_metrics;
    std::array< superblk< append_blkalloc_ctx >, MAX_CP_COUNT > m_sb;
};

} // namespace homestore
