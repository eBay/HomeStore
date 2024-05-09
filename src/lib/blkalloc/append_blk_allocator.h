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
struct append_blk_sb_t {
    uint64_t magic{append_blkalloc_sb_magic};
    uint32_t version{append_blkalloc_sb_version};
    allocator_id_t allocator_id; // doesn't expect this to be changed once initialized;
    blk_num_t freeable_nblks;
    blk_num_t commit_offset;
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

    BlkAllocStatus alloc_contiguous(BlkId& bid) override;
    BlkAllocStatus alloc(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) override;
    void free(BlkId const& b) override;
    BlkAllocStatus reserve_on_disk(BlkId const& in_bid) override;
    BlkAllocStatus reserve_on_cache(BlkId const& b) override;

    void free_on_disk(BlkId const& b) override;
    bool is_blk_alloced_on_disk(BlkId const& b, bool use_lock = false) const override;

    /**
     * @brief :  the number of available blocks that can be allocated by the AppendBlkAllocator.
     * @return : the number of available blocks.
     */
    blk_num_t available_blks() const override;

    /**
     * @brief : the number of used blocks by the AppendBlkAllocator.
     * @return : the number of used blocks.
     */
    blk_num_t get_used_blks() const override;

    /**
     * @brief : the number of blocks that have been fragmented by the free
     * @return : the number of fragmented blks
     */
    blk_num_t get_fragmented_nblks() const;

    /**
     * @brief : check if the input blk id is allocated or not.
     * @return : true if blkid is allocated, false if not;
     */
    bool is_blk_alloced(const BlkId& in_bid, bool use_lock = false) const override;

    std::string to_string() const override;

    void cp_flush(CP* cp) override;

    nlohmann::json get_status(int log_level) const override;

private:
    std::string get_name() const;
    void on_meta_blk_found(const sisl::byte_view& buf, void* meta_cookie);

private:
    std::atomic< blk_num_t > m_last_append_offset{0}; // last appended offset in blocks;
    std::atomic< blk_num_t > m_freeable_nblks{0};
    std::atomic< blk_num_t > m_commit_offset{0}; // commit offset in on-disk version
    std::atomic< bool > m_is_dirty{false};
    AppendBlkAllocMetrics m_metrics;
    superblk< append_blk_sb_t > m_sb; // only cp will be writing to this disk
};

} // namespace homestore
