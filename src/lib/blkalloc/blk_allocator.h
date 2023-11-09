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

#include <cassert>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sisl/fds/bitset.hpp>
#include <folly/MPMCQueue.h>
#include <sisl/utility/enum.hpp>
#include <sisl/utility/urcu_helper.hpp>
#include <sisl/fds/thread_vector.hpp>

#include <homestore/homestore_decl.hpp>
#include <homestore/blk.h>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"

SISL_LOGGING_DECL(blkalloc)
SISL_LOGGING_DECL(transient)

namespace homestore {
#define BLKALLOC_LOG(level, msg, ...) HS_SUBMOD_LOG(level, blkalloc, , "blkalloc", get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_DBG_ASSERT(cond, msg, ...)                                                                            \
    HS_SUBMOD_ASSERT(DEBUG_ASSERT_FMT, cond, , "blkalloc", get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_REL_ASSERT(cond, msg, ...)                                                                            \
    HS_SUBMOD_ASSERT(RELEASE_ASSERT_FMT, cond, , "blkalloc", get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_LOG_ASSERT(cond, msg, ...)                                                                            \
    HS_SUBMOD_ASSERT(LOGMSG_ASSERT_FMT, cond, , "blkalloc", get_name(), msg, ##__VA_ARGS__)

#define BLKALLOC_REL_ASSERT_CMP(val1, cmp, val2, ...)                                                                  \
    HS_SUBMOD_ASSERT_CMP(RELEASE_ASSERT_CMP, val1, cmp, val2, , "blkalloc", get_name(), ##__VA_ARGS__)
#define BLKALLOC_DBG_ASSERT_CMP(val1, cmp, val2, ...)                                                                  \
    HS_SUBMOD_ASSERT_CMP(DEBUG_ASSERT_CMP, val1, cmp, val2, , "blkalloc", get_name(), ##__VA_ARGS__)
#define BLKALLOC_LOG_ASSERT_CMP(val1, cmp, val2, ...)                                                                  \
    HS_SUBMOD_ASSERT_CMP(LOGMSG_ASSERT_CMP, val1, cmp, val2, , "blkalloc", get_name(), ##__VA_ARGS__)

struct blkalloc_cp;

struct BlkAllocConfig {
    friend class BlkAllocator;

public:
    const uint32_t m_blk_size;
    const uint32_t m_align_size;
    const blk_num_t m_capacity;
    const blk_num_t m_blks_per_portion;
    const bool m_persistent{false};
    const std::string m_unique_name;

public:
    BlkAllocConfig(uint32_t blk_size, uint32_t align_size, uint64_t size, bool persistent,
                   const std::string& name = "") :
            m_blk_size{blk_size},
            m_align_size{align_size},
            m_capacity{static_cast< blk_num_t >(size / blk_size)},
            m_blks_per_portion{std::min(HS_DYNAMIC_CONFIG(blkallocator.num_blks_per_portion), m_capacity)},
            m_persistent{persistent},
            m_unique_name{name} {}

    BlkAllocConfig(BlkAllocConfig const&) = default;
    BlkAllocConfig(BlkAllocConfig&&) noexcept = delete;
    BlkAllocConfig& operator=(BlkAllocConfig const&) = default;
    BlkAllocConfig& operator=(BlkAllocConfig&&) noexcept = delete;
    virtual ~BlkAllocConfig() = default;

    virtual std::string to_string() const {
        return fmt::format("BlkSize={} TotalBlks={} BlksPerPortion={} persistent={}", in_bytes(m_blk_size),
                           in_bytes(m_capacity), m_blks_per_portion, m_persistent);
    }
};

VENUM(BlkOpStatus, uint8_t,
      NONE = 0,            // Default no status
      SUCCESS = 1u << 0,   // Success
      FAILED = 1u << 1,    // Generic failure
      SPACEFULL = 1u << 2, // Space full failure
      PARTIAL_FAILED = 1u << 3);

ENUM(BlkAllocatorState, uint8_t, INIT, WAITING, SWEEP_SCHEDULED, SWEEPING, EXITING, DONE);

/* We have the following design requirement it is used in auto recovery mode
 *  - Free BlkIDs should not be re allocated until its free status is persisted on disk. Reasons :-
 *          - It helps is reconstructing btree in crash as it depends on old blkid to read the data
 *          - Different volume recovery doesn't need to dependent on each other. We can sequence based recovery
 *            instead of time based recovery.
 *  - Allocate BlkIDs should not be persisted until it is persisted in journal. If system crash after writing to
 *    in use bm but before writing to journal then blkid will be leak forever.
 *
 * To achieve the above requirements we free blks in three phase
 *      - accumulate all the blkids in the consumer
 *      - Reset bits in disk bitmap only
 *      - persist disk bitmap
 *      - Reset bits in cache bitmap. It is available to reallocate now.
 *  Note :- Blks can be freed directly to the cache if it is not set disk bitmap. This can happen in scenarios like
 *  write failure after blkid allocation.
 *
 *  Allocation of blks also happen in two phase
 *      - Allocate blkid. This blkid will already be set in cache bitmap
 *      - Consumer will persist entry in journal
 *      - Set bit in disk bitmap. Entry is set disk bitmap only when consumer have made sure that they are going to
 *        replay this entry. otherwise there will be disk leak
 *  Note :- Allocate blk should always be done in two phase if auto recovery is set.
 *
 *
 * Blk allocator has two recoveries auto recovery and manual recovery
 * 1. auto recovery :- disk bit map is persisted. Consumers only have to replay journal. It is used by volume and
 * btree.
 * 2. manual recovery :- disk bit map is not persisted. Consumers have to scan its index table to set blks
 * allocated. It is used meta blk manager. Base class manages disk_bitmap as it is common to all blk allocator.
 *
 * Disk bitmap is persisted only during checkpoints. These two things always be true while disk bitmap is persisting
 * 1. It contains atleast all the blks allocated upto that checkpoint. It can contain blks allocated for next
 *    checkpoints also.
 * 2. It contains blks freed only upto that checkpoint.
 */

class CP;
class BlkAllocator {
public:
    BlkAllocator(BlkAllocConfig const& cfg, chunk_num_t id = 0) :
            m_name{cfg.m_unique_name},
            m_blk_size{cfg.m_blk_size},
            m_align_size{cfg.m_align_size},
            m_num_blks{cfg.m_capacity},
            m_chunk_id{id},
            m_is_persistent{cfg.m_persistent} {}
    BlkAllocator(BlkAllocator const&) = delete;
    BlkAllocator(BlkAllocator&&) noexcept = delete;
    BlkAllocator& operator=(BlkAllocator const&) = delete;
    BlkAllocator& operator=(BlkAllocator&&) noexcept = delete;
    virtual ~BlkAllocator() = default;

    virtual BlkAllocStatus alloc_contiguous(BlkId& bid) = 0;
    virtual BlkAllocStatus alloc(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) = 0;
    virtual BlkAllocStatus alloc_on_disk(BlkId const& bid) = 0;

    virtual void free(BlkId const& id) = 0;
    virtual void free_on_disk(BlkId const& bid) = 0;

    virtual blk_num_t available_blks() const = 0;
    virtual blk_num_t get_freeable_nblks() const = 0;
    virtual blk_num_t get_defrag_nblks() const = 0;
    virtual blk_num_t get_used_blks() const = 0;
    virtual bool is_blk_alloced(BlkId const& b, bool use_lock = false) const = 0;
    virtual bool is_blk_alloced_on_disk(BlkId const& b, bool use_lock = false) const = 0;

    virtual std::string to_string() const = 0;
    virtual void cp_flush(CP* cp) = 0;

    uint32_t get_align_size() const { return m_align_size; }
    blk_num_t get_total_blks() const { return m_num_blks; }
    const std::string& get_name() const { return m_name; }
    bool is_persistent() const { return m_is_persistent; }
    uint32_t get_blk_size() const { return m_blk_size; }

    /* Get status */
    virtual nlohmann::json get_status(int log_level) const = 0;

protected:
    const std::string m_name;
    const uint32_t m_blk_size;
    const uint32_t m_align_size;
    const blk_num_t m_num_blks;
    const chunk_num_t m_chunk_id;
    const bool m_is_persistent;
};

} // namespace homestore
