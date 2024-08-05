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

////////////////////////////////////// BlkAllocator Design //////////////////////////////////////////////
//
// BlkAllocator is a generic class to allocate and free blocks. It is a base class upon which different allocators are
// derived from. This class provides generic framework for them to allocate, free and recover those blks.
//
// There are 3 levels where allocated/free blks for the blkallocator is maintained
//   1. cache version
//   2. on-disk version
//   3. Actual persistent version in the devices.
//
// Allocation/Reservation:
// All allocation happens from the cache version of the blkallocator. Based on different blkallocator, it searches and
// picks available free blk and respond to that call. When the blks are ready to be committed, it calls commit_blk of
// the vdev, which calls reserve_on_disk() of the blkallocator to reserve the blkids in the on-disk version.
//
// When the blkids are reserved in the on-disk version, it is not yet written to the actual devices. It is written
// as part of the next CP.
//
// Upon restart, there are 2 types of mismatches possible between state of blks before restart and
// after restart.
//  a) Blks that are allocated in cache version prior to restart, but they are not committed yet.
//  b) Blks that are marked reserved in on-disk version prior to restart, but they are not persisted yet.
//
// During recovery phase after restart the persistent version is loaded and updated into the on-disk version and also
// copies that on-disk version to cache version. BlkAllocator requires consumer to maintain the allocated blkids in
// journal and replay them during restart. When the consumer replays, it calls VirtualDev::commit_blk() calls
// reserve_on_cache() and reserve_on_disk() (only during recovery, otherwise it calls only reserve_on_disk()).
// reserve_on_cache() will mark the blkids in the cache as allocated and reserve_on_disk() marks the blkids in on-disk
// version as allocated.
//
// Free:
// Freeing the blocks is done in a slightly different way, where blkallocator free will free the blk from cache version.
// and also on disk version and will be persisted on next cp. In other words, free blks are always committed entries.
// Blkallocator free is idempotent.
//
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
    virtual BlkAllocStatus reserve_on_disk(BlkId const& bid) = 0;
    virtual BlkAllocStatus reserve_on_cache(BlkId const& bid) = 0;

    virtual void free(BlkId const& id) = 0;

    virtual blk_num_t available_blks() const = 0;
    virtual blk_num_t get_defrag_nblks() const = 0;
    virtual blk_num_t get_used_blks() const = 0;
    virtual bool is_blk_alloced(BlkId const& b, bool use_lock = false) const = 0;
    virtual bool is_blk_alloced_on_disk(BlkId const& b, bool use_lock = false) const = 0;
    virtual void recovery_completed() = 0;

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
