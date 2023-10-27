/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#ifndef ALLOCATOR_H
#define ALLOCATOR_H

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
    const std::string m_unique_name;
    bool m_auto_recovery{false};
    bool m_realtime_bm_on{false}; // only specifically turn off in BlkAlloc Test;

public:
    BlkAllocConfig(uint32_t blk_size, uint32_t align_size, uint64_t size, const std::string& name = "",
                   bool realtime_bm_on = true) :
            m_blk_size{blk_size},
            m_align_size{align_size},
            m_capacity{static_cast< blk_num_t >(size / blk_size)},
            m_blks_per_portion{std::min(HS_DYNAMIC_CONFIG(blkallocator.num_blks_per_portion), m_capacity)},
            m_unique_name{name} {
#ifdef _PRERELEASE
        // for pre-release build, take it from input which is defaulted to true;
        m_realtime_bm_on = realtime_bm_on;
#else
        // for release build, take it from dynamic config which is defaulted to false
        m_realtime_bm_on = HS_DYNAMIC_CONFIG(blkallocator.realtime_bitmap_on);
#endif
    }

    BlkAllocConfig(BlkAllocConfig const&) = default;
    BlkAllocConfig(BlkAllocConfig&&) noexcept = delete;
    BlkAllocConfig& operator=(BlkAllocConfig const&) = default;
    BlkAllocConfig& operator=(BlkAllocConfig&&) noexcept = delete;
    virtual ~BlkAllocConfig() = default;
    void set_auto_recovery(bool is_auto_recovery) { m_auto_recovery = is_auto_recovery; }

    virtual std::string to_string() const {
        return fmt::format("BlkSize={} TotalBlks={} BlksPerPortion={} auto_recovery={}", in_bytes(m_blk_size),
                           in_bytes(m_capacity), m_blks_per_portion, m_auto_recovery);
    }
};

VENUM(BlkOpStatus, uint8_t,
      NONE = 0,            // Default no status
      SUCCESS = 1u << 0,   // Success
      FAILED = 1u << 1,    // Generic failure
      SPACEFULL = 1u << 2, // Space full failure
      PARTIAL_FAILED = 1u << 3);

ENUM(BlkAllocatorState, uint8_t, INIT, WAITING, SWEEP_SCHEDULED, SWEEPING, EXITING, DONE);

class BlkAllocPortion {
private:
    mutable std::mutex m_blk_lock;
    blk_num_t m_portion_num;
    blk_temp_t m_temperature;
    blk_num_t m_available_blocks;

public:
    BlkAllocPortion(blk_temp_t temp = default_temperature()) : m_temperature(temp) {}
    ~BlkAllocPortion() = default;
    BlkAllocPortion(BlkAllocPortion const&) = delete;
    BlkAllocPortion(BlkAllocPortion&&) noexcept = delete;
    BlkAllocPortion& operator=(BlkAllocPortion const&) = delete;
    BlkAllocPortion& operator=(BlkAllocPortion&&) noexcept = delete;

    auto portion_auto_lock() const { return std::scoped_lock< std::mutex >(m_blk_lock); }
    blk_num_t get_portion_num() const { return m_portion_num; }
    blk_num_t get_available_blocks() const { return m_available_blocks; }
    blk_temp_t temperature() const { return m_temperature; }

    void set_portion_num(blk_num_t portion_num) { m_portion_num = portion_num; }
    void set_available_blocks(const blk_num_t available_blocks) { m_available_blocks = available_blocks; }
    blk_num_t decrease_available_blocks(const blk_num_t count) { return (m_available_blocks -= count); }
    blk_num_t increase_available_blocks(const blk_num_t count) { return (m_available_blocks += count); }
    void set_temperature(const blk_temp_t temp) { m_temperature = temp; }
    static constexpr blk_temp_t default_temperature() { return 1; }
};

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
    BlkAllocator(BlkAllocConfig const& cfg, chunk_num_t id = 0);
    BlkAllocator(BlkAllocator const&) = delete;
    BlkAllocator(BlkAllocator&&) noexcept = delete;
    BlkAllocator& operator=(BlkAllocator const&) = delete;
    BlkAllocator& operator=(BlkAllocator&&) noexcept = delete;
    virtual ~BlkAllocator() = default;

    virtual BlkAllocStatus alloc_contiguous(BlkId& bid) = 0;
    virtual BlkAllocStatus alloc(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) = 0;
    virtual void free(BlkId const& id) = 0;
    virtual blk_num_t available_blks() const = 0;
    virtual blk_num_t get_freeable_nblks() const = 0;
    virtual blk_num_t get_defrag_nblks() const = 0;
    virtual blk_num_t get_used_blks() const = 0;
    virtual bool is_blk_alloced(BlkId const& b, bool use_lock = false) const = 0;
    virtual std::string to_string() const = 0;

    virtual void cp_flush(CP* cp); // TODO: it needs to be a pure virtual function after bitmap blkallocator is derived
                                   // from base BlkAllocator;

    sisl::Bitset* get_disk_bm_mutable() {
        set_disk_bm_dirty();
        return m_disk_bm.get();
    }
    const sisl::Bitset* get_disk_bm_const() const { return m_disk_bm.get(); };
    sisl::Bitset* get_realtime_bm() { return m_realtime_bm.get(); }
    const sisl::Bitset* get_realtime_bm() const { return m_realtime_bm.get(); }

    bool need_flush_dirty_bm() const { return is_disk_bm_dirty; }

    void set_disk_bm(std::unique_ptr< sisl::Bitset > recovered_bm);
    BlkAllocPortion& get_blk_portion(blk_num_t portion_num) {
        HS_DBG_ASSERT_LT(portion_num, get_num_portions(), "Portion num is not in range");
        return m_blk_portions[portion_num];
    }

    virtual void inited();

    void incr_alloced_blk_count(blk_count_t nblks) { m_alloced_blk_count.fetch_add(nblks, std::memory_order_relaxed); }

    void decr_alloced_blk_count(blk_count_t nblks) { m_alloced_blk_count.fetch_sub(nblks, std::memory_order_relaxed); }

    int64_t get_alloced_blk_count() const { return m_alloced_blk_count.load(std::memory_order_acquire); }

    /* It is used during recovery in both mode :- auto recovery and manual recovery
     * It is also used in normal IO during auto recovery mode.
     */

    BlkAllocStatus alloc_on_disk(BlkId const& in_bid);

    BlkAllocStatus alloc_on_realtime(BlkId const& b);

    bool is_blk_alloced_on_disk(BlkId const& b, bool use_lock = false) const;

    //
    // Caller should consume the return value and print context when return false;
    //
    [[nodiscard]] bool free_on_realtime(BlkId const& b);

    void free_on_disk(BlkId const& b);

    /* CP start is called when all its consumers have purged their free lists and now want to persist the
     * disk bitmap.
     */
    // sisl::byte_array cp_start([[maybe_unused]] const std::shared_ptr< blkalloc_cp >& id);

    // void cp_done();

    uint32_t get_align_size() const { return m_align_size; }
    blk_num_t get_total_blks() const { return m_num_blks; }
    blk_num_t get_blks_per_portion() const { return m_blks_per_portion; }
    blk_num_t get_num_portions() const { return (m_num_blks - 1) / m_blks_per_portion + 1; }
    const std::string& get_name() const { return m_name; }
    bool auto_recovery_on() const { return m_auto_recovery; }
    uint32_t get_blk_size() const { return m_blk_size; }

    blk_num_t blknum_to_portion_num(const blk_num_t blknum) const { return blknum / m_blks_per_portion; }
    BlkAllocPortion& blknum_to_portion(blk_num_t blknum) { return m_blk_portions[blknum_to_portion_num(blknum)]; }
    BlkAllocPortion const& blknum_to_portion_const(blk_num_t blknum) const {
        return m_blk_portions[blknum_to_portion_num(blknum)];
    }

    void create_debug_bm();
    void update_debug_bm(BlkId const& bid);
    bool verify_debug_bm(bool free_debug_bm);

    /* Get status */
    nlohmann::json get_status(int log_level) const;

    bool realtime_bm_on() const { return (m_realtime_bm_on && m_auto_recovery); }
    void reset_disk_bm_dirty() { is_disk_bm_dirty = false; }

private:
    sisl::Bitset* get_debug_bm() { return m_debug_bm.get(); }
    sisl::ThreadVector< BlkId >* get_alloc_blk_list();
    void set_disk_bm_dirty() { is_disk_bm_dirty = true; }

    // Acquire the underlying bitmap buffer and while the caller has acquired, all the new allocations
    // will be captured in a separate list and then pushes into buffer once released.
    // NOTE: THIS IS NON-THREAD SAFE METHOD. Caller is expected to ensure synchronization between multiple
    // acquires/releases
    sisl::byte_array acquire_underlying_buffer();
    void release_underlying_buffer();

protected:
    const std::string m_name;
    const uint32_t m_blk_size;
    const uint32_t m_align_size;
    const blk_num_t m_num_blks;
    blk_num_t m_blks_per_portion;
    const bool m_auto_recovery{false};
    const bool m_realtime_bm_on{false}; // only specifically turn off in BlkAlloc Test;
    bool m_inited{false};
    const chunk_num_t m_chunk_id;

private:
    sisl::ThreadVector< BlkId >* m_alloc_blkid_list{nullptr};
    std::unique_ptr< BlkAllocPortion[] > m_blk_portions;
    std::unique_ptr< sisl::Bitset > m_disk_bm{nullptr};
    std::unique_ptr< sisl::Bitset > m_debug_bm{
        nullptr}; // it is used only for debugging during boot or when HS is in restricted mode
    std::unique_ptr< sisl::Bitset > m_realtime_bm{
        nullptr}; // it is used only for debugging to keep track of allocated/free blkids in real time
    std::atomic< int64_t > m_alloced_blk_count{0};
    std::atomic< bool > is_disk_bm_dirty{true}; // initially disk_bm treated as dirty
};

/* FixedBlkAllocator is a fast allocator where it allocates only 1 size block and ALL free blocks are cached instead
 * of selectively caching few blks which are free. Thus there is no sweeping of bitmap or other to refill the cache.
 * It does not support temperature of blocks and allocates simply on first come first serve basis
 */
class FixedBlkAllocator : public BlkAllocator {
public:
    FixedBlkAllocator(BlkAllocConfig const& cfg, bool init, chunk_num_t chunk_id);
    FixedBlkAllocator(FixedBlkAllocator const&) = delete;
    FixedBlkAllocator(FixedBlkAllocator&&) noexcept = delete;
    FixedBlkAllocator& operator=(FixedBlkAllocator const&) = delete;
    FixedBlkAllocator& operator=(FixedBlkAllocator&&) noexcept = delete;
    ~FixedBlkAllocator() override = default;

    BlkAllocStatus alloc_contiguous(BlkId& bid) override;
    BlkAllocStatus alloc(blk_count_t nblks, blk_alloc_hints const& hints, BlkId& out_blkid) override;
    void free(BlkId const& b) override;
    void inited() override;

    blk_num_t available_blks() const override;
    blk_num_t get_freeable_nblks() const override;
    blk_num_t get_defrag_nblks() const override;
    blk_num_t get_used_blks() const override;
    bool is_blk_alloced(BlkId const& in_bid, bool use_lock = false) const override;
    std::string to_string() const override;

private:
    blk_num_t init_portion(BlkAllocPortion& portion, blk_num_t start_blk_num);

private:
    folly::MPMCQueue< BlkId > m_blk_q;
};

} // namespace homestore
#endif
