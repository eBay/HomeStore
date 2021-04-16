/*
 * BlkAllocator.h
 *
 *  Created on: Aug 09, 2016
 *      Author: hkadayam
 */

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

#include <boost/range/irange.hpp>
#include <fds/bitset.hpp>
#include <folly/MPMCQueue.h>
#include <utility/enum.hpp>

#include "blk.h"
#include "engine/device/device.h"
#include "engine/homeds/btree/btree.hpp"
#include "engine/homestore_base.hpp"
#include "engine/index/resource_mgr.hpp"
#include "api/meta_interface.hpp"

#include "blk.h"

SDS_LOGGING_DECL(blkalloc)
SDS_LOGGING_DECL(transient)

namespace homestore {
#define BLKALLOC_LOG(level, msg, ...) HS_SUBMOD_LOG(level, blkalloc, , "blkalloc", m_cfg.get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_ASSERT(assert_type, cond, msg, ...)                                                                   \
    HS_SUBMOD_ASSERT(assert_type, cond, , "blkalloc", m_cfg.get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                         \
    HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, , "blkalloc", m_cfg.get_name(), ##__VA_ARGS__)
#define BLKALLOC_ASSERT_NOTNULL(assert_type, val, ...)                                                                 \
    HS_SUBMOD_ASSERT_NOTNULL(assert_type, val, , "blkalloc", m_cfg.get_name(), ##__VA_ARGS__)
#define BLKALLOC_ASSERT_NULL(assert_type, val, ...)                                                                    \
    HS_SUBMOD_ASSERT_NULL(assert_type, val, , "blkalloc", m_cfg.get_name(), ##__VA_ARGS__)

struct blkalloc_cp;

class BlkAllocConfig {
private:
    uint32_t m_blk_size;
    blk_cap_t m_capacity;
    blk_cap_t m_blks_per_portion;
    std::string m_unique_name;
    bool m_auto_recovery = false;

public:
    BlkAllocConfig(const uint32_t blk_size, const uint64_t size, const std::string& name = "") :
            m_blk_size{blk_size},
            m_capacity{static_cast< blk_cap_t >(size / blk_size)},
            m_blks_per_portion{std::min(HS_DYNAMIC_CONFIG(blkallocator.num_blks_per_portion), m_capacity)},
            m_unique_name{name} {}

    BlkAllocConfig(const BlkAllocConfig&) = default;
    BlkAllocConfig(BlkAllocConfig&&) noexcept = delete;
    BlkAllocConfig& operator=(const BlkAllocConfig&) = default;
    BlkAllocConfig& operator=(BlkAllocConfig&&) noexcept = delete;
    virtual ~BlkAllocConfig() = default;

    void set_blk_size(const uint32_t blk_size) { m_blk_size = blk_size; }
    [[nodiscard]] uint32_t get_blk_size() const { return m_blk_size; }

    void set_total_blks(const blk_cap_t cap) { m_capacity = cap; }
    [[nodiscard]] blk_cap_t get_total_blks() const { return m_capacity; }

    void set_blks_per_portion(const blk_cap_t pg_per_portion) { m_blks_per_portion = pg_per_portion; }
    [[nodiscard]] blk_cap_t get_blks_per_portion() const { return m_blks_per_portion; }

    [[nodiscard]] blk_cap_t get_total_portions() const { return (get_total_blks() - 1) / get_blks_per_portion() + 1; }

    void set_auto_recovery(const bool auto_recovery) { m_auto_recovery = auto_recovery; }
    [[nodiscard]] bool get_auto_recovery() const { return m_auto_recovery; }

    [[nodiscard]] const std::string& get_name() const { return m_unique_name; }

    [[nodiscard]] virtual std::string to_string() const {
        return fmt::format("BlkSize={} TotalBlks={} BlksPerPortion={} auto_recovery={}", get_blk_size(),
                           get_total_blks(), get_blks_per_portion(), get_auto_recovery());
    }
};

VENUM(BlkOpStatus, uint8_t,
      NONE = 0,            // Default no status
      SUCCESS = 1u << 0,   // Success
      FAILED = 1u << 1,    // Generic failure
      SPACEFULL = 1u << 2, // Space full failure
      PARTIAL_FAILED = 1u << 3);

ENUM(BlkAllocatorState, uint8_t, WAITING, SWEEP_SCHEDULED, SWEEPING, EXITING, DONE);

/* Hints for various allocators */
struct blk_alloc_hints {
    blk_alloc_hints() :
            desired_temp{0},
            dev_id_hint{-1},
            can_look_for_other_dev{true},
            is_contiguous{false},
            multiplier{1},
            max_blks_per_entry{BlkId::max_blks_in_op()} {}

    blk_temp_t desired_temp;     // Temperature hint for the device
    int dev_id_hint;             // which physical device to pick (hint if any) -1 for don't care
    bool can_look_for_other_dev; // If alloc on device not available can I pick other device
    bool is_contiguous;
    uint32_t multiplier;         // blks allocated in a blkid should be a multiple of multiplier
    uint32_t max_blks_per_entry; // Number of blks on every entry
#ifdef _PRERELEASE
    bool error_simulate = false; // can error simulate happen
#endif
};

static constexpr blk_temp_t default_temperature() { return 1; }

class BlkAllocPortion {
private:
    mutable std::mutex m_blk_lock;
    blk_num_t m_portion_num;
    blk_temp_t m_temperature;
    blk_num_t m_available_blocks;

public:
    BlkAllocPortion(const blk_temp_t temp = default_temperature()) : m_temperature(temp) {}
    ~BlkAllocPortion() = default;
    BlkAllocPortion(const BlkAllocPortion&) = delete;
    BlkAllocPortion(BlkAllocPortion&&) noexcept = delete;
    BlkAllocPortion& operator=(const BlkAllocPortion&) = delete;
    BlkAllocPortion& operator=(BlkAllocPortion&&) noexcept = delete;

    auto portion_auto_lock() const { return std::scoped_lock< std::mutex >(m_blk_lock); }
    void set_portion_num(const blk_num_t portion_num) { m_portion_num = portion_num; }
    [[nodiscard]] blk_num_t get_portion_num() const { return m_portion_num; }
    void set_available_blocks(const blk_num_t available_blocks) { m_available_blocks = available_blocks; }
    [[nodiscard]] blk_num_t get_available_blocks() const { return m_available_blocks; }
    [[maybe_unused]] blk_num_t decrease_available_blocks(const blk_num_t count) {
        return (m_available_blocks -= count);
    }
    [[maybe_unused]] blk_num_t increase_available_blocks(const blk_num_t count) {
        return (m_available_blocks += count);
    }
    void set_temperature(const blk_temp_t temp) { m_temperature = temp; }
    [[nodiscard]] blk_temp_t temperature() const { return m_temperature; }

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
 * 2. manual recovery :- disk bit map is not persisted. Consumers have to scan its index table to set blks allocated.
 * It is used meta blk manager.
 * Base class manages disk_bitmap as it is common to all blk allocator.
 *
 * Disk bitmap is persisted only during checkpoints. These two things always be true while disk bitmap is persisting
 * 1. It contains atleast all the blks allocated upto that checkpoint. It can contain blks allocated for next
 *    checkpoints also.
 * 2. It contains blks freed only upto that checkpoint.
 */

class BlkAllocator {
public:
    BlkAllocator(const BlkAllocConfig& cfg, const uint32_t id = 0) : m_cfg{cfg}, m_chunk_id{(chunk_num_t)id} {
        m_blk_portions = std::make_unique< BlkAllocPortion[] >(cfg.get_total_portions());
        for (blk_num_t index{0}; index < cfg.get_total_portions(); ++index) {
            m_blk_portions[index].set_portion_num(index);
            m_blk_portions[index].set_available_blocks(m_cfg.get_blks_per_portion());
        }
        m_auto_recovery = cfg.get_auto_recovery();
        m_disk_bm = std::make_unique< sisl::Bitset >(cfg.get_total_blks(), id, HS_STATIC_CONFIG(drive_attr.align_size));
        // NOTE:  Blocks per portion must be modulo word size so locks do not fall on same word
        assert(m_cfg.get_blks_per_portion() % m_disk_bm->word_size() == 0);
    }
    BlkAllocator(const BlkAllocator&) = delete;
    BlkAllocator(BlkAllocator&&) noexcept = delete;
    BlkAllocator& operator=(const BlkAllocator&) = delete;
    BlkAllocator& operator=(BlkAllocator&&) noexcept = delete;

    virtual ~BlkAllocator() = default;

    [[nodiscard]] sisl::Bitset* get_disk_bm() { return m_disk_bm.get(); }
    [[nodiscard]] const sisl::Bitset* get_disk_bm_const() const { return m_disk_bm.get(); };

    void set_disk_bm(std::unique_ptr< sisl::Bitset > recovered_bm) {
        BLKALLOC_LOG(INFO, "Persistent bitmap of size={} recovered", recovered_bm->size());
        m_disk_bm = std::move(recovered_bm);
    }

    [[nodiscard]] BlkAllocPortion* get_blk_portion(const blk_num_t portion_num) {
        HS_DEBUG_ASSERT_LT(portion_num, m_cfg.get_total_portions(), "Portion num is not in range");
        return &m_blk_portions[portion_num];
    }

    virtual void inited() {
        if (!m_inited) {
            m_alloced_blk_count.fetch_add(m_disk_bm->get_set_count(), std::memory_order_relaxed);
            if (!m_auto_recovery) { m_disk_bm.reset(); }
            m_inited = true;
        }
    }

    void incr_alloced_blk_count(const blk_count_t nblks) {
        m_alloced_blk_count.fetch_add(nblks, std::memory_order_relaxed);
    }
    void decr_alloced_blk_count(const blk_count_t nblks) {
        m_alloced_blk_count.fetch_sub(nblks, std::memory_order_relaxed);
    }
    [[nodiscard]] int64_t get_alloced_blk_count() const { return m_alloced_blk_count.load(std::memory_order_acquire); }

    [[nodiscard]] bool is_blk_alloced_on_disk(const BlkId& b, const bool use_lock = false) const {
        if (!m_auto_recovery) {
            return true; // nothing to compare. So always return true
        }
        auto bits_set{[this, &b]() {
            // No need to set in cache if it is not recovered. When recovery is complete we copy the disk_bm to cache
            // bm.
            if (!m_disk_bm->is_bits_set(b.get_blk_num(), b.get_nblks())) {
                BLKALLOC_ASSERT(RELEASE, 0, "Expected bits to set");
                return false;
            }
            return true;
        }};
        if (use_lock) {
            const BlkAllocPortion* const portion{blknum_to_portion_const(b.get_blk_num())};
            auto lock{portion->portion_auto_lock()};
            return bits_set();
        } else {
            return bits_set();
        }
    }

    /* It is used during recovery in both mode :- auto recovery and manual recovery
     * It is also used in normal IO during auto recovery mode.
     */
    BlkAllocStatus alloc_on_disk(const BlkId& in_bid) {
        /* enable this assert later when reboot is supported */
        // assert(m_auto_recovery || !m_inited);
        if (!m_auto_recovery && m_inited) { return BlkAllocStatus::FAILED; }
        BlkAllocPortion* const portion{blknum_to_portion(in_bid.get_blk_num())};
        {
            auto lock{portion->portion_auto_lock()};
            if (m_inited) {
                BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_reset(in_bid.get_blk_num(), in_bid.get_nblks()),
                                "Expected disk blks to reset");
            }
            get_disk_bm()->set_bits(in_bid.get_blk_num(), in_bid.get_nblks());
            portion->decrease_available_blocks(in_bid.get_nblks());
            BLKALLOC_LOG(DEBUG, "blks allocated {} chunk number {}", in_bid.to_string(), m_chunk_id);
        }
        return BlkAllocStatus::SUCCESS;
    };

    void free_on_disk(const BlkId& b) {
        /* this api should be called only when auto recovery is enabled */
        assert(m_auto_recovery);
        BlkAllocPortion* const portion{blknum_to_portion(b.get_blk_num())};
        {
            auto lock{portion->portion_auto_lock()};
            if (m_inited) {
                /* During recovery we might try to free the entry which is already freed while replaying the journal,
                 * This assert is valid only post recovery.
                 */
                if (!get_disk_bm()->is_bits_set(b.get_blk_num(), b.get_nblks())) {
                    BLKALLOC_LOG(DEBUG, "bit not set {} nblks{} chunk number {}", b.get_blk_num(), b.get_nblks(),
                                 m_chunk_id);
                    for (uint32_t i = 0; i < b.get_nblks(); ++i) {
                        if (!get_disk_bm()->is_bits_set(b.get_blk_num() + i, 1)) {
                            BLKALLOC_LOG(DEBUG, "bit not set {}", b.get_blk_num() + i);
                        }
                    }
                    BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_set(b.get_blk_num(), b.get_nblks()),
                                    "Expected disk bits to set blk num {} num blks {}", b.get_blk_num(), b.get_nblks());
                }
            }
            get_disk_bm()->reset_bits(b.get_blk_num(), b.get_nblks());
            portion->increase_available_blocks(b.get_nblks());
        }
    }

    /* CP start is called when all its consumers have purged their free lists and now want to persist the
     * disk bitmap.
     */
    [[nodiscard]] sisl::byte_array cp_start([[maybe_unused]] const std::shared_ptr< blkalloc_cp >& id) {
        return (m_disk_bm->serialize());
    }

    virtual BlkAllocStatus alloc(BlkId& bid) = 0;
    virtual BlkAllocStatus alloc(const blk_count_t nblks, const blk_alloc_hints& hints,
                                 std::vector< BlkId >& out_blkid) = 0;
    virtual void free(const std::vector< BlkId >& blk_ids) = 0;
    virtual void free(const BlkId& id) = 0;
    [[nodiscard]] virtual blk_cap_t get_available_blks() const = 0;
    [[nodiscard]] virtual blk_cap_t get_used_blks() const = 0;
    [[nodiscard]] virtual bool is_blk_alloced(const BlkId& b, const bool use_lock = false) const = 0;
    [[nodiscard]] virtual std::string to_string() const = 0;

    [[nodiscard]] virtual const BlkAllocConfig& get_config() const { return m_cfg; }
    [[nodiscard]] blk_num_t blknum_to_portion_num(const blk_num_t blknum) const {
        return blknum / get_config().get_blks_per_portion();
    }

    [[nodiscard]] BlkAllocPortion* blknum_to_portion(const blk_num_t blknum) {
        return &m_blk_portions[blknum_to_portion_num(blknum)];
    }

    [[nodiscard]] const BlkAllocPortion* blknum_to_portion_const(const blk_num_t blknum) const {
        return &m_blk_portions[blknum_to_portion_num(blknum)];
    }

protected:
    BlkAllocConfig m_cfg;
    bool m_inited{false};
    chunk_num_t m_chunk_id;

private:
    std::unique_ptr< BlkAllocPortion[] > m_blk_portions;
    std::unique_ptr< sisl::Bitset > m_disk_bm{nullptr};
    std::atomic< int64_t > m_alloced_blk_count{0};
    bool m_auto_recovery{false};
};

/* FixedBlkAllocator is a fast allocator where it allocates only 1 size block and ALL free blocks are cached instead of
 * selectively caching few blks which are free. Thus there is no sweeping of bitmap or other to refill the cache. It
 * does not support temperature of blocks and allocates simply on first come first serve basis
 */
class FixedBlkAllocator : public BlkAllocator {
public:
    FixedBlkAllocator(const BlkAllocConfig& cfg, const bool init, const chunk_num_t chunk_id);
    FixedBlkAllocator(const FixedBlkAllocator&) = delete;
    FixedBlkAllocator(FixedBlkAllocator&&) noexcept = delete;
    FixedBlkAllocator& operator=(const FixedBlkAllocator&) = delete;
    FixedBlkAllocator& operator=(FixedBlkAllocator&&) noexcept = delete;
    ~FixedBlkAllocator() override = default;

    BlkAllocStatus alloc(BlkId& bid) override;
    BlkAllocStatus alloc(const blk_count_t nblks, const blk_alloc_hints& hints,
                         std::vector< BlkId >& out_blkid) override;
    void free(const std::vector< BlkId >& blk_ids) override;
    void free(const BlkId& b) override;
    void inited() override;

    [[nodiscard]] blk_cap_t get_available_blks() const override;
    [[nodiscard]] blk_cap_t get_used_blks() const override;
    [[nodiscard]] bool is_blk_alloced(const BlkId& in_bid, const bool use_lock = false) const override;
    [[nodiscard]] std::string to_string() const override;

private:
    [[nodiscard]] blk_num_t init_portion(BlkAllocPortion* portion, const blk_num_t start_blk_num);

private:
    folly::MPMCQueue< BlkId > m_blk_q;
};

struct blkalloc_cp {
public:
    bool suspend = false;
    std::vector< blkid_list_ptr > blkid_list_vector;
    HomeStoreBaseSafePtr m_hs{HomeStoreBase::safe_instance()};

public:
    [[nodiscard]] bool is_suspend() const { return suspend; }
    void suspend_cp() { suspend = true; }
    void resume_cp() { suspend = false; }
    void free_blks(const blkid_list_ptr& list) {
        auto it = list->begin(true /* latest */);
        BlkId* bid;
        while ((bid = list->next(it)) != nullptr) {
            auto chunk{m_hs->get_device_manager()->get_chunk(bid->get_chunk_num())};
            auto ba{chunk->get_blk_allocator()};
            ba->free_on_disk(*bid);
        }
        blkid_list_vector.push_back(list);
    }

    blkalloc_cp() = default;
    ~blkalloc_cp() {
        /* free all the blkids in the cache */
        for (auto& list : blkid_list_vector) {
            BlkId* bid;
            auto it = list->begin(false /* latest */);
            while ((bid = list->next(it)) != nullptr) {
                auto chunk{m_hs->get_device_manager()->get_chunk(bid->get_chunk_num())};
                chunk->get_blk_allocator()->free(*bid);
                auto page_size{chunk->get_blk_allocator()->get_config().get_blk_size()};
                ResourceMgr::dec_free_blk(bid->data_size(page_size));
            }
            list->clear();
        }
    }
};

} // namespace homestore
#endif
