/*
 * BlkAllocator.h
 *
 *  Created on: Aug 09, 2016
 *      Author: hkadayam
 */

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include "blk.h"
#include <cassert>
#include <vector>
#include <string>
#include <thread>
#include <sstream>
#include "engine/homeds/bitmap/bitset.hpp"
#include "engine/homeds/btree/btree.hpp"
#include <folly/ThreadLocal.h>
#include <boost/range/irange.hpp>
#include <fds/bitset.hpp>
#include "engine/meta/meta_blks_mgr.hpp"
#include "engine/homestore_base.hpp"
#include "engine/device/device.h"

using namespace std;

namespace homestore {
#define BLKALLOC_LOG(level, mod, msg, ...) HS_SUBMOD_LOG(level, mod, , "blkalloc", m_cfg.get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_ASSERT(assert_type, cond, msg, ...)                                                                   \
    HS_SUBMOD_ASSERT(assert_type, cond, , "blkalloc", m_cfg.get_name(), msg, ##__VA_ARGS__)
#define BLKALLOC_ASSERT_CMP(assert_type, val1, cmp, val2, ...)                                                         \
    HS_SUBMOD_ASSERT_CMP(assert_type, val1, cmp, val2, , "blkalloc", m_cfg.get_name(), ##__VA_ARGS__)
#define BLKALLOC_ASSERT_NOTNULL(assert_type, val, ...)                                                                 \
    HS_SUBMOD_ASSERT_NOTNULL(assert_type, val, , "blkalloc", m_cfg.get_name(), ##__VA_ARGS__)
#define BLKALLOC_ASSERT_NULL(assert_type, val, ...)                                                                    \
    HS_SUBMOD_ASSERT_NULL(assert_type, val, , "blkalloc", m_cfg.get_name(), ##__VA_ARGS__)

struct blkalloc_cp_id;

class BlkAllocConfig {
private:
    uint32_t m_blk_size;
    uint64_t m_nblks;
    uint32_t m_blks_per_portion;
    std::string m_unique_name;
    bool m_auto_recovery = false;

public:
    explicit BlkAllocConfig(const std::string& name) : BlkAllocConfig(8192, 0, name) {}
    explicit BlkAllocConfig(uint64_t nblks) : BlkAllocConfig(8192, nblks, "") {}

    BlkAllocConfig(uint32_t blk_size = 8192, uint64_t nblks = 0, const std::string& name = "") :
            m_blk_size(blk_size), m_nblks(nblks), m_blks_per_portion(nblks), m_unique_name(name) {}

    void set_blk_size(uint64_t blk_size) { m_blk_size = blk_size; }

    uint32_t get_blk_size() const { return m_blk_size; }

    void set_total_blks(uint64_t nblks) { m_nblks = nblks; }

    uint64_t get_total_blks() const { return m_nblks; }

    const std::string& get_name() const { return m_unique_name; }

    virtual std::string to_string() const {
        std::stringstream ss;
        ss << "Blksize=" << get_blk_size() << " TotalBlks=" << get_total_blks();
        return ss.str();
    }

    //! Set Blocks per Portion
    /*!
      \param pg_per_portion an uint32 argument signifies pages per portion
      \return void
    */
    void set_blks_per_portion(uint32_t pg_per_portion) { m_blks_per_portion = pg_per_portion; }

    //! Get Blocks per Portion
    /*!
      \return blocks per portion as uint64
    */
    uint64_t get_blks_per_portion() const { return m_blks_per_portion; }

    //! Get Total Portions
    /*!
      \return portion count as uint64
    */
    uint64_t get_total_portions() const {
        assert(get_total_blks() % get_blks_per_portion() == 0);
        return get_total_blks() / get_blks_per_portion();
    }

    void set_auto_recovery(bool auto_recovery) { m_auto_recovery = auto_recovery; }
    bool get_auto_recovery() { return m_auto_recovery; }
};

enum BlkAllocStatus {
    BLK_ALLOC_NONE = 0,
    BLK_ALLOC_SUCCESS = 1 << 0, // Success
    BLK_ALLOC_FAILED = 1 << 1,  // Failed
    BLK_ALLOC_REQMORE = 1 << 2, // Indicate that we need more
    BLK_ALLOC_SPACEFULL = 1 << 3,
    BLK_ALLOC_INVALID_DEV = 1 << 4
};

enum BlkOpStatus {
    BLK_OP_NONE = 0,
    BLK_OP_SUCCESS = 1 << 0, // Success
    BLK_OP_FAILED = 1 << 1,  // Failed
    BLK_OP_SPACEFULL = 1 << 2,
    BLK_OP_PARTIAL_FAILED = 1 << 3
};

enum BlkAllocatorState {
    BLK_ALLOCATOR_DONE = 0,
    BLK_ALLOCATOR_WAIT_ALLOC = 1,
    BLK_ALLOCATOR_ALLOCATING = 2,
    BLK_ALLOCATOR_EXITING = 3
};

/* Hints for various allocators */
struct blk_alloc_hints {
    blk_alloc_hints() :
            desired_temp(0), dev_id_hint(-1), can_look_for_other_dev(true), is_contiguous(false), multiplier(1) {}

    uint32_t desired_temp;       // Temperature hint for the device
    int dev_id_hint;             // which physical device to pick (hint if any) -1 for don't care
    bool can_look_for_other_dev; // If alloc on device not available can I pick other device
    bool is_contiguous;
    uint32_t multiplier; // blks allocated in a blkid should be a multiple of multiplier
};

class BlkAllocPortion {
private:
    pthread_mutex_t m_blk_lock;

public:
    BlkAllocPortion() { pthread_mutex_init(&m_blk_lock, NULL); }

    ~BlkAllocPortion() { pthread_mutex_destroy(&m_blk_lock); }

    void lock() { pthread_mutex_lock(&m_blk_lock); }

    void unlock() { pthread_mutex_unlock(&m_blk_lock); }
};

/* We have the following design requirement it is used in auto recovery mode
 *  - Free BlkIDs should not be re allocated until its free status is persisted on disk. Reasons :-
 *          - It helps is reconstructing btree in crash as it depends on old blkid to read the data
 *          - Different volume recovery doesn't need to dependent on each other. We can volume based recovery
 *            instead of time based recovery.
 *  - Allocate BlkIDs should not be persisted until it is persisted in journal. If system crash after writing to
 *    in use bm but before writing to journal then blkid will be leak forever.
 *
 * To acheive the above requirements we free blks in two phase
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
 *        replay this entry. otherwise there will be memory leak
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
    std::vector< BlkAllocPortion > m_blk_portions;
    sisl::Bitset* m_disk_bm;

    bool m_auto_recovery = false;

protected:
    bool m_inited = false;

public:
    explicit BlkAllocator(BlkAllocConfig& cfg, uint32_t id = 0) : m_blk_portions(cfg.get_total_portions()) {
        m_auto_recovery = cfg.get_auto_recovery();
        m_disk_bm = new sisl::Bitset(cfg.get_total_blks(), id, HS_STATIC_CONFIG(disk_attr.align_size));
        m_cfg = cfg;
    }

    virtual ~BlkAllocator() {
        if (m_disk_bm) delete m_disk_bm;
    }
    sisl::Bitset* get_disk_bm() { return m_disk_bm; }
    void set_disk_bm(std::unique_ptr< sisl::Bitset > recovered_bm) {
        LOGINFO("bitmap found");
        m_disk_bm->move(*(recovered_bm.get()));
    }
    BlkAllocPortion* get_blk_portions(uint32_t portion_num) { return &(m_blk_portions[portion_num]); }

    virtual void inited() {
        if (!m_auto_recovery) {
            delete m_disk_bm;
            m_disk_bm = nullptr;
        }
        m_inited = true;
    }

    /* It is used during recovery in both mode :- auto recovery and manual recovery
     * It is also used in normal IO during auto recovery mode.
     */
    BlkAllocStatus alloc(BlkId& in_bid) {
        /* enable this assert later when reboot is supported */
        //        assert(m_auto_recovery || !m_inited);
        if (!m_auto_recovery && m_inited) { return BLK_ALLOC_FAILED; }
        BlkAllocPortion* portion = blknum_to_portion(in_bid.get_id());
        portion->lock();
        if (m_inited) {
            BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_reset(in_bid.get_id(), in_bid.get_nblks()),
                            "Expected disk blks to reset");
        }
        get_disk_bm()->set_bits(in_bid.get_id(), in_bid.get_nblks());
        portion->unlock();
        return BLK_ALLOC_SUCCESS;
    };

    void free_on_disk(const BlkId& b) {
        /* this api should be called only when auto recovery is enabled */
        assert(m_auto_recovery);
        BlkAllocPortion* portion = blknum_to_portion(b.get_id());
        portion->lock();
        if (m_inited) {
            /* During recovery we might try to free the entry which is already freed while replaying the journal,
             * This assert is valid only post recovery.
             */
            BLKALLOC_ASSERT(RELEASE, get_disk_bm()->is_bits_set(b.get_id(), b.get_nblks()),
                            "Expected disk bits to set");
        }
        get_disk_bm()->reset_bits(b.get_id(), b.get_nblks());
        portion->unlock();
    }

    /* CP start is called when all its consumers have purged their free lists and now want to persist the
     * disk bitmap.
     */
    sisl::byte_array cp_start(std::shared_ptr< blkalloc_cp_id > id) { return (m_disk_bm->serialize()); }

    virtual bool is_blk_alloced(BlkId& b) = 0;
    virtual std::string to_string() const = 0;
    virtual BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) = 0;
    virtual BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints& hints, BlkId* out_blkid,
                                 bool best_fit = false) = 0;
    virtual void free(const BlkId& id) = 0;

    virtual const BlkAllocConfig& get_config() const { return m_cfg; }
    uint64_t blknum_to_portion_num(uint64_t blknum) const { return blknum / get_config().get_blks_per_portion(); }

    BlkAllocPortion* blknum_to_portion(uint64_t blknum) { return &m_blk_portions[blknum_to_portion_num(blknum)]; }

    const BlkAllocPortion* blknum_to_portion_const(uint64_t blknum) const {
        return &m_blk_portions[blknum_to_portion_num(blknum)];
    }

protected:
    BlkAllocConfig m_cfg;
};

/* FixedBlkAllocator is a fast allocator where it allocates only 1 size block and ALL free blocks are cached instead of
 * selectively caching few blks which are free. Thus there is no sweeping of bitmap or other to refill the cache. It
 * does not support temperature of blocks and allocates simply on first come first serve basis
 */
class FixedBlkAllocator : public BlkAllocator {
private:
    struct __fixed_blk_node {
#ifndef NDEBUG
        uint32_t this_blk_id;
#endif
        uint32_t next_blk;
    } __attribute__((__packed__));

    struct __top_blk {
        struct blob {
            uint32_t gen;
            uint32_t top_blk_id;
        } __attribute__((__packed__));

        blob b;

        __top_blk(uint64_t id) { memcpy(&b, &id, sizeof(uint64_t)); }

        __top_blk(uint32_t gen, uint32_t blk_id) {
            b.gen = gen;
            b.top_blk_id = blk_id;
        }

        uint64_t to_integer() const {
            uint64_t x;
            memcpy(&x, &b, sizeof(uint64_t));
            return x;
        }

        uint32_t get_gen() const { return b.gen; }

        uint32_t get_top_blk_id() const { return b.top_blk_id; }

        void set_gen(uint32_t gen) { b.gen = gen; }

        void set_top_blk_id(uint32_t p) { b.top_blk_id = p; }
    } __attribute__((__packed__));

    std::atomic< uint64_t > m_top_blk_id;

#ifndef NDEBUG
    std::atomic< uint32_t > m_nfree_blks;
#endif

    __fixed_blk_node* m_blk_nodes;

public:
    explicit FixedBlkAllocator(BlkAllocConfig& cfg, bool init, uint32_t id);
    ~FixedBlkAllocator() override;

    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints& hints, BlkId* out_blkid, bool best_fit = false) override;
    BlkAllocStatus alloc(uint8_t nblks, const blk_alloc_hints& hints, std::vector< BlkId >& out_blkid) override;
    void free(const BlkId& b) override;
    virtual void inited() override;
    std::string to_string() const override;
    virtual bool is_blk_alloced(BlkId& in_bid);

#ifndef NDEBUG
    uint32_t total_free_blks() const { return m_nfree_blks.load(std::memory_order_relaxed); }
#endif

private:
    void free_blk(uint32_t id);
    uint32_t m_first_blk_id;
    std::mutex m_bm_mutex;
};

struct blkalloc_cp_id {
    bool suspend = false;
    uint64_t cnt;
    std::vector< blkid_list_ptr > blkid_list_vector;
    bool is_suspend() { return suspend; }
    void suspend_cp() { suspend = true; }
    void resume_cp() { suspend = false; }
    void free_blks(blkid_list_ptr list) {
        sisl::ThreadVector< BlkId >::thread_vector_iterator it;
        auto bid = list->begin(it);
        while (bid != nullptr) {
            auto chunk = HomeStoreBase::safe_instance()->get_device_manager()->get_chunk(bid->get_chunk_num());
            auto ba = chunk->get_blk_allocator();
            ba->free_on_disk(*bid);
            bid = list->next(it);
        }
        blkid_list_vector.push_back(list);
    }

    ~blkalloc_cp_id() {
        /* free all the blkids in the cache */
        for (uint32_t i = 0; blkid_list_vector.size(); ++i) {
            auto list = blkid_list_vector[i];
            sisl::ThreadVector< BlkId >::thread_vector_iterator it;
            auto bid = list->begin(it);
            while (bid != nullptr) {
                auto chunk = HomeStoreBase::safe_instance()->get_device_manager()->get_chunk(bid->get_chunk_num());
                chunk->get_blk_allocator()->free(*bid);
                bid = list->next(it);
            }
            list->erase();
        }
    }
};

} // namespace homestore
#endif
