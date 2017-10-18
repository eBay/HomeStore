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
#include "omds/bitmap/bitset.hpp"
#include "omds/btree/mem_btree.hpp"

using namespace std;

namespace omstorage {

class BlkAllocConfig {
private:
    uint32_t m_blk_size;
    uint64_t m_nblks;

public:
    explicit BlkAllocConfig() : BlkAllocConfig(8192, 0) {}
    explicit BlkAllocConfig(uint64_t nblks) : BlkAllocConfig(8192, nblks) {}

    BlkAllocConfig(uint32_t blk_size, uint64_t nblks) :
            m_blk_size(blk_size),
            m_nblks(nblks) {
    }

    void set_blk_size(uint64_t blk_size) {
        m_blk_size = blk_size;
    }

    uint32_t get_blk_size() const {
        return m_blk_size;
    }

    void set_total_blks(uint32_t nblks) {
        m_nblks = nblks;
    }

    uint64_t get_total_blks() const {
        return m_nblks;
    }

    virtual std::string to_string() const {
        std::stringstream ss;
        ss << "Blksize=" << get_blk_size() << " TotalBlks=" << get_total_blks();
        return ss.str();
    }
};

typedef enum {
    BLK_ALLOC_NONE = 0,
    BLK_ALLOC_SUCCESS = 1 << 0,   // Success
    BLK_ALLOC_FAILED = 1 << 1,   // Failed
    BLK_ALLOC_REQMORE = 1 << 2,   // Indicate that we need more
    BLK_ALLOC_SPACEFULL = 1 << 3,
    BLK_ALLOC_INVALID_DEV = 1 << 4,
} BlkAllocStatus;

typedef enum {
    BLK_OP_NONE = 0,
    BLK_OP_SUCCESS = 1 << 0,   // Success
    BLK_OP_FAILED = 1 << 1,   // Failed
    BLK_OP_SPACEFULL = 1 << 2,
    BLK_OP_PARTIAL_FAILED = 1 << 3,
} BlkOpStatus;

typedef enum {
    BLK_ALLOCATOR_DONE = 0,
    BLK_ALLOCATOR_WAIT_ALLOC = 1,
    BLK_ALLOCATOR_ALLOCATING = 2,
    BLK_ALLOCATOR_EXITING = 3,
} BlkAllocatorState;

class BlkAllocator
{
protected:
    BlkAllocConfig m_cfg;

public:
    explicit BlkAllocator(BlkAllocConfig &cfg) {
        m_cfg = cfg;
    }

    virtual ~BlkAllocator() = default;

    virtual BlkAllocStatus alloc(uint32_t size, uint32_t desired_temp, Blk *outBlk) = 0;
    virtual void free(Blk &b) = 0;
    virtual std::string to_string() const = 0;

    virtual const BlkAllocConfig &get_config() const {
        return m_cfg;
    }
};

/* FixedBlkAllocator is a fast allocator where it allocates only 1 size block and ALL free blocks are cached instead of
 * selectively caching few blks which are free. Thus there is no sweeping of bitmap or other to refill the cache. It
 * does not support temperature of blocks and allocates simply on first come first serve basis
 */
class FixedBlkAllocator : public BlkAllocator {
private:
    struct __fixed_blk_node {
#ifndef NDEBUG
        blkid32_t this_blk_id;
#endif
        blkid32_t next_blk;
    } __attribute__ ((__packed__));

    struct __top_blk {
        struct blob {
            uint32_t gen;
            blkid32_t top_blk_id;
        } __attribute__ ((__packed__));

        blob b;

        __top_blk(uint64_t id) {
            memcpy(&b, &id, sizeof(uint64_t));
        }

        __top_blk(uint32_t gen, blkid32_t blk_id) {
            b.gen = gen;
            b.top_blk_id = blk_id;
        }

        uint64_t to_integer() const {
            uint64_t x;
            memcpy(&x, &b, sizeof(uint64_t));
            return x;
        }

        uint32_t get_gen() const {
            return b.gen;
        }

        blkid32_t get_top_blk_id() const {
            return b.top_blk_id;
        }

        void set_gen(uint32_t gen) {
            b.gen = gen;
        }

        void set_top_blk_id(blkid32_t p) {
            b.top_blk_id = p;
        }
    } __attribute__ ((__packed__));

    std::atomic< uint64_t > m_top_blk_id;

#ifndef NDEBUG
    std::atomic< uint32_t > m_nfree_blks;
#endif

    __fixed_blk_node *m_blk_nodes;

public:
    explicit FixedBlkAllocator(BlkAllocConfig &cfg);
    ~FixedBlkAllocator() override;

    BlkAllocStatus alloc(uint32_t size, uint32_t desired_temp, Blk *out_blk) override;
    void free(Blk &b) override;
    std::string to_string() const override;
private:
    void free_blk(blkid32_t blk_id);
};

} // namespace omstorage
#endif
