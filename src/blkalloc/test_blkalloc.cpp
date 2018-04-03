//#include "BitMap.h"
#include <iostream>
#include <unistd.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <thread>
#include "blk_allocator.h"
#include "varsize_blk_allocator.h"

using namespace std;
using namespace homestore;

void allocate_blocks(BlkAllocator *allocator)
{
    int i;
    int alloced;

    int iter = 0;

    while (++iter <= 2) {
        BlkId blks[4000];

        for (i = 0, alloced = 0; i < 4000; i++, alloced++) {
            blk_alloc_hints hints;
            hints.desired_temp = 0;
            BlkAllocStatus ret = allocator->alloc(1, hints, &blks[i]);

            if (ret == BLK_ALLOC_SUCCESS) {
                fprintf(stderr, "Allocated block num = %llu size = %d chunk_num = %d\n", blks[i].get_id(), blks[i].get_nblks(), blks[i].get_chunk_num());
            } else {
                LOG(ERROR) << "Block Alloc failed with space full after " << alloced << " allocations";
                break;
            }
        }

        LOG(INFO) << "Allocated " << alloced << " blocks, Allocator state: " << allocator->to_string();
        for (i = 0; i < alloced; i++) {
            allocator->free(blks[i]);
        }
        LOG(INFO) << "Freed " << alloced << " blocks: Allocator state: " << allocator->to_string();
        LOG(INFO) << "Reallocating blocks";
    }
}

struct FixedBlkAllocatorTest : public testing::Test {
protected:
    std::atomic< uint64_t > m_alloced_count;
    uint64_t m_total_space;
    uint32_t m_blk_size;
    FixedBlkAllocator *m_fixed_allocator;

public:
    FixedBlkAllocatorTest() :
            m_alloced_count(0),
            m_total_space(1 * 1024 * 1024),
            m_blk_size(8 * 1024) {
        BlkAllocConfig fixed_cfg(m_blk_size, m_total_space / m_blk_size);
        m_fixed_allocator = new FixedBlkAllocator(fixed_cfg);
    }

    uint32_t max_blks() const {
        return m_total_space/m_blk_size;
    }

    static void alloc_fixed_blocks(FixedBlkAllocatorTest *test, std::vector<BlkId> *out_blist) {
        int i;
        int alloced;
        int iter = 0;

        while (true) {
            BlkId bid;
            blk_alloc_hints hints;
            hints.desired_temp = 0;

            BlkAllocStatus ret = test->m_fixed_allocator->alloc(1, hints, &bid);
            EXPECT_TRUE((ret == BLK_ALLOC_SUCCESS) || (ret == BLK_ALLOC_SPACEFULL));
            if (ret == BLK_ALLOC_SPACEFULL) {
                break;
            }
            out_blist->push_back(bid);
            test->m_alloced_count.fetch_add(1);

            //LOG(INFO) << "Allocated block num = " << bid.get_id() << " size = " << bid.get_nblks()
            //          << " chunk num = " << bid.get_chunk_num();
        }
    }

    static void free_fixed_blocks(FixedBlkAllocatorTest *test, const std::vector<BlkId> &blist) {
        for (auto &bid : blist) {
            test->m_fixed_allocator->free(bid);
        }
    }
};

#define NTHREADS 4

TEST_F(FixedBlkAllocatorTest, alloc_free_test) {
    std::array<std::thread *, NTHREADS> thrs;
    std::vector<BlkId> blkids[NTHREADS];

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(alloc_fixed_blocks, this, &blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    EXPECT_EQ(m_alloced_count.load(), max_blks());
    EXPECT_EQ(m_fixed_allocator->total_free_blks(), 0);

    LOG(INFO) << "Allocated " << m_alloced_count.load() << " blocks, Allocator state: "
              << m_fixed_allocator->to_string();

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(free_fixed_blocks, this, blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    LOG(INFO) << "Freed all blocks: Allocator state: " << m_fixed_allocator->to_string();
    EXPECT_EQ(m_fixed_allocator->total_free_blks(), max_blks());

    LOG(INFO) << "Do a realloc blocks";
    m_alloced_count.store(0);
    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(alloc_fixed_blocks, this, &blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    EXPECT_EQ(m_alloced_count.load(), max_blks());
    EXPECT_EQ(m_fixed_allocator->total_free_blks(), 0);
    LOG(INFO) << "ReAlloced " << m_alloced_count.load() << " blocks, Allocator state: "
              << m_fixed_allocator->to_string();
    LOG(INFO) << "FixedSizeBlkAllocator test done";
}

struct VarsizeBlkAllocatorTest : public testing::Test {
protected:
    std::atomic< uint64_t > m_alloced_count;
    uint64_t m_total_space;
    uint32_t m_blk_size;
    VarsizeBlkAllocator *m_varsize_allocator;

public:
    VarsizeBlkAllocatorTest() :
            m_alloced_count(0),
            m_total_space(16 * 1024 * 1024),
            m_blk_size(8 * 1024) {
        VarsizeBlkAllocConfig var_cfg(m_blk_size, m_total_space / m_blk_size);
        var_cfg.set_max_cache_blks(100);
        var_cfg.set_page_size(m_blk_size);
        var_cfg.set_total_segments(1);
        var_cfg.set_pages_per_portion(64);
        var_cfg.set_pages_per_temp_group(10);
        m_varsize_allocator = new VarsizeBlkAllocator(var_cfg);
    }

    uint32_t max_blks() const {
        return m_total_space/m_blk_size;
    }

    static void alloc_var_blocks(VarsizeBlkAllocatorTest *test, std::vector<BlkId> *out_blist) {
        int i;
        int alloced;
        int iter = 0;

        while (true) {
            BlkId bid;
            blk_alloc_hints hints;
            hints.desired_temp = 0;

            BlkAllocStatus ret = test->m_varsize_allocator->alloc(1, hints, &bid);
            EXPECT_TRUE((ret == BLK_ALLOC_SUCCESS) || (ret == BLK_ALLOC_SPACEFULL));
            if (ret == BLK_ALLOC_SPACEFULL) {
                break;
            }
            out_blist->push_back(bid);
            test->m_alloced_count.fetch_add(1);

            //LOG(INFO) << "Allocated block num = " << bid.get_id() << " size = " << bid.get_nblks()
            //          << " chunk num = " << bid.get_chunk_num();
        }
    }

    static void free_var_blocks(VarsizeBlkAllocatorTest *test, const std::vector<BlkId> &blist) {
        for (auto &bid : blist) {
            test->m_varsize_allocator->free(bid);
        }
    }
};

TEST_F(VarsizeBlkAllocatorTest, alloc_free_test) {
    std::array<std::thread *, NTHREADS> thrs;
    std::vector<BlkId> blkids[NTHREADS];

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(alloc_var_blocks, this, &blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    EXPECT_EQ(m_alloced_count.load(), max_blks());
    //EXPECT_EQ(m_varsize_allocator->total_free_blks(), 0);

    LOG(INFO) << "Allocated " << m_alloced_count.load() << " blocks, Allocator state: "
              << m_varsize_allocator->to_string();

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(free_var_blocks, this, blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    LOG(INFO) << "Freed all blocks: Allocator state: " << m_varsize_allocator->to_string();
    //EXPECT_EQ(m_varsize_allocator->total_free_blks(), max_blks());
    LOG(INFO) << "VarsizeBlkAllocator test done";
}

INIT_VMODULES(BTREE_VMODULES);

int main(int argc, char *argv[]) {
    InithomedsLogging(argv[0], BTREE_VMODULES);

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
