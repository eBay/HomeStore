//#include "BitMap.h"
#include <iostream>
#include <unistd.h>
#include <gtest/gtest.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <thread>
#include <random>
#include "blk_allocator.h"
#include "varsize_blk_allocator.h"

SDS_LOGGING_INIT(btree_structures, btree_nodes, btree_generics, varsize_blk_alloc)
THREAD_BUFFER_INIT;

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
                fprintf(stderr, "Allocated block num = %lu size = %d chunk_num = %d\n", blks[i].get_id(), blks[i].get_nblks(), blks[i].get_chunk_num());
            } else {
                LOGERROR("Block Alloc failed with space full after {} allocations", alloced);
                break;
            }
        }

        LOGINFO("Allocated {} blocks, Allocator state: {}", alloced, allocator->to_string());
        for (i = 0; i < alloced; i++) {
            allocator->free(blks[i]);
        }
        LOGINFO("Freed {} blocks: Allocator state: {}", alloced, allocator->to_string());
        LOGINFO("Reallocating blocks");
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
        BlkAllocConfig fixed_cfg(m_blk_size, m_total_space / m_blk_size, "");
        m_fixed_allocator = new FixedBlkAllocator(fixed_cfg, true);
    }

    ~FixedBlkAllocatorTest() {
        delete(m_fixed_allocator);
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

            //LOGINFO("Allocated block num = {} size = {} chunk num = {}",
            //         bid.get_id(),
            //         bid.get_nblks(),
            //         bid.get_chunk_num());
        }
    }

    static void free_fixed_blocks(FixedBlkAllocatorTest *test, const std::vector<BlkId> &blist) {
        for (auto &bid : blist) {
            test->m_fixed_allocator->free(bid);
        }
    }
};

#define NTHREADS 1

TEST_F(FixedBlkAllocatorTest, alloc_free_test) {
    std::array<std::thread *, NTHREADS> thrs;
    std::vector<BlkId> blkids[NTHREADS];

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(alloc_fixed_blocks, this, &blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    for (auto i = 0U; i < NTHREADS; i++) {
        delete (thrs[i]);
    }

    EXPECT_EQ(m_alloced_count.load(), max_blks());
    EXPECT_EQ(m_fixed_allocator->total_free_blks(), 0u);

    LOGINFO("Allocated {} blocks, Allocator state: {}", m_alloced_count.load(), m_fixed_allocator->to_string());

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(free_fixed_blocks, this, blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    for (auto i = 0U; i < NTHREADS; i++) {
        delete (thrs[i]);
    }
    LOGINFO("Freed all blocks: Allocator state: {}", m_fixed_allocator->to_string());
    EXPECT_EQ(m_fixed_allocator->total_free_blks(), max_blks());
    LOGINFO("FixedSizeBlkAllocator test done");
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
            m_total_space(1 * 1024 * 1024),
            m_blk_size(512) {
        VarsizeBlkAllocConfig var_cfg(m_blk_size, m_total_space / m_blk_size, "");
        var_cfg.set_max_cache_blks(1000);
        var_cfg.set_blk_size(m_blk_size);
        var_cfg.set_phys_page_size(m_blk_size);
        var_cfg.set_total_segments(1);
        var_cfg.set_blks_per_portion(64);
        var_cfg.set_blks_per_temp_group(10);
        std::vector<uint32_t> slab_limits(4, 0);
        std::vector<float> slab_weights(5, 0.2);
        for (auto i = 0U; i < slab_limits.size(); i++) {
            slab_limits[i] = (8192*(1<<i))/var_cfg.get_blk_size();
        }
        var_cfg.set_slab(slab_limits, slab_weights);
        m_varsize_allocator = new VarsizeBlkAllocator(var_cfg, true);
    }

    ~VarsizeBlkAllocatorTest() {
        delete(m_varsize_allocator);
    }

    uint32_t max_blks() const {
        return m_total_space/m_blk_size;
    }

    static void alloc_var_blocks(VarsizeBlkAllocatorTest *test,
                    uint8_t nblks, std::vector<BlkId> *out_blist) {
        while (true) {
            BlkId bid;
            blk_alloc_hints hints;
            hints.desired_temp = 0;

            BlkAllocStatus ret = test->m_varsize_allocator->alloc(nblks, hints, &bid);
            EXPECT_TRUE((ret == BLK_ALLOC_SUCCESS) || (ret == BLK_ALLOC_SPACEFULL));
            if (ret == BLK_ALLOC_SPACEFULL) {
                break;
            }
            out_blist->push_back(bid);
            test->m_alloced_count.fetch_add(nblks);
        }
    }

    static void free_var_blocks(VarsizeBlkAllocatorTest *test, const std::vector<BlkId> &blist) {
        for (auto &bid : blist) {
            //testing::FLAGS_gtest_death_test_style = "threadsafe";
            //ASSERT_DEATH(test->m_varsize_allocator->free(bid); , ".*Assertion.*");
            test->m_varsize_allocator->free(bid);
        }
    }
};

TEST_F(VarsizeBlkAllocatorTest, alloc_free_test) {
    std::array<std::thread *, NTHREADS> thrs;
    std::vector<BlkId> blkids[NTHREADS];

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(alloc_var_blocks, this, 1, &blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    for (auto i = 0U; i < NTHREADS; i++) {
        delete (thrs[i]);
    }
    EXPECT_EQ(m_alloced_count.load(), max_blks());
    //EXPECT_EQ(m_varsize_allocator->total_free_blks(), 0);

    LOGINFO("Allocated {} blocks, Allocator state: {}",
            m_alloced_count.load(), m_varsize_allocator->to_string());

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(free_var_blocks, this, blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    for (auto i = 0U; i < NTHREADS; i++) {
        delete (thrs[i]);
    }
    LOGINFO("Freed all blocks: Allocator state: {}", m_varsize_allocator->to_string());
    //EXPECT_EQ(m_varsize_allocator->total_free_blks(), max_blks());
    LOGINFO("VarsizeBlkAllocator test done");
}

TEST_F(VarsizeBlkAllocatorTest, alloc_free_nblks_test) {
    std::array<std::thread *, NTHREADS> thrs;
    std::vector<BlkId> blkids[NTHREADS];

    std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(8, 64);

    for (auto i = 0U; i < NTHREADS; i++) {
        auto nblks = (uint8_t) distribution(generator);
        thrs[i] = new std::thread(alloc_var_blocks, this, nblks, &blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    for (auto i = 0U; i < NTHREADS; i++) {
        delete (thrs[i]);
    }
    EXPECT_EQ(m_alloced_count.load(), max_blks());
    //EXPECT_EQ(m_varsize_allocator->total_free_blks(), 0);

    LOGINFO("Allocated {} blocks, Allocator state: {}",
            m_alloced_count.load(), m_varsize_allocator->to_string());

    for (auto i = 0U; i < NTHREADS; i++) {
        thrs[i] = new std::thread(free_var_blocks, this, blkids[i]);
    }
    for (auto t : thrs) {
        t->join();
    }

    for (auto i = 0U; i < NTHREADS; i++) {
        delete (thrs[i]);
    }
    LOGINFO("Freed all blocks: Allocator state: {}", m_varsize_allocator->to_string());
    //EXPECT_EQ(m_varsize_allocator->total_free_blks(), max_blks());
    LOGINFO("VarsizeBlkAllocator test done");
}

SDS_OPTIONS_ENABLE(logging)
extern bool blk_alloc_test;
int main(int argc, char *argv[]) {
#ifndef NDEBUG
    blk_alloc_test = true;
#endif
    SDS_OPTIONS_LOAD(argc, argv, logging)
    testing::InitGoogleTest(&argc, argv);
    sds_logging::SetLogger("test_blkalloc");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    return RUN_ALL_TESTS();
}
