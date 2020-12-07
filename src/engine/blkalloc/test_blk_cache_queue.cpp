#include <gtest/gtest.h>
#include <utility/thread_buffer.hpp>
#include <sds_options/options.h>
#include <sds_logging/logging.h>
#include <cmath>
#include "engine/common/homestore_header.hpp"

#include "blk_cache_queue.h"
#include "varsize_blk_allocator.h"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT;

using namespace homestore;

std::unique_ptr< BlkAllocMetrics > g_metrics;

struct BlkCacheQueueTest : public testing::Test {
protected:
    std::unique_ptr< FreeBlkCacheQueue > m_fb_cache;
    SlabCacheConfig m_cfg;
    uint32_t m_nslabs{0};
    uint32_t m_count_per_slab{0};

public:
    BlkCacheQueueTest() = default;
    virtual ~BlkCacheQueueTest() override = default;

    void SetUp(uint32_t nslabs, uint32_t count_per_slab) {
        m_nslabs = nslabs;
        m_count_per_slab = count_per_slab;

        for (uint32_t i{0}; i < m_nslabs; ++i) {
            SlabCacheConfig::_slab_config s_cfg;
            s_cfg.slab_size = (1 << i);
            s_cfg.max_entries = m_count_per_slab;
            s_cfg.refill_threshold_pct = 50;
            s_cfg.m_level_distribution_pct = {50.0, 50.0};
            m_cfg.m_per_slab_cfg.push_back(s_cfg);
        }
        m_fb_cache = std::make_unique< FreeBlkCacheQueue >(m_cfg, g_metrics.get());

        fill_cache();
    }

    void fill_cache() {
        LOGINFO("Filling cache with {} slabs and {} entries per slab", m_nslabs, m_count_per_slab);

        auto fill_session = m_fb_cache->create_cache_fill_session(true /* fill_entire_cache */);
        uint32_t blk_id = 0;
        for (const auto& slab_cfg : m_cfg.m_per_slab_cfg) {
            for (auto i = 0u; i < slab_cfg.max_entries; ++i) {
                blk_cache_fill_req fill_req;
                fill_req.start_blk_num = blk_id;
                fill_req.nblks = slab_cfg.slab_size;
                fill_req.preferred_level = 1;
                auto nblks_added = m_fb_cache->try_fill_cache(fill_req, *fill_session);
                ASSERT_EQ(nblks_added, slab_cfg.slab_size)
                    << "Failure in filling cache for i = " << i << " slab=" << slab_cfg.slab_size;

                blk_id += slab_cfg.slab_size;
            }
        }
        m_fb_cache->close_cache_fill_session(*fill_session);
    }

    uint32_t first_blk_num_at_slab(uint8_t slab_idx) {
        uint32_t blk_num{0};
        for (uint32_t idx{0}; idx < slab_idx; ++idx) {
            blk_num += m_count_per_slab * (1 << idx);
        }
        return blk_num;
    }

    uint32_t last_blk_num_at_slab(uint8_t slab_idx) { return first_blk_num_at_slab(slab_idx + 1) - (1 << slab_idx); }

    void validate_alloc(uint32_t count, uint8_t slab_idx, uint32_t start_blk_num, uint32_t expected_entries_per_alloc) {
        // auto expected_blk_num = start_blk_num;

        for (uint32_t i{0}; i < count; ++i) {
            blk_cache_alloc_req req(m_cfg.m_per_slab_cfg[slab_idx].slab_size, 0, false /* is_contiguos */);
            blk_cache_alloc_resp resp;
            ASSERT_EQ(m_fb_cache->try_alloc_blks(req, resp), BlkAllocStatus::SUCCESS)
                << "Failure to alloc from slab=" << slab_idx << " for iter=" << i;
            ASSERT_EQ(resp.nblks_alloced, req.nblks)
                << "Failure on num_blks_alloced from slab=" << slab_idx << " for iter=" << i;
            ASSERT_EQ(resp.out_blks.size(), expected_entries_per_alloc)
                << "Failure on out_blks size from slab=" << slab_idx << " for iter=" << i;
            // ASSERT_EQ(resp.out_blks[0].m_blk_num, expected_blk_num) << "Failure on blk_num for iter=" << i;
            // expected_blk_num += m_cfg[slab_idx].slab_size;
        }
    }

    void validate_alloc_failure(uint8_t slab_idx, bool is_contiguous, const std::string& msg) {
        blk_cache_alloc_req req(m_cfg.m_per_slab_cfg[slab_idx].slab_size, 0, is_contiguous);
        blk_cache_alloc_resp resp;
        ASSERT_NE(m_fb_cache->try_alloc_blks(req, resp), BlkAllocStatus::SUCCESS) << msg;
    }
};

TEST_F(BlkCacheQueueTest, rand_alloc_free_blks) {
    static constexpr slab_idx_t num_slabs = 9;

    std::vector< blk_cache_entry > _excess_blks;
    uint16_t num_zombied{0};

    // 1000 entries for each of the 9 slabs
    SetUp(num_slabs, 1000);

    LOGINFO("Step 1: Allocating 1000 blocks from random slabs and expect all to succeed");
    std::vector< blk_cache_entry > alloced;
    for (auto i{0}; i < 1000; ++i) {
        auto nblks = (1 << rand() % num_slabs);
        blk_cache_alloc_req req(nblks, 0, false /* is_contiguos */);
        blk_cache_alloc_resp resp;

        BlkAllocStatus status = m_fb_cache->try_alloc_blks(req, resp);
        ASSERT_EQ(status, BlkAllocStatus::SUCCESS) << "Failure in allocation i = " << i;
        ASSERT_EQ(resp.out_blks.size(), 1u) << "Expected all allocations come from their own slab - not for i=" << i;
        alloced.insert(alloced.end(), resp.out_blks.begin(), resp.out_blks.end());
    }

    LOGINFO("Step 2: Free all allocated blks and expect all free to succeed");
    for (auto& e : alloced) {
        auto nblks = (1 << rand() % num_slabs);
        BlkAllocStatus status = m_fb_cache->try_free_blks(e, _excess_blks, num_zombied);
        ASSERT_EQ(status, BlkAllocStatus::SUCCESS)
            << "Failure in freeing the blks to cache for entry e = " << e.to_string();
    }

    // Freeing one more blk of any size should result in failure because all of them should have been freed in
    // the previous step to its original slab
    LOGINFO("Step 3: Now all slots are back full, try freeing one additional blocks and expect to fail");
    for (auto& slab_cfg : m_cfg.m_per_slab_cfg) {
        blk_cache_entry e{10000u, slab_cfg.slab_size, 0};
        ASSERT_NE(m_fb_cache->try_free_blks(e, _excess_blks, num_zombied), BlkAllocStatus::SUCCESS)
            << "Expected failure to add after queue is full, but not for entry=" << e.to_string();
    }

    LOGINFO("Step 4: Realloc 1000 more random blks and it should succeed");
    for (auto i{0}; i < 1000; ++i) {
        auto nblks = (1 << rand() % num_slabs);
        blk_cache_alloc_req req(nblks, 0, false /* is_contiguos */);
        blk_cache_alloc_resp resp;

        BlkAllocStatus status = m_fb_cache->try_alloc_blks(req, resp);
        ASSERT_EQ(status, BlkAllocStatus::SUCCESS) << "Failure in allocation i = " << i;
        ASSERT_EQ(resp.out_blks.size(), 1u) << "Expected all allocations come from their own slab - not for i=" << i;
    }
}

TEST_F(BlkCacheQueueTest, alloc_higher_lower_slab) {
    static constexpr slab_idx_t num_slabs = 9;

    // 1024 entries for each of the 10 slabs
    SetUp(num_slabs, 1024);

    // Get all blks from 5th slab
    uint32_t slab_idx{5};
    uint32_t count{0};
    for (uint32_t idx{slab_idx}; idx < m_nslabs; ++idx) {
        count += m_count_per_slab * (1 << (idx - slab_idx));
    }

    LOGINFO("Step 1: Allocate all blocks from slab={} and above for count={} and expect to break higher slab", slab_idx,
            count);
    validate_alloc(count, slab_idx, first_blk_num_at_slab(slab_idx), 1);

    // Next contiguous allocation should fail because we should have drained all higher slabs
    LOGINFO("Step 2: Since all higher slab are allocated, so contiguous only alloc of slab={} is expected to fail",
            slab_idx);
    validate_alloc_failure(slab_idx, true /* is_contiguos */, "Expected alloc failure base_slab for contiguous blks");

    LOGINFO("Step 3: Allocate from lower than slab={} and expect all to succeed", slab_idx);
    count = m_count_per_slab / 2;
    uint32_t expected_entries_per_alloc{2};
    for (int64_t idx{slab_idx - 1}; idx >= 0; --idx) {
        validate_alloc(count, slab_idx, first_blk_num_at_slab(idx), expected_entries_per_alloc);
        count /= 2;
        expected_entries_per_alloc *= 2;
    }
}

TEST_F(BlkCacheQueueTest, alloc_partial_blks) {
    static constexpr slab_idx_t num_slabs = 3;

    // 9 entries for each of the 3 slabs
    SetUp(num_slabs, 9);

    uint32_t slab_idx{1};
    uint32_t count = m_count_per_slab * 3; // one for second slab and 2 from third slab

    LOGINFO("Step 1: Allocate all blocks from slab={} and above for count={} and expect to break higher slab", slab_idx,
            count);
    validate_alloc(count, slab_idx, first_blk_num_at_slab(slab_idx), 1);

    // Next contiguous allocation should fail because we should have drained all higher slabs
    LOGINFO("Step 2: Since all higher slab are allocated, so contiguous only alloc of slab={} is expected to fail",
            slab_idx);
    validate_alloc_failure(slab_idx, true /* is_contiguos */, "Expected alloc failure base_slab for contiguous blks");

    LOGINFO("Step 3: Allocate from lower than slab={} and expect all to succeed", slab_idx);
    count = m_count_per_slab / 2;
    validate_alloc(count, slab_idx, first_blk_num_at_slab(slab_idx - 1), 2);

    LOGINFO("Step 4: Try to allocate the partial block even non-contiguous in previous slab and ensure it fails");
    validate_alloc_failure(slab_idx, false /* is_contiguos */, "Expected alloc failure in prev slab");

    LOGINFO("Step 5: Try allocate only one from previous slab and it should succeed");
    validate_alloc(1, slab_idx - 1, last_blk_num_at_slab(slab_idx - 1), 1);

    LOGINFO("Step 6: Try to allocate one more blk for previous slab and it should fail");
    validate_alloc_failure(slab_idx - 1, false /* is_contiguos */, "Expected alloc failure in prev slab");
}

TEST_F(BlkCacheQueueTest, join_from_multiple_levels) {
    static constexpr slab_idx_t num_slabs = 3;
    std::vector< blk_cache_entry > _excess_blks;
    uint16_t num_zombied{0};

    // 4 entries for each of the 3 slabs
    SetUp(num_slabs, 4);

    LOGINFO("Step 1: Allocate all entries from slab=2, all-but-1 from slab=1, all-but-3 from slab=0");
    validate_alloc(4, 2, first_blk_num_at_slab(2), 1);
    validate_alloc(3, 1, first_blk_num_at_slab(1), 1);
    validate_alloc(1, 0, first_blk_num_at_slab(0), 1);

    LOGINFO("Step 2: Allocate one from slab=2, and see if result is from both the slabs");
    validate_alloc(1 /* count */, 2 /* slab */, last_blk_num_at_slab(1), 3);

    LOGINFO("Step 3: Put one block back on slab 1 and then repeat the allocation, it should fail since there are only "
            "partial available");
    blk_cache_entry e{10000u, 2, 0};
    ASSERT_EQ(m_fb_cache->try_free_blks(e, _excess_blks, num_zombied), BlkAllocStatus::SUCCESS)
        << "Expected to be able to put back an entry";
    validate_alloc_failure(2, false /* is_contiguous */, "Expected alloc failure with partial available");

    LOGINFO("Step 4: Subsequent alloc from slab 1 and slab 0 are successful, validates if previous partial alloc is "
            "captured back");
    validate_alloc(1 /* count */, 1 /* slab */, 10000u, 1);
    validate_alloc(1 /* count */, 0 /* slab */, last_blk_num_at_slab(0), 1);
}

SDS_OPTIONS_ENABLE(logging)
int main(int argc, char* argv[]) {
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, logging)
    sds_logging::SetLogger("test_blkalloc");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    g_metrics = std::make_unique< BlkAllocMetrics >("BlkCacheQueueTest");
    return RUN_ALL_TESTS();
}
