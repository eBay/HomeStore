#include <iostream>
#include <gtest/gtest.h>
#include <sds_logging/logging.h>
#include <sds_options/options.h>
#include <thread>
#include <random>
//#include <folly/SharedMutex.h>
#include <folly/ConcurrentSkipList.h>
#include <boost/dynamic_bitset.hpp>
#include <fds/bitword.hpp>

#include "blk_allocator.h"
#include "varsize_blk_allocator.h"
#include "blk_cache.h"
#include "engine/common/homestore_config.hpp"

SDS_LOGGING_INIT(HOMESTORE_LOG_MODS)
THREAD_BUFFER_INIT;

using namespace homestore;

/* This verbose syntax for a simple random range is precisely why people started hating C++ */
static thread_local std::default_random_engine g_rd;

using BlkListT = folly::ConcurrentSkipList< uint32_t >;
using BlkListAccessorT = BlkListT::Accessor;
using size_generator_t = std::function< blk_count_t(void) >;

struct AllocedBlkTracker {
    AllocedBlkTracker(uint64_t quota) : m_alloced_blk_list{BlkListT::create(4u)}, m_max_quota{quota} {}

    void adjust_limits(uint8_t hi_limit_pct) {
        m_lo_limit = m_alloced_blk_list.size();
        m_hi_limit = std::max((m_max_quota * hi_limit_pct) / 100, m_lo_limit);
    }

    bool reached_lo_limit() const { return (m_alloced_blk_list.size() < m_lo_limit); }
    bool reached_hi_limit() const { return (m_alloced_blk_list.size() > m_hi_limit); }

    BlkListAccessorT m_alloced_blk_list;
    uint64_t m_max_quota;
    uint64_t m_lo_limit{0};
    uint64_t m_hi_limit{0};
};

static uint32_t round_count(const uint32_t count) {
    uint32_t new_count = count;
    if ((count & (count - 1)) != 0) {
        new_count = (1 << ((uint32_t)sisl::logBase2(count) + 1));
        LOGINFO("Count {} is not a power of 2, rounding total count to {}", count, new_count);
    }
    return new_count;
}

struct BlkAllocatorTest {
protected:
    std::atomic< int64_t > m_alloced_count{0};
    const uint32_t m_total_count;
    std::vector< AllocedBlkTracker > m_slab_alloced_blk_list;
    std::uniform_int_distribution< uint32_t > m_rand_blk_generator;
    bool m_track_slabs{false};

public:
    BlkAllocatorTest() :
            m_total_count{round_count(SDS_OPTIONS["num_blks"].as< uint32_t >())},
            m_rand_blk_generator{1, m_total_count} {
        m_slab_alloced_blk_list.emplace_back(m_total_count);
    }
    virtual ~BlkAllocatorTest() = default;

    void start_track_slabs() {
        assert(m_track_slabs == false);
        m_track_slabs = true;

        uint16_t i{0};
        int64_t cum{0};
        for (auto& dpct : homestore::HomeStoreDynamicConfig::default_slab_distribution()) {
            uint32_t slab_count = (m_total_count / (1 << i)) * dpct / 100;
            if (i == 0) {
                m_slab_alloced_blk_list[0].m_max_quota = slab_count;
            } else {
                m_slab_alloced_blk_list.emplace_back(slab_count);
            }
            cum += slab_count * (1 << i);
            ++i;
        }
        m_slab_alloced_blk_list[0].m_max_quota += m_total_count - cum;
    }

    BlkListAccessorT& blk_list(slab_idx_t idx) { return m_slab_alloced_blk_list[idx].m_alloced_blk_list; }

    slab_idx_t nblks_to_idx(const blk_count_t n_blks) { return m_track_slabs ? nblks_to_slab_tbl[n_blks] : 0; }

    void alloced(const BlkId& bid) {
        uint32_t blk_num{static_cast< uint32_t >(bid.get_blk_num())};
        ASSERT_LT(blk_num, m_total_count);
        m_alloced_count.fetch_add(bid.get_nblks(), std::memory_order_acq_rel);

        slab_idx_t slab_idx{0};
        if (m_track_slabs) {
            slab_idx = nblks_to_idx(bid.get_nblks());
            ASSERT_EQ(blk_list(slab_idx).add(blk_num), true) << "Duplicate alloc of blk=" << blk_num;
        } else {
            for (blk_count_t i{0}; i < bid.get_nblks(); ++i) {
                ASSERT_EQ(blk_list(slab_idx).add(blk_num), true) << "Duplicate alloc of blk=" << blk_num;
                ++blk_num;
            }
        }

        LOGTRACEMOD(blkalloc, "After Alloced nblks={} blk_range=[{}-{}] skip_list_size={} alloced_count={}",
                    bid.get_nblks(), bid.get_blk_num(), bid.get_blk_num() + bid.get_nblks() - 1,
                    blk_list(slab_idx).size(), m_alloced_count.load(std::memory_order_relaxed));
    }

    void freed(const uint32_t blk_num) {
        assert(m_track_slabs == false);
        m_alloced_count.fetch_sub(1, std::memory_order_acq_rel);
        ASSERT_EQ(blk_list(0).erase((uint32_t)blk_num), true) << "Expected to be set blk=" << blk_num;
    }

    BlkId pick_rand_blks_to_free(blk_count_t pref_nblks, bool round_nblks = false) {
        return m_track_slabs ? pick_rand_slab_blks_to_free(pref_nblks)
                             : pick_rand_single_pool_blks_to_free(pref_nblks, round_nblks);
    }

    void run_parallel(uint32_t nthreads, uint64_t total_count, const std::function< void(uint64_t) >& thr_fn) {
        uint64_t start = 0;
        uint64_t n_per_thread = (total_count - 1) / nthreads + 1;
        std::vector< std::thread > threads;

        while (start < total_count) {
            threads.emplace_back(thr_fn, std::min(n_per_thread, total_count - start));
            start += n_per_thread;
        }

        for (auto& t : threads) {
            if (t.joinable()) { t.join(); }
        }
    }

    static blk_count_t uniform_rand_size() {
        static std::uniform_int_distribution< blk_count_t > s_rand_size_generator{1, static_cast< blk_count_t >(256)};
        return s_rand_size_generator(g_rd);
    }

    static blk_count_t round_rand_size() {
        static std::uniform_int_distribution< uint8_t > s_rand_slab_generator{0, static_cast< uint8_t >(8)};
        return static_cast< blk_count_t >((1 << s_rand_slab_generator(g_rd)));
    }

    static constexpr blk_count_t single_blk_size() { return 1; }

private:
    BlkId pick_rand_slab_blks_to_free(blk_count_t pref_nblks) {
        uint32_t rand_blk_num = m_rand_blk_generator(g_rd);
        const auto start_idx = nblks_to_idx(pref_nblks);
        auto idx = start_idx;

        bool picked{false};
        do {
            if (blk_list(idx).size() > 0) {
                auto it = blk_list(idx).lower_bound(rand_blk_num);
                if (it == blk_list(idx).end()) {
                    rand_blk_num = 0;
                    continue;
                }
                rand_blk_num = *it;
                if (blk_list(idx).erase(*it)) {
                    picked = true;
                    break;
                }
            } else {
                if (++idx == 9) { idx = 0; }
                if (idx == start_idx) { break; }
            }
        } while (true);
        HS_RELEASE_ASSERT_EQ(picked, true);

        blk_count_t n_blks = (1 << idx);
        m_alloced_count.fetch_sub(n_blks, std::memory_order_acq_rel);
        return BlkId{rand_blk_num, n_blks, 0};
    }

    BlkId pick_rand_single_pool_blks_to_free(blk_count_t pref_nblks, bool round_nblks = false) {
        uint32_t start_blk_num{0};
        blk_count_t n_blks{0};
        uint32_t rand_num = m_rand_blk_generator(g_rd);

        bool picked = false;
        while (n_blks < pref_nblks) {
            assert(blk_list(0).size() > 0);
            auto it = blk_list(0).lower_bound(rand_num);
            if (it == blk_list(0).end()) {
                if (n_blks > 0) break;
                rand_num = 0;
                continue;
            }

            // If its not contiguos blks can't consider the count, use what we got
            if ((n_blks > 0) && (*it != start_blk_num + n_blks)) { break; }
            if (n_blks == 0) start_blk_num = *it;

            // By the time we erase, if somebody else got this one, just do retry.
            n_blks = (blk_list(0).erase(*it)) ? n_blks + 1 : 0;
        }

        assert(n_blks > 0);
        if (round_nblks) {
            const auto rounded_n_blks = (1 << static_cast< blk_count_t >(sisl::logBase2(n_blks)));
            for (int i{0}; i < (n_blks - rounded_n_blks); ++i) { // Add back to the free
                blk_list(0).add(start_blk_num + rounded_n_blks + i);
            }
            n_blks = rounded_n_blks;
        }

        m_alloced_count.fetch_sub(n_blks, std::memory_order_acq_rel);

        LOGTRACEMOD(blkalloc, "After Freed n_blks={} blk_range=[{}-{}] skip_list_size={} alloced_count={}", n_blks,
                    start_blk_num, start_blk_num + n_blks - 1, blk_list(0).size(),
                    m_alloced_count.load(std::memory_order_relaxed));

        return BlkId{start_blk_num, n_blks, 0};
    }
};

struct FixedBlkAllocatorTest : public testing::Test, BlkAllocatorTest {
protected:
    std::unique_ptr< FixedBlkAllocator > m_allocator;

public:
    FixedBlkAllocatorTest() : BlkAllocatorTest() {
        BlkAllocConfig fixed_cfg(4096, static_cast< uint64_t >(m_total_count) * 4096, "");
        m_allocator = std::make_unique< FixedBlkAllocator >(fixed_cfg, true, 0);
    }
    ~FixedBlkAllocatorTest() override = default;

    void alloc_blk(BlkAllocStatus exp_status, BlkId& bid) {
        auto ret = m_allocator->alloc(bid);
        ASSERT_EQ(ret, exp_status);
        if (ret == BlkAllocStatus::SUCCESS) { alloced(bid); }
    }

    void free_blk(const uint32_t blk_num) {
        m_allocator->free(BlkId{blk_num, 1, 0});
        freed(blk_num);
    }

    BlkId free_random_alloced_blk() {
        BlkId bid = pick_rand_blks_to_free(1);
        m_allocator->free(bid);
        return bid;
    }

    void validate_count() const {
        ASSERT_EQ(m_allocator->get_used_blks(), m_alloced_count.load(std::memory_order_relaxed))
            << "Used blks count mismatch";
    }
};

struct VarsizeBlkAllocatorTest : public testing::Test, BlkAllocatorTest {
protected:
    std::unique_ptr< VarsizeBlkAllocator > m_allocator;

public:
    VarsizeBlkAllocatorTest() : BlkAllocatorTest() {
        HomeStoreDynamicConfig::init_settings_default();
        VarsizeBlkAllocConfig cfg{4096u, static_cast< uint64_t >(m_total_count) * 4096, ""};
        cfg.set_phys_page_size(4096);
        cfg.set_auto_recovery(true);
        m_allocator = std::make_unique< VarsizeBlkAllocator >(cfg, true, 0);
    }
    VarsizeBlkAllocatorTest(const VarsizeBlkAllocatorTest&) = default;
    VarsizeBlkAllocatorTest(VarsizeBlkAllocatorTest&&) noexcept = delete;
    VarsizeBlkAllocatorTest& operator=(const VarsizeBlkAllocatorTest&) = default;
    VarsizeBlkAllocatorTest& operator=(VarsizeBlkAllocatorTest&&) noexcept = delete;
    ~VarsizeBlkAllocatorTest() override = default;

    void alloc_rand_blk(BlkAllocStatus exp_status, bool is_contiguous, blk_count_t reqd_size) {
        blk_alloc_hints hints;
        hints.is_contiguous = is_contiguous;

        static thread_local std::vector< BlkId > _bids;
        _bids.clear();

        auto ret = m_allocator->alloc(reqd_size, hints, _bids);
        ASSERT_EQ(ret, exp_status);
        if (ret == BlkAllocStatus::SUCCESS) {
            if (is_contiguous) { ASSERT_EQ(_bids.size(), 1) << "Did not expect multiple bids for contiguous request"; }

            blk_count_t sz = 0;
            for (auto& bid : _bids) {
                alloced(bid);
                sz += bid.get_nblks();
            }
            ASSERT_EQ(sz, reqd_size) << "Didn't get the size we expect from";
        }
    }

    BlkId free_random_alloced_sized_blk(blk_count_t reqd_size, bool round_nblks) {
        BlkId bid = pick_rand_blks_to_free(reqd_size, round_nblks);
        m_allocator->free(bid);
        return bid;
    }

    void validate_count() const {
        ASSERT_EQ(m_allocator->get_used_blks(), m_alloced_count.load(std::memory_order_relaxed))
            << "Used blks count mismatch";
    }

    void preload(uint64_t count, bool is_contiguous, const size_generator_t& size_generator) {
        auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
        run_parallel(nthreads, count, [&](uint64_t count_per_thread) {
            for (uint64_t i{0}; i < count_per_thread;) {
                auto rand_size = size_generator();
                alloc_rand_blk(BlkAllocStatus::SUCCESS, is_contiguous, rand_size);
                i += rand_size;
            }
        });
        // validate_count();
        // LOGINFO("Metrics after preallocate: {}", m_allocator->get_metrics_in_json().dump(4));
    }

    void do_alloc_free(uint64_t num_iters, bool is_contiguous, const size_generator_t& size_generator,
                       const uint8_t limit_pct, bool round_nblks = false) {
        auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
        for (auto& s : m_slab_alloced_blk_list) {
            s.adjust_limits(limit_pct);
        }

        int64_t overall_hi_limit = (m_total_count * limit_pct) / 100;
        run_parallel(nthreads, num_iters, [&](uint64_t iters_per_thread) {
            uint64_t alloced_nblks{0};
            uint64_t freed_nblks{0};

            for (uint64_t i{0}; i < iters_per_thread; ++i) {
                blk_count_t rand_size = size_generator();
                auto idx = nblks_to_idx(rand_size);

                if (!m_slab_alloced_blk_list[idx].reached_hi_limit() &&
                    (m_alloced_count.load(std::memory_order_relaxed) < overall_hi_limit)) {
                    alloc_rand_blk(BlkAllocStatus::SUCCESS, is_contiguous, rand_size);
                    alloced_nblks += rand_size;
                }

                if (!m_slab_alloced_blk_list[idx].reached_lo_limit()) {
                    auto bid = free_random_alloced_sized_blk(rand_size, round_nblks);
                    freed_nblks += bid.get_nblks();
                }
            }
            LOGINFO("Alloced {} random blks and freed {} random blks in this thread", alloced_nblks, freed_nblks);
        });
    }
};

TEST_F(FixedBlkAllocatorTest, alloc_free_fixed_size) {
    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    LOGINFO("Step 1: Pre allocate {} objects in {} threads", m_total_count / 2, nthreads);
    run_parallel(nthreads, m_total_count / 2, [&](uint64_t count_per_thread) {
        for (uint64_t i{0}; i < count_per_thread; ++i) {
            BlkId bid;
            alloc_blk(BlkAllocStatus::SUCCESS, bid);
        }
    });
    validate_count();

    LOGINFO("Step 2: Free {} blks randomly in {} threads ", m_total_count / 4, nthreads);
    run_parallel(nthreads, m_total_count / 4, [&](uint64_t count_per_thread) {
        for (uint64_t i{0}; i < count_per_thread; ++i) {
            free_random_alloced_blk();
        }
    });
    validate_count();

    LOGINFO("Step 3: Fill in the remaining {} blks to empty the device in {} threads", m_total_count * 3 / 4, nthreads);
    run_parallel(nthreads, m_total_count * 3 / 4, [&](uint64_t count_per_thread) {
        for (uint64_t i{0}; i < count_per_thread; ++i) {
            BlkId bid;
            alloc_blk(BlkAllocStatus::SUCCESS, bid);
        }
    });
    validate_count();

    BlkId bid;
    LOGINFO("Step 4: Validate if further allocation result in space full error");
    alloc_blk(BlkAllocStatus::SPACE_FULL, bid);

    LOGINFO("Step 5: Free up 2 blocks and make sure 2 more alloc is successful and do FIFO allocation");
    BlkId free_bid1 = free_random_alloced_blk();
    BlkId free_bid2 = free_random_alloced_blk();

    BlkId bid1;
    alloc_blk(BlkAllocStatus::SUCCESS, bid1);
    BlkId bid2;
    alloc_blk(BlkAllocStatus::SUCCESS, bid2);
    ASSERT_EQ(BlkId::compare(bid1, free_bid1), 0) << "Order of block allocation not expected";
    ASSERT_EQ(BlkId::compare(bid2, free_bid2), 0) << "Order of block allocation not expected";
    validate_count();
}

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_unirandsize) {
    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    uint8_t prealloc_pct = 5;
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct,
            m_total_count * prealloc_pct / 100, nthreads);
    preload(m_total_count * prealloc_pct / 100, true /* is_contiguous */, BlkAllocatorTest::uniform_rand_size);

    // auto num_iters = std::max(SDS_OPTIONS["iters"].as< uint64_t >(), 10000u);
    auto num_iters = SDS_OPTIONS["iters"].as< uint64_t >();
    if (num_iters > m_total_count / 150) {
        LOGINFO("For contiguous_unirandsize test, iters={} cannot be more than 1/150th of total count={}. Adjusting",
                num_iters, m_total_count);
        num_iters = m_total_count / 150;
    }
    uint8_t runtime_pct = 10;
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    do_alloc_free(num_iters, true /* is_contiguous */, BlkAllocatorTest::uniform_rand_size, runtime_pct,
                  false /* round_blks */);
}

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_roundrandsize) {
    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    uint8_t prealloc_pct = 5;
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct,
            (m_total_count * prealloc_pct) / 100, nthreads);
    preload((m_total_count * prealloc_pct) / 100, true /* is_contiguous */, BlkAllocatorTest::round_rand_size);

    auto num_iters = SDS_OPTIONS["iters"].as< uint64_t >();
    if (num_iters > m_total_count / 100) {
        LOGINFO("For contiguous_unirandsize test, iters={} cannot be more than 1/100th of total count={}. Adjusting",
                num_iters, m_total_count);
        num_iters = m_total_count / 100;
    }
    uint8_t runtime_pct = 10;
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    do_alloc_free(num_iters, true /* is_contiguous */, BlkAllocatorTest::round_rand_size, runtime_pct,
                  true /* round_blks */);
}

#if 0
TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_slabrandsize) {
    start_track_slabs();

    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    uint8_t prealloc_pct = 50;
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct,
            (m_total_count * prealloc_pct) / 100, nthreads);
    preload((m_total_count * prealloc_pct) / 100, true /* is_contiguous */, BlkAllocatorTest::round_rand_size);
    LOGINFO("Metrics after preallocate: {}", m_allocator->get_metrics_in_json().dump(4));

    auto num_iters = SDS_OPTIONS["iters"].as< uint64_t >();
    uint8_t runtime_pct = 75;
    LOGINFO("Step 2: Do alloc/free contiguous blks with on slab sized ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    do_alloc_free(num_iters, true /* is_contiguous */, BlkAllocatorTest::round_rand_size, runtime_pct,
                  false /* round_blks */);
}
#endif

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_onesize) {
    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    LOGINFO("Step 1: Pre allocate 50% of total blks which is {} blks in {} threads", (m_total_count * 50) / 100,
            nthreads);
    preload((m_total_count * 50) / 100, true /* is_contiguous */, BlkAllocatorTest::single_blk_size);

    auto num_iters = SDS_OPTIONS["iters"].as< uint64_t >();
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size for blks span={}, threads={} iters={}",
            m_total_count, nthreads, num_iters);
    do_alloc_free(num_iters, true /* is_contiguous */, BlkAllocatorTest::single_blk_size, 90, true /* round_blks */);

    LOGINFO("Step 3: Reallocate to alloc all remaining count {}", m_allocator->get_available_blks());
    preload(m_allocator->get_available_blks(), true /* is_contiguous */, BlkAllocatorTest::single_blk_size);

    ASSERT_EQ(m_allocator->get_available_blks(), 0u) << "Expected no blocks to be free";
}

#if 0
TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_scatter_unirandsize) {
    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    uint8_t prealloc_pct = 5;
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct,
            m_total_count * prealloc_pct / 100, nthreads);
    preload(m_total_count * prealloc_pct / 100, true /* is_contiguous */, BlkAllocatorTest::uniform_rand_size);

    auto num_iters = SDS_OPTIONS["iters"].as< uint64_t >();
    uint8_t runtime_pct = 75;
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    do_alloc_free(num_iters, false /* is_contiguous */, BlkAllocatorTest::uniform_rand_size, runtime_pct,
                  false /* round_blks */);

    LOGINFO("Step 3: Reallocate to alloc all remaining count {}", m_allocator->get_available_blks());
    preload(m_allocator->get_available_blks(), false /* is_contiguous */, BlkAllocatorTest::single_blk_size);
    ASSERT_EQ(m_allocator->get_available_blks(), 0u) << "Expected no blocks to be free";
}
#endif

TEST_F(VarsizeBlkAllocatorTest, alloc_var_scatter_direct_unirandsize) {
    LOGINFO("Step 1: Set the flip to force directly bypassing freeblk cache");
    FlipClient* fc = HomeStoreFlip::client_instance();
    FlipFrequency freq;
    freq.set_count((uint64_t)m_total_count * 1000);
    freq.set_percent(100);
    fc->inject_noreturn_flip("varsize_blkalloc_bypass_cache", {}, freq);

    uint8_t prealloc_pct = 90;
    auto nthreads = SDS_OPTIONS["num_threads"].as< uint32_t >();
    LOGINFO("Step 2: Alloc upto {}% of space which is {} blks in {} threads as scattered blks", prealloc_pct,
            m_total_count * prealloc_pct / 100, nthreads);
    preload(m_total_count * prealloc_pct / 100, false /* is_contiguous */, BlkAllocatorTest::uniform_rand_size);

    LOGINFO("Step 3: Reallocate to alloc all remaining count {}", m_allocator->get_available_blks());
    preload(m_allocator->get_available_blks(), false /* is_contiguous */, BlkAllocatorTest::single_blk_size);
    ASSERT_EQ(m_allocator->get_available_blks(), 0u) << "Expected no blocks to be free";
}

template < typename T >
std::shared_ptr< cxxopts::Value > opt_default(const char* val) {
    return ::cxxopts::value< T >()->default_value(val);
}

#define ENABLED_OPTIONS logging, test_blkalloc
SDS_OPTIONS_ENABLE(ENABLED_OPTIONS)

SDS_OPTION_GROUP(test_blkalloc,
                 (num_blks, "", "num_blks", "number of blks", opt_default< uint32_t >("1000000"), "number"),
                 (iters, "", "iters", "number of iterations", opt_default< uint64_t >("100000"), "number"),
                 (num_threads, "", "num_threads", "num_threads", opt_default< uint32_t >("8"), "number"))

int main(int argc, char* argv[]) {
    testing::InitGoogleTest(&argc, argv);
    SDS_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sds_logging::SetLogger("test_blkalloc");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");
    return RUN_ALL_TESTS();
}
