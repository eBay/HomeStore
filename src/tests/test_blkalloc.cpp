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
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <boost/dynamic_bitset.hpp>
#include <sisl/fds/bitword.hpp>
#include <folly/ConcurrentSkipList.h>
#include <folly/concurrency/ConcurrentHashMap.h>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <iomgr/iomgr_flip.hpp>

#include "blkalloc/blk_allocator.h"
#include "blkalloc/blk_cache.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include "blkalloc/varsize_blk_allocator.h"

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

using namespace homestore;

/* This verbose syntax for a simple random range is precisely why people started hating C++ */
static thread_local std::random_device g_rd{};
static thread_local std::default_random_engine g_re{g_rd()};
static std::mutex s_print_mutex;

using BlkMapT = folly::ConcurrentHashMap< blk_num_t, blk_count_t >;
using BlkListT = folly::ConcurrentSkipList< blk_num_t >;
using BlkListAccessorT = BlkListT::Accessor;
using size_generator_t = std::function< blk_count_t(void) >;

struct AllocedBlkTracker {
    AllocedBlkTracker(const uint64_t quota) :
            m_alloced_blk_list{BlkListT::create(8)}, m_alloced_blk_map{quota}, m_max_quota{quota} {}

    void adjust_limits(const uint8_t hi_limit_pct) {
        m_lo_limit = m_alloced_blk_list.size();
        m_hi_limit = std::max((m_max_quota * hi_limit_pct) / 100, m_lo_limit);
    }

    bool reached_lo_limit() const { return (m_alloced_blk_list.size() < m_lo_limit); }
    bool reached_hi_limit() const { return (m_alloced_blk_list.size() > m_hi_limit); }

    BlkListAccessorT m_alloced_blk_list;
    BlkMapT m_alloced_blk_map;
    uint64_t m_max_quota;
    uint64_t m_lo_limit{0};
    uint64_t m_hi_limit{0};
};

static uint32_t round_count(const uint32_t count) {
    uint32_t new_count{count};
    if ((count & (count - 1)) != 0) {
        new_count = static_cast< uint32_t >(1) << (sisl::logBase2(count) + 1);
        LOGINFO("Count {} is not a power of 2, rounding total count to {}", count, new_count);
    }
    return new_count;
}

struct BlkAllocatorTest {
    std::atomic< int64_t > m_alloced_count{0};
    std::vector< AllocedBlkTracker > m_slab_alloced_blks;
    std::uniform_int_distribution< uint32_t > m_rand_blk_generator;
    bool m_track_slabs{false};
    size_t m_num_slabs{0};

    const uint32_t m_total_count;
    BlkAllocatorTest() :
            m_rand_blk_generator{1, m_total_count},
            m_total_count{round_count(SISL_OPTIONS["num_blks"].as< uint32_t >())} {
        m_slab_alloced_blks.emplace_back(m_total_count);
    }
    BlkAllocatorTest(const BlkAllocatorTest&) = delete;
    BlkAllocatorTest(BlkAllocatorTest&&) noexcept = delete;
    BlkAllocatorTest& operator=(const BlkAllocatorTest&) = delete;
    BlkAllocatorTest& operator=(BlkAllocatorTest&&) noexcept = delete;
    ~BlkAllocatorTest() = default;

    void start_track_slabs() {
        assert(m_track_slabs == false);
        m_track_slabs = true;

        double cum_pct{0.0};
        uint64_t cum{0};
        size_t slab_index{0};
        const auto& slab_distribution{homestore::HomeStoreDynamicConfig::default_slab_distribution()};
        m_num_slabs = slab_distribution.size();
        for (size_t slab_index{0}; slab_index < slab_distribution.size(); ++slab_index) {
            cum_pct += slab_distribution[slab_index];
            const blk_count_t slab_size{static_cast< blk_count_t >(static_cast< blk_count_t >(1) << slab_index)};
            const blk_cap_t slab_count{
                static_cast< blk_cap_t >((m_total_count / slab_size) * (slab_distribution[slab_index] / 100.0))};
            if (slab_index == 0) {
                m_slab_alloced_blks[0].m_max_quota = slab_count;
            } else {
                m_slab_alloced_blks.emplace_back(slab_count);
            }
            cum += slab_count * slab_size;
        }
        assert(cum_pct < 100.0 * (1.0 + std::numeric_limits< double >::epsilon()));
        if (cum < m_total_count) { m_slab_alloced_blks[0].m_max_quota += m_total_count - cum; }
    }

    [[nodiscard]] BlkListAccessorT& blk_list(const slab_idx_t idx) {
        return m_slab_alloced_blks[idx].m_alloced_blk_list;
    }
    [[nodiscard]] BlkMapT& blk_map(const slab_idx_t idx) { return m_slab_alloced_blks[idx].m_alloced_blk_map; }

    [[nodiscard]] slab_idx_t nblks_to_idx(const blk_count_t n_blks) {
        return m_track_slabs ? nblks_to_slab_tbl[n_blks] : 0;
    }

    [[nodiscard]] bool alloced(const BlkId& bid, const bool track_block_group) {
        uint32_t blk_num{static_cast< uint32_t >(bid.get_blk_num())};
        if (blk_num >= m_total_count) {
            {
                std::scoped_lock< std::mutex > lock{s_print_mutex};
                std::cout << "Alloced: blk_num >= m_total_count" << blk_num << ' ' << m_total_count << std::endl;
            }
            return false;
        }
        m_alloced_count.fetch_add(bid.get_nblks(), std::memory_order_acq_rel);

        const slab_idx_t slab_idx{m_track_slabs ? nblks_to_idx(bid.get_nblks()) : static_cast< slab_idx_t >(0)};
        if (track_block_group) {
            // add blocks as group to each slab
            if (!blk_map(slab_idx).insert(blk_num, bid.get_nblks()).second) {
                {
                    std::scoped_lock< std::mutex > lock{s_print_mutex};
                    std::cout << "Duplicate alloc of blk=" << blk_num << std::endl;
                }
                return false;
            } else {
                // add block group size to map
                blk_list(slab_idx).add(blk_num);
            }

        } else {
            // add blocks individually to each slab
            for (blk_count_t i{0}; i < bid.get_nblks(); ++i) {
                if (!blk_list(slab_idx).add(blk_num)) {
                    {
                        std::scoped_lock< std::mutex > lock{s_print_mutex};
                        std::cout << "Duplicate alloc of blk=" << blk_num << std::endl;
                    }
                    return false;
                }
                ++blk_num;
            }
        }

        LOGTRACEMOD(blkalloc, "After Alloced nblks={} blk_range=[{}-{}] skip_list_size={} alloced_count={}",
                    bid.get_nblks(), blk_num, blk_num + bid.get_nblks() - 1, blk_list(slab_idx).size(),
                    m_alloced_count.load(std::memory_order_relaxed));
        return true;
    }

    [[nodiscard]] bool freed(const uint32_t blk_num) {
        assert(m_track_slabs == false);
        m_alloced_count.fetch_sub(1, std::memory_order_acq_rel);
        if (!blk_list(0).erase(static_cast< blk_num_t >(blk_num))) {
            {
                std::scoped_lock< std::mutex > lock{s_print_mutex};
                std::cout << "freed: Expected to be set blk=" << blk_num << std::endl;
            }
            return false;
        }
        return true;
    }

    [[nodiscard]] BlkId pick_rand_blks_to_free(const blk_count_t pref_nblks, const bool round_nblks,
                                               const bool track_group_block) {
        return m_track_slabs ? pick_rand_slab_blks_to_free(pref_nblks, track_group_block)
                             : pick_rand_pool_blks_to_free(pref_nblks, round_nblks, track_group_block);
    }

    void run_parallel(const uint32_t nthreads, const uint64_t total_count,
                      const std::function< void(uint64_t, std::atomic< bool >& terminate_flag) >& thr_fn) {
        std::atomic< bool > terminate_flag{false};
        uint64_t start{0};
        const uint64_t n_per_thread{(total_count - 1) / nthreads + 1};
        std::vector< std::thread > threads;

        while (start < total_count) {
            const uint64_t n_amount{std::min(n_per_thread, total_count - start)};
            threads.emplace_back(thr_fn, n_amount, std::ref(terminate_flag));
            start += n_amount;
        }

        for (auto& t : threads) {
            if (t.joinable()) { t.join(); }
        }
        ASSERT_EQ(terminate_flag, false);
    }

    [[nodiscard]] static blk_count_t uniform_rand_size() {
        static std::uniform_int_distribution< blk_count_t > s_rand_size_generator{1, static_cast< blk_count_t >(256)};
        return s_rand_size_generator(g_re);
    }

    [[nodiscard]] static blk_count_t round_rand_size() {
        static std::uniform_int_distribution< uint8_t > s_rand_slab_generator{1, static_cast< uint8_t >(8)};
        return (static_cast< blk_count_t >(1) << s_rand_slab_generator(g_re));
    }

    [[nodiscard]] static constexpr blk_count_t single_blk_size() { return 1; }

    [[nodiscard]] BlkId pick_rand_slab_blks_to_free(const blk_count_t pref_nblks, const bool track_block_group) {
        const auto start_idx{nblks_to_idx(pref_nblks)};
        auto idx{start_idx};

        uint32_t start_blk_num{0};
        blk_count_t n_blks{0};
        uint32_t rand_num{m_rand_blk_generator(g_re)};
        do {
            if (blk_list(idx).size() > 0) {
                // find a block to free
                do {
                    const auto it{blk_list(idx).lower_bound(rand_num)};
                    if (it != blk_list(idx).end()) {
                        if (blk_list(idx).erase(*it)) {
                            start_blk_num = *it;
                            if (track_block_group) {
                                const auto map_it{blk_map(idx).find(start_blk_num)};
                                const blk_count_t group_size{map_it->second};
                                n_blks = std::min(group_size, pref_nblks);
                                blk_map(idx).erase(start_blk_num);
                                if (n_blks < group_size) {
                                    // add back to right slab
                                    const blk_count_t remain_blocks{static_cast< blk_count_t >(group_size - n_blks)};
                                    const auto new_idx = nblks_to_idx(remain_blocks);
                                    blk_map(new_idx).insert(start_blk_num + n_blks, remain_blocks);
                                    blk_list(new_idx).add(start_blk_num + n_blks);
                                }
                            } else {
                                n_blks = 1;
                            }
                            break;
                        }
                        // reduce thread contention
                        std::this_thread::sleep_for(std::chrono::milliseconds{1});
                    } else {
                        rand_num /= 2;
                    }
                } while (blk_list(idx).size() > 0);
            } else {
                if (++idx == m_num_slabs) { idx = 0; }
                if (idx == start_idx) { break; }
            }
        } while (n_blks == 0);
        HS_REL_ASSERT_GE(n_blks, 1);

        // try to erase up to perf_blks contiguous blocks
        if (!track_block_group) {
            blk_num_t current_blk{start_blk_num + 1};
            while (n_blks < pref_nblks) {
                if (blk_list(idx).erase(current_blk)) {
                    ++n_blks;
                    ++current_blk;
                } else {
                    // take what we got
                    break;
                }
            }
        }

        m_alloced_count.fetch_sub(n_blks, std::memory_order_acq_rel);
        return BlkId{start_blk_num, n_blks, 0};
    }

    [[nodiscard]] BlkId pick_rand_pool_blks_to_free(const blk_count_t pref_nblks, const bool round_nblks,
                                                    const bool track_block_group) {
        uint32_t start_blk_num{0};
        blk_count_t n_blks{0};

        // find a block to free
        uint32_t rand_num{m_rand_blk_generator(g_re)};
        do {
            const auto it{blk_list(0).lower_bound(rand_num)};
            if (it != blk_list(0).end()) {
                start_blk_num = *it;
                if (blk_list(0).erase(start_blk_num)) {
                    if (track_block_group) {
                        const auto map_it{blk_map(0).find(start_blk_num)};
                        const blk_count_t group_size{map_it->second};
                        n_blks = std::min(group_size, pref_nblks);
                        if (round_nblks && (n_blks > 2)) {
                            n_blks = static_cast< blk_count_t >(1) << sisl::logBase2(n_blks);
                        }
                        blk_map(0).erase(start_blk_num);
                        if (n_blks < group_size) {
                            // add remaining back
                            const blk_count_t remain_blocks{static_cast< blk_count_t >(group_size - n_blks)};
                            blk_map(0).insert(start_blk_num + n_blks, remain_blocks);
                            blk_list(0).add(start_blk_num + n_blks);
                        }
                    } else {
                        n_blks = 1;
                    }
                    break;
                }
                // reduce thread contention
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            } else {
                rand_num /= 2;
            }
        } while (blk_list(0).size() > 0);
        assert(n_blks >= 1);

        // try to erase up to perf_blks contiguous blocks
        if (!track_block_group) {
            blk_num_t current_blk{start_blk_num + 1};
            while (n_blks < pref_nblks) {
                if (blk_list(0).erase(current_blk)) {
                    ++n_blks;
                    ++current_blk;
                } else {
                    // take what we got
                    break;
                }
            }

            if (round_nblks && (n_blks > 2)) {
                const auto rounded_n_blks = static_cast< blk_count_t >(1) << sisl::logBase2(n_blks);
                for (int i{0}; i < (n_blks - rounded_n_blks); ++i) { // Add back to the free
                    blk_list(0).add(start_blk_num + rounded_n_blks + i);
                }
                n_blks = rounded_n_blks;
            }
        }

        m_alloced_count.fetch_sub(n_blks, std::memory_order_acq_rel);

        LOGTRACEMOD(blkalloc, "After Freed n_blks={} blk_range=[{}-{}] skip_list_size={} alloced_count={}", n_blks,
                    start_blk_num, start_blk_num + n_blks - 1, blk_list(0).size(),
                    m_alloced_count.load(std::memory_order_relaxed));

        return BlkId{start_blk_num, n_blks, 0};
    }
};

struct FixedBlkAllocatorTest : public ::testing::Test, BlkAllocatorTest {
    std::unique_ptr< FixedBlkAllocator > m_allocator;
    FixedBlkAllocatorTest() : BlkAllocatorTest() {
        BlkAllocConfig fixed_cfg{4096, 4096, static_cast< uint64_t >(m_total_count) * 4096, "", false};
        m_allocator = std::make_unique< FixedBlkAllocator >(fixed_cfg, true, 0);
        HS_REL_ASSERT_EQ(m_allocator->realtime_bm_on(), false);
    }
    FixedBlkAllocatorTest(const FixedBlkAllocatorTest&) = delete;
    FixedBlkAllocatorTest(FixedBlkAllocatorTest&&) noexcept = delete;
    FixedBlkAllocatorTest& operator=(const FixedBlkAllocatorTest&) = delete;
    FixedBlkAllocatorTest& operator=(FixedBlkAllocatorTest&&) noexcept = delete;
    virtual ~FixedBlkAllocatorTest() override = default;

    virtual void SetUp() override{};
    virtual void TearDown() override{};

    [[nodiscard]] bool alloc_blk(const BlkAllocStatus exp_status, BlkId& bid, const bool track_block_group) {
        const auto ret{m_allocator->alloc(bid)};
        if (ret != exp_status) {
            {
                std::scoped_lock< std::mutex > lock{s_print_mutex};
                std::cout << "Ret!=exp_status: ret=" << ret << " expected status=" << exp_status << std::endl;
            }
            return false;
        }
        if (ret == BlkAllocStatus::SUCCESS) {
            if (!alloced(bid, track_block_group)) { return false; }
        }
        return true;
    }

    [[nodiscard]] bool free_blk(const uint32_t blk_num) {
        m_allocator->free(BlkId{blk_num, 1, 0});
        return freed(blk_num);
    }

    [[nodiscard]] BlkId free_random_alloced_blk(const bool track_block_group) {
        const BlkId bid{pick_rand_blks_to_free(1, false, track_block_group)};
        m_allocator->free(bid);
        return bid;
    }

    void validate_count() const {
        ASSERT_EQ(m_allocator->get_used_blks(), m_alloced_count.load(std::memory_order_relaxed))
            << "Used blks count mismatch";
    }
};

struct VarsizeBlkAllocatorTest : public ::testing::Test, BlkAllocatorTest {
    std::unique_ptr< VarsizeBlkAllocator > m_allocator;

    VarsizeBlkAllocatorTest() : BlkAllocatorTest() { HomeStoreDynamicConfig::init_settings_default(); }
    VarsizeBlkAllocatorTest(const VarsizeBlkAllocatorTest&) = delete;
    VarsizeBlkAllocatorTest(VarsizeBlkAllocatorTest&&) noexcept = delete;
    VarsizeBlkAllocatorTest& operator=(const VarsizeBlkAllocatorTest&) = delete;
    VarsizeBlkAllocatorTest& operator=(VarsizeBlkAllocatorTest&&) noexcept = delete;
    virtual ~VarsizeBlkAllocatorTest() override = default;

    virtual void SetUp() override{};
    virtual void TearDown() override{};

    void create_allocator(const bool use_slabs = true) {
        VarsizeBlkAllocConfig cfg{4096, 4096, 4096u, static_cast< uint64_t >(m_total_count) * 4096, "", false};
        cfg.set_phys_page_size(4096);
        cfg.set_auto_recovery(true);
        cfg.set_use_slabs(use_slabs);
        m_allocator = std::make_unique< VarsizeBlkAllocator >(cfg, true, 0);
        HS_REL_ASSERT_EQ(m_allocator->realtime_bm_on(), false);
    }

    [[nodiscard]] bool alloc_rand_blk(const BlkAllocStatus exp_status, const bool is_contiguous,
                                      const blk_count_t reqd_size, const bool track_block_group) {
        blk_alloc_hints hints;
        hints.is_contiguous = is_contiguous;

        static thread_local std::vector< BlkId > bids;
        bids.clear();

        const auto ret{m_allocator->alloc(reqd_size, hints, bids)};
        if (ret != exp_status) {
            {
                std::scoped_lock< std::mutex > lock{s_print_mutex};
                std::cout << "Ret!=exp_status: ret=" << ret << " expected status=" << exp_status << std::endl;
            }
            return false;
        }
        if (ret == BlkAllocStatus::SUCCESS) {
            if (is_contiguous) {
                if (bids.size() != 1) {
                    {
                        std::scoped_lock< std::mutex > lock{s_print_mutex};
                        std::cout << "Did not expect multiple bids for contiguous request.  Bids=" << bids.size()
                                  << std::endl;
                    }
                    return false;
                }
            }

            blk_count_t sz{0};
            for (auto& bid : bids) {
                if (!alloced(bid, track_block_group)) { return false; }
                sz += bid.get_nblks();
            }
            if (sz != reqd_size) {
                {
                    std::scoped_lock< std::mutex > lock{s_print_mutex};
                    std::cout << "Didn't get the size we expect.  Requested size=" << reqd_size << " size=" << sz
                              << std::endl;
                }
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] BlkId free_random_alloced_sized_blk(const blk_count_t reqd_size, const bool round_nblks,
                                                      const bool track_block_group) {
        const BlkId bid{pick_rand_blks_to_free(reqd_size, round_nblks, track_block_group)};
        m_allocator->free(bid);
        return bid;
    }

    void validate_count() const {
        ASSERT_EQ(m_allocator->get_used_blks(), m_alloced_count.load(std::memory_order_relaxed))
            << "Used blks count mismatch";
    }

public:
    [[nodiscard]] uint64_t preload(const uint64_t count, const bool is_contiguous,
                                   const size_generator_t& size_generator, const bool track_block_group) {
        const auto nthreads{std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2,
                                                   SISL_OPTIONS["num_threads"].as< uint32_t >())};
        std::atomic< uint64_t > total_alloced{0};
        run_parallel(nthreads, count, [&](const uint64_t count_per_thread, std::atomic< bool >& terminate_flag) {
            for (uint64_t i{0}; (i < count_per_thread) && !terminate_flag;) {
                const auto rand_size{size_generator()};
                if (!alloc_rand_blk(BlkAllocStatus::SUCCESS, is_contiguous, rand_size, track_block_group)) {
                    terminate_flag = true;
                }
                i += rand_size;
                total_alloced += rand_size;
            }
        });
        // validate_count();
        // LOGINFO("Metrics after preallocate: {}", m_allocator->get_metrics_in_json().dump(4));
        return total_alloced;
    }

    [[nodiscard]] std::pair< uint64_t, uint64_t > do_alloc_free(const uint64_t num_iters, const bool is_contiguous,
                                                                const size_generator_t& size_generator,
                                                                const uint8_t limit_pct, const bool round_nblks,
                                                                const bool track_block_group) {
        const auto nthreads{std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2,
                                                   SISL_OPTIONS["num_threads"].as< uint32_t >())};
        for (auto& s : m_slab_alloced_blks) {
            s.adjust_limits(limit_pct);
        }

        const int64_t overall_hi_limit{(m_total_count * limit_pct) / 100};
        std::atomic< uint64_t > total_alloc{0}, total_dealloc{0};
        run_parallel(nthreads, num_iters, [&](const uint64_t iters_per_thread, std::atomic< bool >& terminate_flag) {
            uint64_t alloced_nblks{0};
            uint64_t freed_nblks{0};

            for (uint64_t i{0}; (i < iters_per_thread) && !terminate_flag; ++i) {
                const blk_count_t rand_size{size_generator()};
                const auto idx{nblks_to_idx(rand_size)};

                if (!m_slab_alloced_blks[idx].reached_hi_limit() &&
                    (m_alloced_count.load(std::memory_order_relaxed) < overall_hi_limit)) {
                    if (!alloc_rand_blk(BlkAllocStatus::SUCCESS, is_contiguous, rand_size, track_block_group)) {
                        terminate_flag = true;
                        continue;
                    }
                    alloced_nblks += rand_size;
                }

                if (!m_slab_alloced_blks[idx].reached_lo_limit()) {
                    blk_count_t freed_size{0};
                    while (freed_size < rand_size) {
                        const auto bid{
                            free_random_alloced_sized_blk(rand_size - freed_size, round_nblks, track_block_group)};
                        freed_nblks += bid.get_nblks();
                        freed_size += bid.get_nblks();
                    }
                }
            }
            LOGINFO("Alloced {} random blks and freed {} random blks in this thread", alloced_nblks, freed_nblks);
            total_alloc += alloced_nblks;
            total_dealloc += freed_nblks;
            return !terminate_flag;
        });
        LOGINFO("Total Alloced {} random blks and freed {} random blks in all thread", total_alloc.load(),
                total_dealloc.load());
        return {total_alloc, total_dealloc};
    }
};

TEST_F(FixedBlkAllocatorTest, alloc_free_fixed_size) {
    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};
    LOGINFO("Step 1: Pre allocate {} objects in {} threads", m_total_count / 2, nthreads);
    run_parallel(nthreads, m_total_count / 2,
                 [&](const uint64_t count_per_thread, std::atomic< bool >& terminate_flag) {
                     for (uint64_t i{0}; (i < count_per_thread) && !terminate_flag; ++i) {
                         BlkId bid;
                         if (!alloc_blk(BlkAllocStatus::SUCCESS, bid, false)) { terminate_flag = true; }
                     }
                 });
    validate_count();

    LOGINFO("Step 2: Free {} blks randomly in {} threads ", m_total_count / 4, nthreads);
    run_parallel(nthreads, m_total_count / 4,
                 [&](const uint64_t count_per_thread, std::atomic< bool >& terminate_flag) {
                     for (uint64_t i{0}; (i < count_per_thread) && !terminate_flag; ++i) {
                         [[maybe_unused]] const BlkId blkId{free_random_alloced_blk(false)};
                     }
                 });
    validate_count();

    LOGINFO("Step 3: Fill in the remaining {} blks to empty the device in {} threads", m_total_count * 3 / 4, nthreads);
    run_parallel(nthreads, m_total_count * 3 / 4,
                 [&](const uint64_t count_per_thread, std::atomic< bool >& terminate_flag) {
                     for (uint64_t i{0}; (i < count_per_thread) && !terminate_flag; ++i) {
                         BlkId bid;
                         if (!alloc_blk(BlkAllocStatus::SUCCESS, bid, false)) { terminate_flag = true; }
                     }
                 });
    validate_count();

    BlkId bid;
    LOGINFO("Step 4: Validate if further allocation result in space full error");
    ASSERT_TRUE(alloc_blk(BlkAllocStatus::SPACE_FULL, bid, false));

    LOGINFO("Step 5: Free up 2 blocks and make sure 2 more alloc is successful and do FIFO allocation");
    const BlkId free_bid1{free_random_alloced_blk(false)};
    const BlkId free_bid2{free_random_alloced_blk(false)};

    BlkId bid1;
    ASSERT_TRUE(alloc_blk(BlkAllocStatus::SUCCESS, bid1, false));
    BlkId bid2;
    ASSERT_TRUE(alloc_blk(BlkAllocStatus::SUCCESS, bid2, false));
    ASSERT_EQ(BlkId::compare(bid1, free_bid1), 0) << "Order of block allocation not expected";
    ASSERT_EQ(BlkId::compare(bid2, free_bid2), 0) << "Order of block allocation not expected";
    validate_count();
}

namespace {
void alloc_free_var_contiguous_unirandsize(VarsizeBlkAllocatorTest* const block_test_pointer) {
    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};
    const uint8_t prealloc_pct{5};
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct,
            block_test_pointer->m_total_count * prealloc_pct / 100, nthreads);
    [[maybe_unused]] const auto preload_alloced{
        block_test_pointer->preload(block_test_pointer->m_total_count * prealloc_pct / 100, true /* is_contiguous */,
                                    BlkAllocatorTest::uniform_rand_size, true)};

    auto num_iters{SISL_OPTIONS["iters"].as< uint64_t >()};
    const uint64_t divisor{1024};
    if (num_iters > block_test_pointer->m_total_count / divisor) {
        LOGINFO("For contiguous_unirandsize test, iters={} cannot be more than 1/{}th of total count={}. Adjusting",
                num_iters, divisor, block_test_pointer->m_total_count);
        num_iters = block_test_pointer->m_total_count / divisor;
    }
    const uint8_t runtime_pct{10};
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    const auto result{block_test_pointer->do_alloc_free(num_iters, true /* is_contiguous */,
                                                        BlkAllocatorTest::uniform_rand_size, runtime_pct,
                                                        false /* round_blks */, true)};
}
} // namespace

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_unirandsize_with_slabs) {
    // test with slabs
    create_allocator();
    alloc_free_var_contiguous_unirandsize(this);
}

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_unirandsize_without_slabs) {
    // test without slabs
    create_allocator(false);
    alloc_free_var_contiguous_unirandsize(this);
}

namespace {
void alloc_free_var_contiguous_roundrandsize(VarsizeBlkAllocatorTest* const block_test_pointer) {
    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};
    const uint8_t prealloc_pct{5};
    const uint64_t preload_amount{static_cast< uint64_t >(block_test_pointer->m_total_count * prealloc_pct / 100)};
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct, preload_amount,
            nthreads);
    [[maybe_unused]] const auto preload_alloced{
        block_test_pointer->preload(preload_amount, true /* is_contiguous */, BlkAllocatorTest::round_rand_size, true)};

    auto num_iters{SISL_OPTIONS["iters"].as< uint64_t >()};
    const uint64_t divisor{512};
    if (num_iters > block_test_pointer->m_total_count / divisor) {
        LOGINFO("For contiguous_unirandsize test, iters={} cannot be more than 1/{}th of total count={}. Adjusting",
                num_iters, divisor, block_test_pointer->m_total_count);
        num_iters = block_test_pointer->m_total_count / divisor;
    }
    const uint8_t runtime_pct{10};
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    [[maybe_unused]] const auto result{block_test_pointer->do_alloc_free(num_iters, true /* is_contiguous */,
                                                                         BlkAllocatorTest::round_rand_size, runtime_pct,
                                                                         true /* round_blks */, true)};
}
} // namespace

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_roundrandsize_with_slabs) {
    // test with slabs
    create_allocator();
    alloc_free_var_contiguous_roundrandsize(this);
}

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_roundrandsize_without_slabs) {
    // test without slabs
    create_allocator(false);
    alloc_free_var_contiguous_roundrandsize(this);
}

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_slabrandsize) {
    create_allocator();
    start_track_slabs();

    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};
    const uint8_t prealloc_pct{25};
    const uint64_t preload_amount{static_cast< uint64_t >(m_total_count) * prealloc_pct / 100};
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct, preload_amount,
            nthreads);
    [[maybe_unused]] const auto preload_alloced{
        preload(preload_amount, true /* is_contiguous */, BlkAllocatorTest::round_rand_size, true)};
    LOGINFO("Metrics after preallocate: {}", m_allocator->get_metrics_in_json().dump(4));

    auto num_iters{SISL_OPTIONS["iters"].as< uint64_t >()};
    const uint64_t divisor{1};
    if (num_iters > m_total_count / divisor) {
        LOGINFO("For contiguous_slabrandsize test, iters={} cannot be more than 1/{}th of total count={}. Adjusting",
                num_iters, divisor, m_total_count);
        num_iters = m_total_count / divisor;
    }
    const uint8_t runtime_pct{75};
    LOGINFO("Step 2: Do alloc/free contiguous blks with on slab sized ratio_range=[{}-{}] threads={} iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    [[maybe_unused]] const auto result{do_alloc_free(num_iters, true /* is_contiguous */,
                                                     BlkAllocatorTest::round_rand_size, runtime_pct,
                                                     false /* round_blks */, true)};
}

namespace {
void alloc_free_var_contiguous_onesize(VarsizeBlkAllocatorTest* const block_test_pointer) {
    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};

    const uint64_t preload_amount{static_cast< uint64_t >(block_test_pointer->m_total_count) / 2};
    LOGINFO("Step 1: Pre allocate 50% of total blks which is {} blks in {} threads", preload_amount, nthreads);
    const auto preload_alloced{
        block_test_pointer->preload(preload_amount, true /* is_contiguous */, BlkAllocatorTest::single_blk_size, true)};

    const auto num_iters{SISL_OPTIONS["iters"].as< uint64_t >()};
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size for blks span={}, threads={} iters={}",
            block_test_pointer->m_total_count, nthreads, num_iters);
    const auto result{block_test_pointer->do_alloc_free(
        num_iters, true /* is_contiguous */, BlkAllocatorTest::single_blk_size, 90, true /* round_blks */, true)};

    const uint64_t calculated_remaining{static_cast< uint64_t >(block_test_pointer->m_total_count) - preload_alloced +
                                        result.second - result.first};
    const uint64_t remaining{block_test_pointer->m_allocator->available_blks()};
    LOGINFO("Step 3: Reallocate to alloc all remaining count {} calculated remaining {}", remaining,
            calculated_remaining);
    [[maybe_unused]] const auto preload_alloced2{
        block_test_pointer->preload(remaining, true /* is_contiguous */, BlkAllocatorTest::single_blk_size, true)};

    ASSERT_EQ(block_test_pointer->m_allocator->available_blks(), 0u) << "Expected no blocks to be free";
}
}; // namespace

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_onesize_with_slabs) {
    // test with slabs
    create_allocator();
    alloc_free_var_contiguous_onesize(this);
}
#if 0
TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_contiguous_onesize_without_slabs) {
    // test with slabs
    create_allocator(false);
    alloc_free_var_contiguous_onesize(this);
}
#endif
namespace {
void alloc_free_var_scatter_unirandsize(VarsizeBlkAllocatorTest* const block_test_pointer) {
    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};
    const uint8_t prealloc_pct{50};

    const uint64_t preload_amount{static_cast< uint64_t >(block_test_pointer->m_total_count) * prealloc_pct / 100};
    LOGINFO("Step 1: Pre allocate {}% of total blks which is {} blks in {} threads", prealloc_pct, preload_amount,
            nthreads);
    const auto preload_alloced{block_test_pointer->preload(preload_amount, false /* is_contiguous */,
                                                           BlkAllocatorTest::uniform_rand_size, true)};
    const uint64_t remaining_after_preload{block_test_pointer->m_total_count - preload_alloced};
    ASSERT_EQ(block_test_pointer->m_allocator->available_blks(), remaining_after_preload)
        << "Expected available to match";

    const auto num_iters{SISL_OPTIONS["iters"].as< uint64_t >()};
    const uint8_t runtime_pct{75};
    LOGINFO("Step 2: Do alloc/free contiguous blks with completely random size ratio_range=[{}-{}] threads={} "
            "iters={}",
            prealloc_pct, runtime_pct, nthreads, num_iters);
    const auto result{block_test_pointer->do_alloc_free(num_iters, false /* is_contiguous */,
                                                        BlkAllocatorTest::uniform_rand_size, runtime_pct,
                                                        false /* round_blks */, true)};
    // wait for any sweeping to complete.
    const uint64_t calculated_remaining{remaining_after_preload + result.second - result.first};
    const uint64_t remaining{block_test_pointer->m_allocator->available_blks()};
    LOGINFO("Step 3: Reallocate to alloc all remaining count {} calculated remaining {}", remaining,
            calculated_remaining);
    [[maybe_unused]] const auto preload_alloced2{
        block_test_pointer->preload(remaining, false /* is_contiguous */, BlkAllocatorTest::single_blk_size, true)};
    ASSERT_EQ(block_test_pointer->m_allocator->available_blks(), 0u) << "Expected no blocks to be free";
}
} // namespace

TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_scatter_unirandsize_with_slabs) {
    // test with slabs
    create_allocator();
    alloc_free_var_scatter_unirandsize(this);
}

#if 0
TEST_F(VarsizeBlkAllocatorTest, alloc_free_var_scatter_unirandsize_without_slabs) {
    // test without slabs
    create_allocator(false);
    alloc_free_var_scatter_unirandsize(this);
}
#endif

namespace {
void alloc_var_scatter_direct_unirandsize(VarsizeBlkAllocatorTest* const block_test_pointer) {
    LOGINFO("Step 1: Set the flip to force directly bypassing freeblk cache");
#ifdef _PRERELEASE
    flip::FlipClient* const fc{iomgr_flip::client_instance()};
    flip::FlipFrequency freq;
    freq.set_count(static_cast< uint32_t >(block_test_pointer->m_total_count) * 1000);
    freq.set_percent(100);
    fc->inject_noreturn_flip("varsize_blkalloc_bypass_cache", {}, freq);
#endif
    const uint8_t prealloc_pct{90};
    const uint64_t preload_amount{static_cast< uint64_t >(block_test_pointer->m_total_count) * prealloc_pct / 100};
    const auto nthreads{
        std::clamp< uint32_t >(std::thread::hardware_concurrency(), 2, SISL_OPTIONS["num_threads"].as< uint32_t >())};
    LOGINFO("Step 2: Alloc upto {}% of space which is {} blks in {} threads as scattered blks", prealloc_pct,
            preload_amount, nthreads);
    const auto preload_alloced{block_test_pointer->preload(preload_amount, false /* is_contiguous */,
                                                           BlkAllocatorTest::uniform_rand_size, true)};

    const uint64_t remaining{block_test_pointer->m_allocator->available_blks()};
    const uint64_t calculated_remaining{block_test_pointer->m_total_count - preload_alloced};
    LOGINFO("Step 3: Reallocate to alloc all remaining count {} calculated remaining {}", remaining,
            calculated_remaining);
    [[maybe_unused]] const auto preload_alloced2{
        block_test_pointer->preload(remaining, false /* is_contiguous */, BlkAllocatorTest::single_blk_size, true)};
    ASSERT_EQ(block_test_pointer->m_allocator->available_blks(), 0u) << "Expected no blocks to be free";
}
} // namespace

#if 0
TEST_F(VarsizeBlkAllocatorTest, alloc_var_scatter_direct_unirandsize_with_slabs) {
    // test with slabs
    create_allocator();
    alloc_var_scatter_direct_unirandsize(this);
}

TEST_F(VarsizeBlkAllocatorTest, alloc_var_scatter_direct_unirandsize_without_slabs) {
    // test without slabs
    create_allocator(false);
    alloc_var_scatter_direct_unirandsize(this);
}
#endif
template < typename T >
std::shared_ptr< cxxopts::Value > opt_default(const char* val) {
    return ::cxxopts::value< T >()->default_value(val);
}

#define ENABLED_OPTIONS logging, test_blkalloc
SISL_OPTIONS_ENABLE(ENABLED_OPTIONS)

SISL_OPTION_GROUP(test_blkalloc,
                  (num_blks, "", "num_blks", "number of blks", opt_default< uint32_t >("1000000"), "number"),
                  (iters, "", "iters", "number of iterations", opt_default< uint64_t >("100000"), "number"),
                  (num_threads, "", "num_threads", "num_threads", opt_default< uint32_t >("8"), "number"))

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sisl::logging::SetLogger("test_blkalloc");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%t] %v");
    const int result{RUN_ALL_TESTS()};
    return result;
}
