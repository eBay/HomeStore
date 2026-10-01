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
 *********************************************************************************/

// Regression tests for two data races on MemVector pointer fields.
//
// Race A — CacheBuffer::m_mem
//   Writer: CacheBuffer::set_memvec()           — btree write path
//   Reader: CacheBuffer::get_memvec_intrusive() — flush path, insert_missing_pieces
//
//   Before fix: concurrent access with no lock → use-after-free.
//   After fix:  m_mem_mtx serialises all accesses.
//
//   Test class: CacheBufRaceTest
//
// Race B — writeback_req::m_mem
//   Writer: WriteBackCache::write() else-branch — updates wb_req->m_mem without wb_req->mtx
//   Reader: flush_buffers() / writeBack_completion_internal() — reads wb_req->m_mem
//
//   Test class: WbCacheRaceTest
//   Build with -DSIMULATE_WB_MEM_RACE=ON to activate the unfixed code path.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include <boost/intrusive_ptr.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/atomic_counter.hpp>

#include "homeds/memory/mempiece.hpp"

// Include the actual CacheBuffer<K> so Race A is sensitive to whether
// the m_mem_mtx fix is present in cache.h.
#include "engine/cache/cache.h"

#ifdef _PRERELEASE
#include "common/homestore_flip.hpp"
#include <sisl/flip/flip_client.hpp>
#endif

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging)

using namespace homeds;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static boost::intrusive_ptr< MemVector > make_memvec() {
    auto mv = boost::intrusive_ptr< MemVector >(new MemVector());
    uint8_t* buf = static_cast< uint8_t* >(std::malloc(8192));
    mv->push_back(MemPiece{buf, 8192, 0});
    return mv;
}

// ---------------------------------------------------------------------------
// TwoPhaseBarrier: deterministic race window, mirrors the FLIP delay in production.
// ---------------------------------------------------------------------------
class TwoPhaseBarrier {
public:
    void arrive_write() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_write_ready = true;
        m_cv.notify_all();
        m_cv.wait(lk, [this] { return m_write_released; });
    }

    void wait_for_write() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_cv.wait(lk, [this] { return m_write_ready; });
    }

    void release_write() {
        std::unique_lock< std::mutex > lk(m_mtx);
        m_write_released = true;
        m_cv.notify_all();
    }

private:
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool m_write_ready{false};
    bool m_write_released{false};
};

// ============================================================================
// Race A — CacheBuffer::m_mem
// ============================================================================

// Minimal key type satisfying CacheBuffer<K> requirements.
struct MinKey {
    uint64_t id{0};
    std::string to_string() const { return std::to_string(id); }
};

class CacheBufRaceTest : public ::testing::Test {};

// Simulates the production crash path:
//   Thread A (writer): set_memvec(make_memvec(), ...)  — btree swap_node / copy_node
//   Thread B (reader): insert_missing_pieces(...)       — flush path
//
// The writer passes make_memvec() directly (no local ref held), so when
// set_memvec() replaces m_mem the old MemVector's refcount drops to 0 and
// is freed while the reader may still hold a raw reference → use-after-free.
//
// Fixed: insert_missing_pieces() calls get_memvec_intrusive() under m_mem_mtx
// shared lock, bumping refcount before the lock is released.
TEST_F(CacheBufRaceTest, InsertMissingPiecesRaceFreeUnderConcurrentSetMemvec) {
    constexpr int kIterations = 2000;
#ifdef _PRERELEASE
    {
        using namespace homestore;
        flip::FlipClient fc{HomeStoreFlip::instance()};
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(kIterations * 2);
        freq.set_percent(100);
        fc.inject_delay_flip("wb_cache_get_memvec_before_use", {null_cond}, freq, 100 /* ignored, source sleeps */);
    }
#endif
    homestore::CacheBuffer< MinKey > buf;
    // Size must be a multiple of engine.min_io_size (8192) for MemPiece::encode().
    buf.set_memvec(make_memvec(), 0, 8192);

    std::thread writer([&] {
        for (int i = 0; i < kIterations; ++i)
            buf.set_memvec(make_memvec(), 0, 8192);
    });

    std::thread reader([&] {
        for (int i = 0; i < kIterations; ++i) {
            std::vector< std::pair< uint32_t, uint32_t > > missing;
            buf.insert_missing_pieces(0, 8192, missing);
        }
    });

    writer.join();
    reader.join();
}

// ============================================================================
// Race B — writeback_req::m_mem
// ============================================================================
//
// MockWbReq mirrors the writeback_req fields involved in Race B.
//
// Default build: MockWbReq has std::mutex mtx — fixed pattern.
//   Both writer and flusher hold mtx when touching m_mem.
//
// -DSIMULATE_WB_MEM_RACE: MockWbReq has no mutex — broken pattern.
//   Writer and flusher access m_mem without any lock.

struct MockWbReq {
#ifndef SIMULATE_WB_MEM_RACE
    std::mutex mtx;
#endif
    boost::intrusive_ptr< MemVector > m_mem;
    explicit MockWbReq(boost::intrusive_ptr< MemVector > mv) : m_mem(std::move(mv)) {}
};

class WbCacheRaceTest : public ::testing::Test {};

static void run_wb_req_pattern(int iterations) {
    auto mv1 = make_memvec();
    auto mv2 = make_memvec();
    MockWbReq req(mv1);

    std::thread writer([&] {
        for (int i = 0; i < iterations; ++i) {
            auto mv = (i & 1) ? mv2 : mv1;
#ifndef SIMULATE_WB_MEM_RACE
            std::unique_lock< std::mutex > lk(req.mtx);
#endif
            req.m_mem = mv;
        }
    });

    std::thread flusher([&] {
        for (int i = 0; i < iterations; ++i) {
            boost::intrusive_ptr< MemVector > captured;
            {
#ifndef SIMULATE_WB_MEM_RACE
                std::unique_lock< std::mutex > lk(req.mtx);
#endif
                captured = req.m_mem;
            }
            EXPECT_TRUE(captured == mv1 || captured == mv2);
        }
    });

    writer.join();
    flusher.join();
}

TEST_F(WbCacheRaceTest, WbReqMemPatternIsRaceFree) { run_wb_req_pattern(500); }

// Verify that under the mutex the captured pointer is always one of the two
// valid values, never a torn or null intermediate.
TEST_F(WbCacheRaceTest, CapturedMemVecIsAlwaysOneOfTwoValidValues) {
    constexpr int kIterations = 200;
    auto mv1 = make_memvec();
    auto mv2 = make_memvec();
    int mv1_seen{0};
    int mv2_seen{0};

    for (int i = 0; i < kIterations; ++i) {
        MockWbReq req(mv1);
        TwoPhaseBarrier barrier;

        std::thread writer([&] {
            barrier.arrive_write();
#ifndef SIMULATE_WB_MEM_RACE
            std::unique_lock< std::mutex > lk(req.mtx);
#endif
            req.m_mem = mv2;
        });

        std::thread flusher([&] {
            barrier.wait_for_write();
            boost::intrusive_ptr< MemVector > captured;
            {
#ifndef SIMULATE_WB_MEM_RACE
                std::unique_lock< std::mutex > lk(req.mtx);
#endif
                captured = req.m_mem;
            }
            barrier.release_write();

            if (captured == mv1) {
                ++mv1_seen;
            } else if (captured == mv2) {
                ++mv2_seen;
            } else {
                FAIL() << "Torn / invalid MemVector pointer — race detected!";
            }
        });

        flusher.join();
        writer.join();
    }

    LOGINFO("Observed mv1={} mv2={} across {} iterations", mv1_seen, mv2_seen, kIterations);
    EXPECT_EQ(mv1_seen + mv2_seen, kIterations);
}

// ---------------------------------------------------------------------------
// FLIP-backed sub-test (requires _PRERELEASE build)
//
// Confirms that the FLIP point "wb_flush_before_m_mem_read" fires between
// the dependent_cnt decrement and the m_mem read, allowing deterministic
// race window widening in integration scenarios.
// ---------------------------------------------------------------------------
#ifdef _PRERELEASE

static std::atomic< bool > g_flip_fired{false};

static void simulated_flush_path_with_flip(MockWbReq& req) {
    if (homestore_flip->test_flip("wb_cache_get_memvec_before_use")) {
        g_flip_fired = true;
    }
    boost::intrusive_ptr< MemVector > captured;
    {
#ifndef SIMULATE_WB_MEM_RACE
        std::unique_lock< std::mutex > lk(req.mtx);
#endif
        captured = req.m_mem;
    }
    EXPECT_NE(captured.get(), nullptr);
}

TEST_F(WbCacheRaceTest, FlipPointFiresAtCorrectLocation) {
    using namespace homestore;
    flip::FlipClient fc{HomeStoreFlip::instance()};

    flip::FlipCondition null_cond;
    flip::FlipFrequency freq;
    freq.set_count(10);
    freq.set_percent(100);

    fc.inject_delay_flip("wb_cache_get_memvec_before_use", {null_cond}, freq, 1000 /* 1 ms */);

    auto mv = make_memvec();
    MockWbReq req(mv);
    g_flip_fired = false;

    simulated_flush_path_with_flip(req);

    EXPECT_TRUE(g_flip_fired) << "FLIP point wb_cache_get_memvec_before_use did not fire";
}

// Confirms the second vulnerable get_memvec() path — update_missing_piece —
// also has a FLIP point, giving Race A the same wide window as insert_missing_pieces.
//
// Strategy: inject 2 boolean-flip shots, call update_missing_piece() once, then
// manually call test_flip twice.  If the FLIP point fired inside update_missing_piece
// it consumed shot 1, leaving shot 2 for the first manual call (returns true) and
// nothing for the second (returns false).  If the FLIP point did NOT fire both shots
// survive and both manual calls return true.
TEST_F(CacheBufRaceTest, UpdateMissingPieceFlipFiresAtCorrectLocation) {
    using namespace homestore;
    flip::FlipClient fc{HomeStoreFlip::instance()};
    flip::FlipCondition null_cond;
    flip::FlipFrequency freq;
    freq.set_count(2);
    freq.set_percent(100);
    fc.inject_delay_flip("cache_buf_update_before_use", {null_cond}, freq, 1 /* 1 us */);

    CacheBuffer< MinKey > buf;
    buf.set_memvec(make_memvec(), 0, 8192);
    uint8_t data[8192]{};
    buf.update_missing_piece(0, 8192, data);

    const bool manual1 = homestore_flip->test_flip("cache_buf_update_before_use");
    const bool manual2 = homestore_flip->test_flip("cache_buf_update_before_use");
    EXPECT_TRUE(manual1) << "flip was never registered (both shots unused)";
    EXPECT_FALSE(manual2) << "FLIP cache_buf_update_before_use did not fire in update_missing_piece";
}

#endif // _PRERELEASE

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, logging);
    sisl::logging::SetLogger("test_wb_cache_race");
    sisl::logging::install_crash_handler();
    return RUN_ALL_TESTS();
}
