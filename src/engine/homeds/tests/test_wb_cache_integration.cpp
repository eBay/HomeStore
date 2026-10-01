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

// ============================================================================
// Race B integration test — WriteBackCache::write() else-branch + flush_buffers()
// ============================================================================
//
// Exercises the actual WriteBackCache write path on a live homestore instance
// (real SSD btree, real blkstore, real CP machinery).
//
// Race B:
//   Writer: WriteBackCache::write() else-branch — updates wb_req->m_mem
//           while holding the btree node write lock (NOT wb_req->mtx, before fix)
//   Reader: flush_buffers() — reads wb_req->m_mem to pass to blkstore->write()
//
// Reproduction (requires _PRERELEASE):
//   1. Write a key into the SSD btree → wb_req created for current CP
//   2. Inject "wb_flush_before_m_mem_read" delay flip → flush thread pauses
//      between dependent_cnt decrement and wb_req->m_mem read
//   3. Write the same key again (same CP) → else-branch updates wb_req->m_mem
//   4. Delay expires → flush thread reads wb_req->m_mem
// ============================================================================

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _PRERELEASE
#include "engine/common/homestore_flip.hpp"
#include <sisl/flip/flip_client.hpp>
#endif

#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#endif

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/utility/obj_life_counter.hpp>

#include "api/vol_interface.hpp"
#include "engine/homeds/btree/btree.hpp"
#include "engine/index/indx_mgr.hpp"
#include "homeblks/home_blks.hpp"
#include "homeblks/volume/mapping.hpp"
#include "test_common/homestore_test_common.hpp"

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging)

RCU_REGISTER_INIT

using namespace homestore;
using namespace homeds::btree;

namespace fs = std::filesystem;

// ============================================================================
// Types
// ============================================================================

// Must match BLKSTORE_BUFFER_TYPE used by the index blkstore so that
// dynamic_pointer_cast in blkstore's process_completions succeeds.
using WbTestBtree = Btree< btree_store_type::SSD_BTREE, MappingKey, MappingValue,
                           btree_node_type::VAR_VALUE, btree_node_type::VAR_VALUE >;

static constexpr uint64_t DISK_SIZE{2 * 1024 * 1024 * 1024ULL}; // 2 GiB
static const std::string DISK_FILE{"wbcache_integration_test_disk"};

// ============================================================================
// Fixture
// ============================================================================
//
// Homestore (VolInterface) does NOT support re-initialization in the same
// process: on_io_thread_start callbacks registered by internal modules hold
// a reference to the old HomeBlks singleton; after shutdown the pointer is
// null and the second init crashes before HomeBlks is constructed.
//
// Fix: start/stop homestore once per test suite (SetUpTestSuite /
// TearDownTestSuite).  Each test gets a fresh standalone btree pointing at
// the shared index blkstore; per-test SetUp / TearDown create and flush it.

class WbCacheIntegrationTest : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        (void)fs::remove(DISK_FILE);
        auto fd = ::open(DISK_FILE.c_str(), O_RDWR | O_CREAT | O_DIRECT, 0666);
        ASSERT_GE(fd, 0) << "failed to open disk file";
        ASSERT_EQ(::fallocate(fd, 0, 0, static_cast< off_t >(DISK_SIZE)), 0) << "fallocate failed";
        ::close(fd);

        ioenvironment.with_iomgr(2 /* threads */, false /* spdk */);

        std::vector< dev_info > device_info;
        device_info.emplace_back(fs::canonical(DISK_FILE).string(), HSDevType::Data);

        init_params params;
        params.data_open_flags = io_flag::BUFFERED_IO;
        params.fast_open_flags = io_flag::BUFFERED_IO;
        params.min_virtual_page_size = 4096;
        params.app_mem_size = static_cast< uint64_t >(1) * 1024 * 1024 * 1024;
        params.data_devices = device_info;
        params.init_done_cb = [](std::error_condition err, const out_params&) { on_init_done(err); };
        params.vol_mounted_cb = [](const VolumePtr&, vol_state) {};
        params.vol_state_change_cb = [](const VolumePtr&, vol_state, vol_state) {};
        params.vol_found_cb = [](const boost::uuids::uuid) { return true; };

        test_common::set_random_http_port();
        VolInterface::init(params);

        std::unique_lock< std::mutex > lk{s_init_mtx};
        s_init_cv.wait(lk, [] { return s_init_done; });
        ASSERT_FALSE(s_init_failed) << "homestore init failed";
    }

    static void TearDownTestSuite() { fs::remove(DISK_FILE); }

protected:
    void SetUp() override {
        // Each test gets its own standalone btree against the shared blkstore.
        // The btree is not registered with StaticIndxMgr; cp_start is called
        // directly in TearDown to drain dirty wb_cache buffers.
        BtreeConfig cfg{4096};
        cfg.set_max_objs(100000);
        cfg.set_max_key_size(sizeof(uint32_t));
        cfg.set_max_value_size(4096);
        cfg.blkstore = HomeBlks::instance()->get_index_blkstore();
        m_btree = std::unique_ptr< WbTestBtree >(WbTestBtree::create_btree(cfg));
        m_bcp = m_btree->attach_prepare_cp(nullptr, false, false);
    }

    void TearDown() override {
        std::mutex mtx;
        std::condition_variable cv;
        bool done{false};
        m_btree->cp_start(m_bcp, [&](const btree_cp_ptr&) {
            std::unique_lock< std::mutex > lk{mtx};
            done = true;
            cv.notify_one();
        });
        std::unique_lock< std::mutex > lk{mtx};
        cv.wait(lk, [&] { return done; });
        m_btree.reset();
    }

    void btree_put(uint64_t key_id) {
        MappingKey k{static_cast< lba_t >(key_id), 1};
        // MappingValue() leaves m_earr uninitialized; alloc_element is only called from
        // the parameterized constructors. Use a placeholder BlkId so the value is valid.
        MappingValue v{static_cast< seq_id_t >(0), BlkId{blk_num_t{1}, blk_count_t{1}}};
        m_btree->put(k, v, btree_put_type::REPLACE_IF_EXISTS_ELSE_INSERT, &v, m_bcp);
    }

    void flush_cp() {
        std::mutex mtx;
        std::condition_variable cv;
        bool done{false};
        StaticIndxMgr::trigger_indx_cp_with_cb([&](bool) {
            std::unique_lock< std::mutex > lk{mtx};
            done = true;
            cv.notify_one();
        });
        std::unique_lock< std::mutex > lk{mtx};
        cv.wait(lk, [&] { return done; });
    }

    btree_cp_ptr advance_cp() {
        btree_cp_ptr old = m_bcp;
        m_bcp = m_btree->attach_prepare_cp(old, false, false);
        return old;
    }

    void flush_cp_async(const btree_cp_ptr& old_bcp, std::function< void() > done_cb) {
        m_btree->cp_start(old_bcp, [cb = std::move(done_cb)](const btree_cp_ptr&) { cb(); });
    }

private:
    static void on_init_done(std::error_condition err) {
        std::unique_lock< std::mutex > lk{s_init_mtx};
        s_init_failed = static_cast< bool >(err);
        s_init_done = true;
        s_init_cv.notify_one();
    }

    std::unique_ptr< WbTestBtree > m_btree;
    btree_cp_ptr m_bcp;

    static std::mutex s_init_mtx;
    static std::condition_variable s_init_cv;
    static bool s_init_done;
    static bool s_init_failed;
};

std::mutex WbCacheIntegrationTest::s_init_mtx;
std::condition_variable WbCacheIntegrationTest::s_init_cv;
bool WbCacheIntegrationTest::s_init_done{false};
bool WbCacheIntegrationTest::s_init_failed{false};

// ============================================================================
// Tests
// ============================================================================

// Verifies that concurrent btree writes and CP flushes on a live homestore
// instance do not produce a data race on wb_req->m_mem.
//
// Both WriteBackCache::write() else-branch and flush_buffers() must hold
// wb_req->mtx when accessing wb_req->m_mem.
TEST_F(WbCacheIntegrationTest, ConcurrentWriteAndFlushIsRaceFree) {
    constexpr int kNumKeys{20000};    // large enough to force many btree node splits
    constexpr int kNumIterations{3};  // each iteration: write burst + CP + write-again burst

    for (int iter = 0; iter < kNumIterations; ++iter) {
        // Phase 1: initial write pass — creates wb_req for current CP for each key
        for (int k = 0; k < kNumKeys; ++k) {
            btree_put(static_cast< uint64_t >(k));
        }

        // Phase 2: trigger CP flush in a background thread while concurrently
        //          re-writing the same keys (else-branch of WriteBackCache::write()).
        //
        // The flush thread will read wb_req->m_mem (under wb_req->mtx with fix).
        // The write threads will update wb_req->m_mem (under wb_req->mtx with fix).
        // Without the fix these two accesses are concurrent and unsynchronised.
        std::thread flusher{[this] { flush_cp(); }};

        // Write the same keys again from multiple threads while flush runs.
        // Small key space forces reuse of btree leaf nodes → else-branch fires.
        constexpr int kWriteThreads{4};
        std::vector< std::thread > writers;
        writers.reserve(kWriteThreads);
        for (int t = 0; t < kWriteThreads; ++t) {
            writers.emplace_back([this, t] {
                for (int k = 0; k < kNumKeys; ++k) {
                    btree_put(static_cast< uint64_t >(k + t * 1000));
                    btree_put(static_cast< uint64_t >(k)); // same key → same node → else-branch
                }
            });
        }

        for (auto& w : writers) { w.join(); }
        flusher.join();
    }
}

// ============================================================================
// Cross-CP Race A regression test (requires _PRERELEASE)
//
// Verifies that the existing FLIP point in insert_missing_pieces widens the
// race window exactly where Race A can fire:
//
//   read_and_lock_node() calls read_node() FIRST (no node lock held), THEN
//   lock_and_refresh_node().  The FLIP fires inside read_node() before any
//   lock is acquired, giving a concurrent CP1 writer time to:
//     1. Acquire the write lock on the same node
//     2. Call refresh_buf() → set_memvec(MV2) → MV1 refcount drops
//     3. Allow CP0 flush to complete → wb_req0 freed → MV1 refcount 0 → freed
//   Thread A resumes after the FLIP delay holding a stale raw reference to
//   the freed MV1 → UAF → SIGSEGV.  The fix must make Thread A hold a
//   refcounted intrusive_ptr so MV1 stays alive through the window.
// ============================================================================
#ifdef _PRERELEASE
TEST_F(WbCacheIntegrationTest, CrossCpMemvecRaceDetectedByFlip) {
    constexpr int kNumKeys = 500;

    // Phase 1: populate CP0 — each leaf node gets bn->bcp = CP0, bn->m_mem = MV1.
    for (int k = 0; k < kNumKeys; ++k) btree_put(static_cast< uint64_t >(k));

    // Advance to CP1 so subsequent writes trigger refresh_buf's cross-CP COW path.
    auto old_bcp = advance_cp();

    // Two FLIPs cooperate to make Race A deterministic:
    //
    // 1. wb_flush_delay_before_write (200ms): fires at the start of flush_buffers
    //    keeping all CP0 reqs in WB_REQ_WAITING while Phase 2 writers run
    //    refresh_buf → set_memvec(MV2) → MV1 refcount 2→1.
    //
    // 2. wb_cache_get_memvec_cp_delay (500ms): fires in insert_missing_pieces
    //    after the raw reference to MV1 is taken (no-fix) or the intrusive_ptr
    //    is captured (fix).  During this sleep CP0 flush completes, wb_req0 is
    //    freed → MV1 refcount 1→0 → freed.  On no-fix: Thread A wakes holding
    //    a dangling raw ref → UAF.  On fix: Thread A holds an intrusive_ptr
    //    that kept MV1 alive → no crash.
    {
        using namespace flip;
        FlipClient fc{HomeStoreFlip::instance()};
        FlipCondition null_cond;

        FlipFrequency freq_flush;
        freq_flush.set_count(1);
        freq_flush.set_percent(100);
        fc.inject_delay_flip("wb_flush_delay_before_write", {null_cond}, freq_flush, 1 /* ignored, source sleeps 200ms */);

        FlipFrequency freq;
        freq.set_count(3);
        freq.set_percent(100);
        fc.inject_delay_flip("wb_cache_get_memvec_cp_delay", {null_cond}, freq, 200000 /* ignored, source sleeps 500ms */);
    }

    // Fire CP0 flush async — does not wait here so it can race with Phase 2.
    std::mutex cp0_mtx;
    std::condition_variable cp0_cv;
    bool cp0_done{false};
    flush_cp_async(old_bcp, [&] {
        std::unique_lock< std::mutex > lk{cp0_mtx};
        cp0_done = true;
        cp0_cv.notify_one();
    });

    // Phase 2: concurrent CP1 writes to the same key range → same leaf nodes.
    // Without fix: Thread A's FLIP fires (no lock), Thread B gets write lock →
    // set_memvec(MV2) → MV1 freed by CP0 flush → Thread A crashes on resume.
    constexpr int kWriteThreads = 4;
    std::vector< std::thread > writers;
    writers.reserve(kWriteThreads);
    for (int t = 0; t < kWriteThreads; ++t) {
        writers.emplace_back([this, kNumKeys] {
            for (int k = 0; k < kNumKeys; ++k) btree_put(static_cast< uint64_t >(k));
        });
    }
    for (auto& w : writers) w.join();

    // Reached here: fix is in place.  Wait for CP0 flush so TearDown's
    // cp_start(m_bcp [CP1]) sees a clean wb_cache.
    std::unique_lock< std::mutex > lk{cp0_mtx};
    cp0_cv.wait(lk, [&] { return cp0_done; });
}
#endif // _PRERELEASE

// ============================================================================
// main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    SISL_OPTIONS_LOAD(argc, argv, logging);
    sisl::logging::SetLogger("test_wb_cache_integration");
    sisl::logging::install_crash_handler();
    const int ret{RUN_ALL_TESTS()};
    VolInterface::shutdown(true /* wait */);
    iomanager.stop();
    return ret;
}
