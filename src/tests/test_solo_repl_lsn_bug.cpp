/*
 * Unit tests for the SoloReplDev out-of-order LSN / fixed-threshold replay fix.
 *
 * These tests simulate the core logic of on_log_found in isolation, without spinning
 * up a full HomeStore stack.  They are intentionally lightweight (no I/O, no SPDK).
 *
 * Background: the logstore LSN counter (log_store.cpp) and the log-device physical
 * position counter (log_dev.cpp) are independent atomics with no lock between them.
 * Under concurrent writes a thread can be preempted after taking its LSN but before
 * taking its physical position, causing physical order to diverge from LSN order on
 * disk.  On recovery, log entries are delivered in physical order, so a lower-numbered
 * LSN can arrive after a higher-numbered one.
 *
 * The original on_log_found used m_commit_upto — a value that advances as each entry
 * is replayed — as the skip threshold.  After replaying lsn=4, the threshold becomes 4,
 * and a subsequently delivered lsn=2 is wrongly skipped.
 *
 * The fix: read m_rd_sb->durable_commit_lsn once at entry and use that fixed value as
 * the threshold throughout the callback.  m_commit_upto still advances (needed by
 * cp_flush), but it is no longer used to decide whether to skip an entry.
 */

#include <atomic>
#include <algorithm>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

// ---------------------------------------------------------------------------
// 1. Counter race (disabled — probabilistic, run manually to observe the race)
//
//    Demonstrates that two independent fetch_adds produce non-monotonic LSN
//    ordering when sorted by physical log position.  Mirrors log_store.cpp:89
//    (LSN counter) and log_dev.cpp:297 (log-device position counter).
// ---------------------------------------------------------------------------
TEST(SoloReplLsnBug, DISABLED_CounterRace) {
    std::atomic< int64_t > lsn_counter{0};
    std::atomic< int64_t > logidx_counter{0};

    struct Entry {
        int64_t lsn;
        int64_t log_idx;
    };
    std::vector< Entry > entries;
    std::mutex mu;

    const int N = 500;
    std::vector< std::thread > threads;
    threads.reserve(N);

    for (int i = 0; i < N; ++i) {
        threads.emplace_back([&] {
            int64_t lsn = lsn_counter.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::yield(); // widen the race window
            int64_t idx = logidx_counter.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard< std::mutex > lock{mu};
            entries.push_back({lsn, idx});
        });
    }
    for (auto& t : threads) {
        t.join();
    }

    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return a.log_idx < b.log_idx;
    });

    bool found_out_of_order = false;
    for (int i = 1; i < static_cast< int >(entries.size()); ++i) {
        if (entries[i].lsn < entries[i - 1].lsn) {
            found_out_of_order = true;
            break;
        }
    }

    EXPECT_TRUE(found_out_of_order) << "Race did not manifest on this run — try again under load";
}

// ---------------------------------------------------------------------------
// 2. Regression test: fixed threshold recovers all entries in physical order
//    [1, 3, 4, 2] — the case the bug would have corrupted.
//
//    Mirrors the fixed on_log_found: compare each lsn against the static
//    durable_commit_lsn read once from the superblock, never update it.
// ---------------------------------------------------------------------------
TEST(SoloReplLsnBug, FixedThresholdRecoversAll) {
    // Physical order on disk after a counter race: lsn=2 landed after lsns 1,3,4.
    const std::vector< int64_t > physical_order = {1, 3, 4, 2};

    // Simulates m_rd_sb->durable_commit_lsn — the last checkpointed LSN.
    // Nothing checkpointed before this crash, so the value is 0.
    const int64_t durable_lsn = 0;

    std::vector< int64_t > replayed;
    std::vector< int64_t > skipped;

    for (int64_t lsn : physical_order) {
        if (durable_lsn >= lsn) {
            skipped.push_back(lsn);
        } else {
            replayed.push_back(lsn);
        }
    }

    EXPECT_EQ(replayed.size(), 4u) << "All 4 entries should be replayed";
    EXPECT_TRUE(skipped.empty()) << "No entry should be skipped when durable_lsn=0";
}

// ---------------------------------------------------------------------------
// 3. Regression test: entries already in the last checkpoint are skipped.
//
//    When the system had checkpointed up through lsn=3 before the crash,
//    lsns 1 and 3 should be skipped and lsns 4+ replayed.
// ---------------------------------------------------------------------------
TEST(SoloReplLsnBug, FixedThresholdSkipsCheckpointedEntries) {
    const std::vector< int64_t > physical_order = {1, 3, 4, 2};
    const int64_t durable_lsn = 3; // checkpointed through lsn=3

    std::vector< int64_t > replayed;
    std::vector< int64_t > skipped;

    for (int64_t lsn : physical_order) {
        if (durable_lsn >= lsn) {
            skipped.push_back(lsn);
        } else {
            replayed.push_back(lsn);
        }
    }

    // lsn=1 and lsn=2 are <= durable_lsn=3, so both are skipped.
    // lsn=3 is exactly the checkpoint — also skipped (already committed).
    // lsn=4 is beyond the checkpoint — replayed.
    EXPECT_EQ(replayed.size(), 1u) << "Only lsn=4 should be replayed";
    EXPECT_EQ(replayed[0], 4);
    EXPECT_EQ(skipped.size(), 3u) << "lsns 1, 3, 2 should be skipped";
}

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
