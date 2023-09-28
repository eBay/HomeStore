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

#include <gtest/gtest.h>

#include "blkdata_svc/blk_read_tracker.hpp"

using namespace homestore;

SISL_LOGGING_INIT(test_blk_read_tracker, iomgr, flip, io_wd)
SISL_OPTIONS_ENABLE(logging, test_blk_read_tracker)

class BlkReadTrackerTest : public testing::Test {
public:
    virtual void SetUp() override {
        LOGINFO("Step 0: initialize BlkReadTracker instance. ");
        init();
    }

    void init() { m_blk_read_tracker = std::make_unique< BlkReadTracker >(); }
    std::shared_ptr< BlkReadTracker > get_inst() { return m_blk_read_tracker; }

private:
    std::shared_ptr< BlkReadTracker > m_blk_read_tracker;
};

/*
 * 1. alignment: 16
 * 2. no overlap insert and remove without any waiter,
 * */
TEST_F(BlkReadTrackerTest, TestBaiscInsertRemoveWithNoWaiter) {
    LOGINFO("Step 1: set entries per record to 16");
    get_inst()->set_entries_per_record(16);

    const uint32_t nblkids = 128;
    const blk_count_t nblks = 64;
    blk_num_t start_blk_num{0};

    LOGINFO("Step 2: read {} BlkId (no overlap), with nblks:{} to hash map.", nblkids, nblks);
    for (uint32_t i = 0; i < nblkids; ++i) {
        // blk num:
        // first  : {0, 1, nblks-1},
        // second : { nblks, nblk+1, ..., 2*nblk -1},
        // so on so forth;
        get_inst()->insert(BlkId{start_blk_num, nblks, 0});
        start_blk_num += nblks;
    }

    LOGINFO("Step 3: remove {} BlkIds, with nblks {} from hash map.", nblkids, nblks);
    start_blk_num = 0;
    for (uint32_t i = 0; i < nblkids; ++i) {
        get_inst()->remove(BlkId{start_blk_num, nblks, 0});
        start_blk_num += nblks;
    }
}

/*
 * alignment: 16
 * */
TEST_F(BlkReadTrackerTest, TestOverlapInsertThenRemoveWithNoWaiter) {
    LOGINFO("Step 1: set entries per record to 16");
    get_inst()->set_entries_per_record(16);

    LOGINFO("Step 2: read olverlaped BlkIds to hash map.");

    // insert same BlkId to accumulate ref_cnt;
    BlkId b{100, 64, 10};
    get_inst()->insert(b);
    get_inst()->insert(b);
    get_inst()->insert(b);

    // different chunk
    BlkId c{100, 64, 2};
    get_inst()->insert(c);
    get_inst()->insert(c);

    get_inst()->remove(b);
    get_inst()->remove(b);
    get_inst()->remove(b);

    get_inst()->remove(c);
    get_inst()->remove(c);

    // differnt BlkId with same base ID (after alignment)
    get_inst()->insert(BlkId{70, 51, 5});
    get_inst()->insert(BlkId{72, 50, 5});
    get_inst()->insert(BlkId{68, 44, 5});

    get_inst()->remove(BlkId{70, 51, 5});
    get_inst()->remove(BlkId{72, 50, 5});
    get_inst()->remove(BlkId{68, 44, 5});
}

/*
 * waiter overlap with read, but there is no read completes, waiter's cb should NOT be triggered;
 * */
TEST_F(BlkReadTrackerTest, TestInsertWithWaiter) {

    BlkId b{16, 20, 0};
    get_inst()->insert(b);

    bool called{false};
    get_inst()->wait_on(b, [&called, &b]() {
        LOGMSG_ASSERT_EQ(called, false, "not expecting wait_on callback to be called more than once!");
        called = true;
        LOGINFO("wait_on called on blkid: {};", b.to_string());
    });

    // cb should be called in same thread serving remove;
    assert(!called);

    // remove the record so that waiter can be destroyed to avoid crash in shared_ptr<BlkTrackRecord>::~shared_ptr on
    // exit of this test case;
    get_inst()->remove(b);
}

/*
 * free same blkid as read.
 * free bid callback should be called after read completes
 * */
TEST_F(BlkReadTrackerTest, TestInsRmWithWaiterOnSameBid) {
    BlkId b{16, 20, 0};
    LOGINFO("Step 1: read blkid: {} into hash map.", b.to_string());
    get_inst()->insert(b);

    bool called{false};
    LOGINFO("Step 2: free blkid: {} to be completed on reading");
    get_inst()->wait_on(b, [&called, &b]() {
        LOGMSG_ASSERT_EQ(called, false, "not expecting wait_on callback to be called more than once!");
        called = true;
        LOGINFO("wait_on callback triggered on blkid: {};", b.to_string());
    });

    LOGINFO("Step 3: try to do read completed on blkid: {}. ", b.to_string());
    get_inst()->remove(b);

    // cb should be called in same thread serving remove;
    LOGINFO("Step 4: assert that callback is triggered by read complete.");
    assert(called);
}

/*
 * Alignment:16
 * 1. read-1: {16, 40, 0} // read on two base ids: {16, 16, 0}, {32, 16, 0}, {48, 16, 0}
 * 2. free: {10, 8, 0, cb1} // across two base ids, {0, 16, 0}, {16, 16, 0} , overlap with read-1 on 2nd base id;
 * 3. read-2: {64, 8, 0} // read on base id: {64, 16, 0}, which not overlap with free's base id
 * 4. read-2: complete;  // callback of free should not be triggered
 * 5. read-1 complete;  // callback of free should be triggered;
 *
 * free cb1 should be called only after read-1 completes;
 * */
TEST_F(BlkReadTrackerTest, TestInsRmeWithWaiterOverlapOneRead) {
    auto align = 16ul;
    LOGINFO("Step 1: set entries per record to {}.", align);
    get_inst()->set_entries_per_record(align);

    BlkId b{16, 40, 0};
    LOGINFO("Step 2: read on blkid: {}. ", b.to_string());
    get_inst()->insert(b);

    bool called{false};
    BlkId free_bid{10, 8, 0};
    LOGINFO("Step 3: free blkid: {}.", free_bid);
    get_inst()->wait_on(free_bid, [&called, &free_bid]() {
        LOGMSG_ASSERT_EQ(called, false, "not expecting wait_on callback to be called more than once!");
        called = true;
        LOGINFO("wait_on callback triggered on blkid: {}.", free_bid.to_string());
    });

    BlkId c{64, 8, 0};
    LOGINFO("Step 4: read on blkid: {}.", c.to_string());
    get_inst()->insert(c);

    LOGINFO("Step 5a: read on blkid: {} completed.", c.to_string());
    get_inst()->remove(c);

    LOGINFO("Step 5b: assert callback on free_bid should NOT be triggered.");
    assert(!called);

    LOGINFO("Step 6a: read on blkid: {} completed. ", b.to_string());
    get_inst()->remove(b);

    LOGINFO("Step 6b: assert callback should be triggered");
    assert(called);
}

/*
 *  Alignment: 16
 *  Read-1, free-blk, Read-2
 *
 *  1. Read-1: {35, 20, 0}, covers two base ids: {32, 16, 0}, {48, 16, 0}
 *  2. free: {36, 2, 0}, covers base id: {32, 16, 0}
 *  3. Read-2: {40, 5, 0} covers same base id as free {32, 16, 0}
 *  4. Read-2 completes // <<< free cb should not be triggered
 *  5. Read-1 completes // <<< free cb should be triggered
 * */
TEST_F(BlkReadTrackerTest, TestInsRmWithWaiterOverlapMultiReads0) {
    auto align = 16ul;
    LOGINFO("Step 1: set entries per record to {}.", align);
    get_inst()->set_entries_per_record(align);

    BlkId b{35, 20, 0};
    LOGINFO("Step 2: read 1 blkid: {}.", b.to_string());
    get_inst()->insert(b);

    BlkId free_bid{36, 2, 0};
    LOGINFO("Step 3: free blkid: {}.", free_bid.to_string());
    bool called{false};
    get_inst()->wait_on(free_bid, [&free_bid, &called]() {
        LOGMSG_ASSERT_EQ(called, false, "not expecting wait_on callback to be called more than once!");
        called = true;
        LOGINFO("wait on callback triggered on blkid: {}", free_bid.to_string());
    });

    BlkId c{40, 5, 0};
    LOGINFO("Step 4: read 2 blkid: {}.", c.to_string());
    get_inst()->insert(c);

    LOGINFO("Step 5: read 2 completes");
    get_inst()->remove(c);

    LOGINFO("Step 5a: assert callback should NOT be triggered.");
    assert(!called);

    LOGINFO("Step 6: read 1 completes");
    get_inst()->remove(b);

    LOGINFO("Step 6a: assert callback should be triggered.");
    assert(called);
}

/*
 * Alignment: 8
 * Waiter overlap with two read base ids, waiter cb to be called after both read completes
 *
 * 1. Read-1: {35, 12, 1}, covers two base id: {32, 8, 1}, {40, 8, 1}
 * 2. Read-2: {50, 16, 1}, covers three base ids: {48, 8, 1}, {56, 8, 1}, {64, 8, 1}
 * 3. free: {44, 6, 1}, covers two base id: {40, 8, 1}, {48, 8, 1}
 * 4, Read-1 completes; // free cb should NOT be triggered;
 * 5. Read-2 completes; // free cb should be triggered;
 * */
TEST_F(BlkReadTrackerTest, TestInsRmWithWaiterOverlapMultiReads1) {
    auto align = 8ul;
    LOGINFO("Step 1: set entries per record to {}.", align);
    get_inst()->set_entries_per_record(align);

    // Read-1 covers two base id: {32, 8, 1}, {40, 8, 1}
    BlkId b{35, 12, 1};
    LOGINFO("Step 2: read 1 blkid: {}. ", b.to_string());
    get_inst()->insert(b);

    // Read-2 covers three base ids: {48, 8, 1}, {56, 8, 1}, {64, 8, 0}
    BlkId c{48, 16, 1};
    LOGINFO("Step 3: read 2 blkid: {}. ", c.to_string());
    get_inst()->insert(c);

    // free blk wait on two base ids: {40, 8, 1}, {48, 8, 1}
    BlkId free_bid{44, 6, 1};
    bool called{false};
    LOGINFO("Step 4: free blkid: {}.", free_bid);
    get_inst()->wait_on(free_bid, [&free_bid, &called]() {
        LOGMSG_ASSERT_EQ(called, false, "not expecting wait_on callback to be called more than once!");
        called = true;
        LOGINFO("wait_on callback triggered on blkid: {}", free_bid.to_string());
    });

    LOGINFO("Step 5a: read complete on blkid: {}", b.to_string());
    get_inst()->remove(b);

    LOGINFO("Step 5b: assert callback not triggered yet.");
    assert(!called);

    LOGINFO("Step 6a: read complete on blkid: {}", c.to_string());
    get_inst()->remove(c);

    LOGINFO("Step 6b: assert that callback is triggered by read completes");
    assert(called);
}

/*
 * Alignment: 16
 * 1. read-1: {16, 40, 0} // read on base ids: {16, 16, 0}, {32, 16, 0}, {48, 16, 0}
 * 2. free: {10, 8, 0, cb1} // across two base ids, {0, 16, 0}, {16, 16, 0}
 * 3. read-2: {5, 4, 0} // read on base id {0, 16, 0}, which overlap free's base id, but actual block is not
 * overlapping;
 * 4. read-1 completes // callback of free should be called, even though read-2 is not completed yet;
 * 5. read-2 completes
 * Note: read should never olverap with unfinished free blkid; read-2 is not violating this rule;
 *
 * free cb1 should only wait on read-1 to completes, read-2 should not block free;
 * */
TEST_F(BlkReadTrackerTest, TestInsRmWithWaiterOverlapMultiReads2) {
    auto align = 16ul;
    LOGINFO("Step 1: set entries per record to {}.", align);
    get_inst()->set_entries_per_record(align);

    BlkId b{16, 40, 0};
    LOGINFO("Step 2: read-1 on blkid: {}. ", b.to_string());
    get_inst()->insert(b);

    BlkId free_bid{10, 8, 0};
    LOGINFO("Step 3: free on blkid: {}. ", free_bid.to_string());
    bool called{false};
    get_inst()->wait_on(free_bid, [&free_bid, &called]() {
        LOGMSG_ASSERT_EQ(called, false, "not expecting wait_on callback to be called more than once!");
        called = true;
        LOGINFO("wait on callback triggered on free_bid: {}", free_bid.to_string());
    });

    BlkId c{5, 4, 0};
    LOGINFO("Step 4: read-2 on blkid: {}.", c.to_string());
    get_inst()->insert(c);

    LOGINFO("Step 5a: read-1 completed on blkid: {}.", b.to_string());
    get_inst()->remove(b);

    LOGINFO("Step 5b: assert free blk callback should be triggered");
    assert(called);

    LOGINFO("Step 6: read-2 completed on blkid: {}.", c.to_string());
    get_inst()->remove(c);
}

//////////////////////////// Multi-thread test cases //////////////////////////////

/*
 * Multi-thread Insert and remove, with no free operation;
 *
 * 1. do insert with a few threads -- (can also be done in massive threads, but not necessary)
 * 2. do remove in massive threads (must be same amount of inserts);
 * */
VENUM(op_type_t, uint8_t, insert = 1, remove = 2, wait_on = 3, no_op = 4);
TEST_F(BlkReadTrackerTest, TestThreadedInsertAndRemove) {
    auto align = 8ul;
    LOGINFO("Step 1: set entries per record to {}.", align);
    get_inst()->set_entries_per_record(align);

    std::vector< BlkId > bids{{10, 8, 0}, {20, 5, 0}, {25, 6, 0}, {43, 16, 0}, {56, 4, 0}, {72, 18, 0}, {122, 4, 0}};

    const auto repeat = 100ul;
    std::vector< std::thread > op_threads;

    for (const auto& b : bids) {
        std::thread t([this, &b]() {
            for (auto j = 0ul; j < repeat; ++j) {
                get_inst()->insert(b);
            }
        });
        op_threads.push_back(std::move(t));
    }

    LOGINFO("Step 2: threaded insert issued.");

    for (auto& t : op_threads) {
        t.join();
    }

    // remove has to wait for insert to complete because if insert thread runs slower than remove, it might assert
    // complaining no elements are found in map;

    LOGINFO("Step 3: threaded insert joined.");
    op_threads.clear();

    for (auto i = 0ul; i < bids.size(); ++i) {
        for (auto j = 0ul; j < repeat; ++j) {
            std::thread t([this, &bids, i]() { get_inst()->remove(bids[i]); });
            op_threads.push_back(std::move(t));
        }
    }

    LOGINFO("Step 4: threaded remove issued.");
    for (auto& t : op_threads) {
        t.join();
    }

    LOGINFO("Step 4: all threads joined.");
}

TEST_F(BlkReadTrackerTest, TestThreadedInsertWaitonThenRemove) {
    auto align = 8ul;
    LOGINFO("Step 1: set entries per record to {}.", align);
    get_inst()->set_entries_per_record(align);

    std::vector< BlkId > bids{{12, 6, 0}, {18, 5, 0}, {25, 8, 0}, {36, 16, 0}, {57, 4, 0}, {66, 18, 0}, {92, 14, 0}};
    const auto repeat = 100ul;
    std::vector< std::thread > op_threads;
    for (auto i = 0ul; i < bids.size(); ++i) {
        std::thread t([this, &bids, i]() {
            for (auto j = 0ul; j < repeat; ++j) {
                get_inst()->insert(bids[i]);
            }
        });
        op_threads.push_back(std::move(t));
    }

    LOGINFO("Step 2: threaded insert issued.");

    std::vector< bool > called(bids.size(), false);
    std::mutex mtx;
    for (auto i = 0ul; i < bids.size(); ++i) {
        std::thread t([this, &bids, i, &mtx, &called]() {
            get_inst()->wait_on(bids[i], [i, &bids, &mtx, &called]() {
                std::unique_lock lk(mtx);
                LOGMSG_ASSERT(called[i] == false, "not expecting callback to be called more than once!");
                called[i] = true;
                LOGINFO("wait_on called on blkid: {};", bids[i].to_string());
            });
        });
        op_threads.push_back(std::move(t));
    }

    // wait for all insert to complete, otherwise it will race with remove thread;
    for (auto& t : op_threads) {
        t.join();
    }

    op_threads.clear();

    LOGINFO("Step 3: threaded wait_on issued on all bids.");

    for (auto i = 0ul; i < bids.size(); ++i) {
        for (auto j = 0ul; j < repeat; ++j) {
            std::thread t([this, &bids, i]() { get_inst()->remove(bids[i]); });
            op_threads.push_back(std::move(t));
        }
    }

    LOGINFO("Step 3: threaded remove issued.");
    for (auto& t : op_threads) {
        t.join();
    }

    LOGINFO("Step 4: all threads joined.");

    for (auto i = 0ul; i < called.size(); ++i) {
        LOGMSG_ASSERT(called[i] == true, "expecting all waiters to be called");
    }

    LOGINFO("Step 5: all bids wait_on cb called.");
}

SISL_OPTION_GROUP(test_blk_read_tracker,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_blk_read_tracker);
    sisl::logging::SetLogger("test_blk_read_tracker");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    const auto ret{RUN_ALL_TESTS()};
    return ret;
}
