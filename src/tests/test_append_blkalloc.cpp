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
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <iomgr/iomgr_flip.hpp>
#include <iomgr/io_environment.hpp>
#include "blkalloc/append_blk_allocator.h"
#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
#include "test_common/homestore_test_common.hpp"
#include <homestore/blkdata_service.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//     This test is to test data serice with append block allocator with heap chunk selector      //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

RCU_REGISTER_INIT
 
SISL_OPTIONS_ENABLE(logging, test_append_blkalloc, iomgr, test_common_setup)

constexpr uint64_t Ki{1024};
constexpr uint64_t Mi{Ki * Ki};
constexpr uint64_t Gi{Ki * Mi};

struct Param {
    uint64_t num_io;
    uint64_t run_time;
};

static Param gp;

class AppendBlkAllocatorTest : public testing::Test {
public:
    BlkDataService& inst() { return homestore::data_service(); }

    virtual void SetUp() override {
        m_helper.start_homestore(
            "test_append_blkalloc",
            {{HS_SERVICE::META, {.size_pct = 5.0}},
             {HS_SERVICE::DATA,
              {.size_pct = 80.0, .blkalloc_type = homestore::blk_allocator_type_t::append, .num_chunks = 65000}}});
    }

    virtual void TearDown() override { m_helper.shutdown_homestore(); }

    void reset_io_job_done() { m_io_job_done = false; }

    void finish_and_notify() {
        {
            std::lock_guard lk(this->m_mtx);
            this->m_io_job_done = true;
        }
        // notify any one who is waiting for this write to complete;
        this->m_cv.notify_one();
    }

    void free(sisl::sg_list& sg) { test_common::HSTestHelper::free(sg); }

    //
    // this api is for caller who is not interested with the write buffer and blkids;
    //
    void write_io(uint64_t io_size, uint32_t num_iovs = 1) {
        auto sg = std::make_shared< sisl::sg_list >();
        write_sgs(io_size, sg, num_iovs).thenValue([this, sg](auto) {
            free(*sg);
            finish_and_notify();
        });
    }

    void wait_for_all_io_complete() {
        std::unique_lock lk(m_mtx);
        m_cv.wait(lk, [this] { return this->m_io_job_done; });
    }

    void write_io_verify(const uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */)
            .thenValue([sg_write_ptr, sg_read_ptr, this](auto&& written_bid_ptr) mutable {
                // this will be called in write io completion cb;
                LOGINFO("after_write_cb: Write completed;");

                iovec iov;
                iov.iov_len = written_bid_ptr->blk_count() * inst().get_blk_size();
                iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                sg_read_ptr->iovs.push_back(iov);
                sg_read_ptr->size = iov.iov_len;

                LOGINFO("Step 2: async read on blkid: {}", written_bid_ptr->to_string());
                return inst().async_read(*written_bid_ptr, *sg_read_ptr, sg_read_ptr->size);
            })
            .thenValue([this, sg_write_ptr, sg_read_ptr](auto err) mutable {
                RELEASE_ASSERT(!err, "read failured");
                const auto equal = test_common::HSTestHelper::compare(*sg_read_ptr, *sg_write_ptr);
                RELEASE_ASSERT(equal, "read/write mismatch");

                LOGINFO("Read completed;");
                free(*sg_write_ptr);
                free(*sg_read_ptr);

                this->finish_and_notify();
            });
    }

    void write_io_free_blk(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write_ptr = std::make_shared< sisl::sg_list >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */)
            .thenValue([sg_write_ptr, this](auto&& written_bid_ptr) {
                LOGINFO("after_write_cb: Write completed;");
                free(*sg_write_ptr);

                LOGINFO("Step 2: started async_free_blk: {}", written_bid_ptr->to_string());
                return inst().async_free_blk(*written_bid_ptr);
            })
            .thenValue([this](auto&& err) {
                RELEASE_ASSERT(!err, "Failed to free blks");
                LOGINFO("completed async_free_blks");
                this->finish_and_notify();
            });
    }

private:
    //
    // call this api when caller needs the write buffer and blkids;
    // caller is responsible to free the sg buffer;
    //
    // caller should be responsible to call free(sg) to free the iobuf allocated in iovs,
    // normally it should be freed in after_write_cb;
    //
    folly::Future< shared< BlkId > > write_sgs(uint64_t io_size, cshared< sisl::sg_list >& sg, uint32_t num_iovs) {
        // TODO: What if iov_len is not multiple of 4Ki?
        HS_DBG_ASSERT_EQ(io_size % (4 * Ki * num_iovs), 0, "Expecting iov_len : {} to be multiple of {}.",
                         io_size / num_iovs, 4 * Ki);
        const auto iov_len = io_size / num_iovs;
        for (auto i = 0ul; i < num_iovs; ++i) {
            struct iovec iov;
            iov.iov_len = iov_len;
            iov.iov_base = iomanager.iobuf_alloc(512, iov_len);
            test_common::HSTestHelper::fill_data_buf(r_cast< uint8_t* >(iov.iov_base), iov.iov_len);
            sg->iovs.push_back(iov);
            sg->size += iov_len;
        }

        MultiBlkId blkid;
        return inst()
            .async_alloc_write(*(sg.get()), blk_alloc_hints{}, blkid, false /* part_of_batch*/)
            .thenValue([sg, this, blkid](auto err) {
                RELEASE_ASSERT(!err, "Write failure");
                return folly::makeFuture< shared< MultiBlkId > >(std::make_shared< MultiBlkId >(blkid));
            });
    }

protected:
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool m_io_job_done{false};
    test_common::HSTestHelper m_helper;
};

TEST_F(AppendBlkAllocatorTest, TestBasicWrite) {
    // start io in worker thread;
    const auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(AppendBlkAllocatorTest, TestWriteThenReadVerify) {
    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io_verify(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(AppendBlkAllocatorTest, TestWriteThenFreeBlk) {
    // start io in worker thread;
    auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, then free blk.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_io_free_blk(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(AppendBlkAllocatorTest, TestCPFlush) {
    const auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, trigger_cp and wait.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Step 4: cp completed, do shutdown.");
}

TEST_F(AppendBlkAllocatorTest, TestWriteThenRecovey) {
    // start io in worker thread;
    auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, then free blk.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_io_free_blk(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, trigger_cp and wait.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Step 4: cp completed, restart homestore.");
    m_helper.restart_homestore();

    std::this_thread::sleep_for(std::chrono::seconds{3});
    LOGINFO("Step 5: Restarted homestore with data service recovered");

    this->reset_io_job_done();

    LOGINFO("Step 6: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 7: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 8: I/O completed, trigger_cp and wait.");
    test_common::HSTestHelper::trigger_cp(true /* wait */);

    LOGINFO("Step 9: do shutdown. ");
}

SISL_OPTION_GROUP(test_append_blkalloc,
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("30"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_append_blkalloc, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_append_blkalloc");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    gp.run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    gp.num_io = SISL_OPTIONS["num_io"].as< uint64_t >();

    return RUN_ALL_TESTS();
}
