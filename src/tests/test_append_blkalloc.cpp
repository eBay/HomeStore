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

using namespace homestore;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_append_blkalloc, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_append_blkalloc)

std::vector< std::string > test_common::HSTestHelper::s_dev_names;
blk_allocator_type_t test_common::HSTestHelper::s_ds_alloc_type;
chunk_selector_type_t test_common::HSTestHelper::s_ds_chunk_sel_type;

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
    void free_sg_buf(sisl::sg_list& sg) {
        for (auto x : sg.iovs) {
            iomanager.iobuf_free(s_cast< uint8_t* >(x.iov_base));
            x.iov_base = nullptr;
            x.iov_len = 0;
        }

        sg.size = 0;
    }

    void finish_and_notify() {
        {
            std::lock_guard lk(this->m_mtx);
            this->m_io_job_done = true;
        }
        // notify any one who is waiting for this write to complete;
        this->m_cv.notify_one();
    }

    //
    // this api is for caller who is not interested with the write buffer and blkids;
    //
    void write_io(uint64_t io_size, uint32_t num_iovs = 1) {
        auto sg = std::make_shared< sisl::sg_list >();
        write_sgs(io_size, sg, num_iovs).thenValue([this, sg](auto) {
            free_sg_buf(*sg);
            finish_and_notify();
        });
    }

    void wait_for_all_io_complete() {
        std::unique_lock lk(m_mtx);
        m_cv.wait(lk, [this] { return this->m_io_job_done; });
    }

private:
    //
    // call this api when caller needs the write buffer and blkids;
    // caller is responsible to free the sg buffer;
    //
    // caller should be responsible to call free_sg_buf(sg) to free the iobuf allocated in iovs, normally it should be
    // freed in after_write_cb;
    //
    folly::Future< std::vector< BlkId > > write_sgs(uint64_t io_size, cshared< sisl::sg_list >& sg, uint32_t num_iovs) {
        // TODO: What if iov_len is not multiple of 4Ki?
        HS_DBG_ASSERT_EQ(io_size % (4 * Ki * num_iovs), 0, "Expecting iov_len : {} to be multiple of {}.",
                         io_size / num_iovs, 4 * Ki);
        const auto iov_len = io_size / num_iovs;
        for (auto i = 0ul; i < num_iovs; ++i) {
            struct iovec iov;
            iov.iov_len = iov_len;
            iov.iov_base = iomanager.iobuf_alloc(512, iov_len);
            // fill_data_buf(r_cast< uint8_t* >(iov.iov_base), iov.iov_len);
            sg->iovs.push_back(iov);
            sg->size += iov_len;
        }

        auto out_bids_ptr = std::make_shared< std::vector< BlkId > >();
        return inst()
            .async_alloc_write(*(sg.get()), blk_alloc_hints{}, *out_bids_ptr, false /* part_of_batch*/)
            .thenValue([sg, this, out_bids_ptr](bool success) {
                assert(success);
                for (const auto& bid : *out_bids_ptr) {
                    LOGINFO("bid: {}", bid.to_string());
                }
                return folly::makeFuture< std::vector< BlkId > >(std::move(*out_bids_ptr));
            });
    }

private:
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool m_io_job_done{false};
};

TEST_F(AppendBlkAllocatorTest, TestBasicWrite) {
    LOGINFO("Step 0: Starting homestore.");

    test_common::HSTestHelper::set_data_svc_allocator(homestore::blk_allocator_type_t::append);
    test_common::HSTestHelper::set_data_svc_chunk_selector(
        homestore::chunk_selector_type_t::round_robin); // <<< TODO: change to heap

    test_common::HSTestHelper::start_homestore("test_append_blkalloc", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    const auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

SISL_OPTION_GROUP(test_append_blkalloc,
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("30"), "number"),
                  (num_io, "", "num_io", "number of io", ::cxxopts::value< uint64_t >()->default_value("300"),
                   "number"));

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
