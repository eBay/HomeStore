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
#include <vector>
#include <iostream>
#include <filesystem>

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/fds/buffer.hpp>
#include <gtest/gtest.h>
#include <iomgr/iomgr_flip.hpp>

#include <homestore/blk.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "blkalloc/blk_allocator.h"
#include "test_common/bits_generator.hpp"
#include "test_common/homestore_test_common.hpp"

#include <homestore/blkdata_service.hpp>

////////////////////////////////////////////////////////////////////////////
//                                                                        //
//     This test is to test data serice with varsize block allocator      //
//                                                                        //
////////////////////////////////////////////////////////////////////////////

using namespace homestore;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_data_service, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_data_service)

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

ENUM(DataSvcOp, uint8_t, WRITE, READ, FREE_BLK, COMMIT_BLK, RESERVE_STREAM, ALLOC_STREAM, FREE_STREAM)

typedef std::function< void(std::error_condition err, std::shared_ptr< std::vector< BlkId > > out_bids) >
    after_write_cb_t;

class BlkDataServiceTest : public testing::Test {
public:
    BlkDataService& inst() { return homestore::data_service(); }

    void print_bids(const std::vector< BlkId >& out_bids) {
        for (auto i = 0ul; i < out_bids.size(); ++i) {
            LOGINFO("bid[{}]: {}", i, out_bids[i].to_string());
        }
    }

    void free(sisl::sg_list& sg) { test_common::HSTestHelper::free(sg); }

    // free_blk after read completes
    void write_read_free_blk(uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();
        auto test_blkid_ptr = std::make_shared< MultiBlkId >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */)
            .thenValue([this, sg_write_ptr, test_blkid_ptr](MultiBlkId const& out_bids) {
                LOGINFO("after_write_cb: Write completed;");
                // sg_write buffer is no longer needed;
                free(*sg_write_ptr);

                LOGINFO("Write blk ids: ");
                print_bids(out_bids);

                HS_DBG_ASSERT_GE(out_bids.num_pieces(), 1);
                *test_blkid_ptr = out_bids[0];
            })
            .thenValue([this, sg_read_ptr, test_blkid_ptr](auto) {
                struct iovec iov;
                iov.iov_len = test_blkid_ptr->blk_count() * inst().get_blk_size();
                iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                sg_read_ptr->iovs.push_back(iov);
                sg_read_ptr->size += iov.iov_len;

                LOGINFO("Step 2: async read on blkid: {}", test_blkid_ptr->to_string());
                add_read_delay();
                return inst().async_read(*test_blkid_ptr, *sg_read_ptr, sg_read_ptr->size);
            })
            .thenValue([this, sg_read_ptr, test_blkid_ptr](auto) {
                LOGINFO("read completed;");
                free(*sg_read_ptr);
                return inst().async_free_blk(*test_blkid_ptr);
            })
            .thenValue([this, test_blkid_ptr](auto) {
                LOGINFO("completed async_free_blk: {}", test_blkid_ptr->to_string());
                this->finish_and_notify();
            });
    }

    // free_blk before read completes
    void write_free_blk_before_read_comp(const uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();
        auto test_blkid_ptr = std::make_shared< BlkId >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */)
            .thenValue([this, sg_write_ptr, test_blkid_ptr](const std::vector< BlkId >& out_bids) {
                // write completed, now we trigger read on a blkid and in read completion routine, we do
                // a free blk;

                LOGINFO("after_write_cb: Write completed;");
                free(*sg_write_ptr); // sg_write buffer is no longer needed;

                LOGINFO("Write blk ids: ");
                print_bids(out_bids);

                HS_DBG_ASSERT_GE(out_bids.size(), 1);
                *test_blkid_ptr = out_bids[0];
            })
            .thenValue([this, sg_read_ptr, test_blkid_ptr](auto) mutable {
                struct iovec iov;
                iov.iov_len = test_blkid_ptr->blk_count() * inst().get_page_size();
                iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                sg_read_ptr->iovs.push_back(iov);
                sg_read_ptr->size += iov.iov_len;

                LOGINFO("Step 2a: inject read delay on blkid: {}", test_blkid_ptr->to_string());
                LOGINFO("Step 2b: async read on blkid: {}", test_blkid_ptr->to_string());
                inst()
                    .async_read(*test_blkid_ptr, *sg_read_ptr, sg_read_ptr->size)
                    .thenValue([sg_read_ptr, this](auto) {
                        // if we are here, free_blk callback must have been called already, because data service layer
                        // trigger the free_blk cb firstly then send read complete cb back to caller;
                        m_read_blk_done = true;
                        LOGINFO("read completed;");
                        HS_DBG_ASSERT_EQ(m_free_blk_done.load(), true,
                                         "free blk callback should not be called before read blk completes");

                        free(*sg_read_ptr);
                        this->finish_and_notify();
                    });

                LOGINFO("Step 3: started async_free_blk: {}", test_blkid_ptr->to_string());
                inst().async_free_blk(*test_blkid_ptr).thenValue([this](auto) {
                    LOGINFO("completed async_free_blk");
                    HS_DBG_ASSERT_EQ(m_free_blk_done.load(), false, "Duplicate free blk completion");
                    m_free_blk_done = true;
                });
            });
    }

    void write_io_free_blk(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write_ptr = std::make_shared< sisl::sg_list >();

        auto futs = write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */)
                        .thenValue([sg_write_ptr, this](const std::vector< BlkId >& out_bids) {
                            LOGINFO("after_write_cb: Write completed;");
                            free(*sg_write_ptr);

                            std::vector< folly::Future< bool > > futs;
                            for (const auto& free_bid : out_bids) {
                                LOGINFO("Step 2: started async_free_blk: {}", free_bid.to_string());
                                auto f = inst().async_free_blk(free_bid);
                                futs.emplace_back(std::move(f));
                            }
                            return futs;
                        });

        folly::collectAllUnsafe(futs).then([this](auto) {
            LOGINFO("completed async_free_blks");
            this->finish_and_notify();
        });
    }

    void write_io_verify(const uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */)
            .thenValue([sg_write_ptr, sg_read_ptr, this](const std::vector< BlkId >& out_bids) mutable {
                // this will be called in write io completion cb;
                LOGINFO("after_write_cb: Write completed;");

                // TODO: verify multiple read blks;
                HS_DBG_ASSERT_EQ(out_bids.size(), 1);

                const auto num_iovs = out_bids.size();

                for (auto i = 0ul; i < num_iovs; ++i) {
                    struct iovec iov;
                    iov.iov_len = out_bids[i].blk_count() * inst().get_page_size();
                    iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                    sg_read_ptr->iovs.push_back(iov);
                    sg_read_ptr->size += iov.iov_len;
                }

                LOGINFO("Step 2: async read on blkid: {}", out_bids[0].to_string());
                return inst().async_read(out_bids[0], *sg_read_ptr, sg_read_ptr->size);
            })
            .thenValue([this, sg_write_ptr, sg_read_ptr](auto) mutable {
                const auto equal = test_common::HSTestHelper::compare(*sg_read_ptr, *sg_write_ptr);
                assert(equal);

                LOGINFO("Read completed;");
                free(*sg_write_ptr);
                free(*sg_read_ptr);

                this->finish_and_notify();
            });
    }

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

    void finish_and_notify() {
        {
            std::lock_guard lk(this->m_mtx);
            this->m_io_job_done = true;
        }
        // notify any one who is waiting for this write to complete;
        this->m_cv.notify_one();
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
    // caller should be responsible to call free(sg) to free the iobuf allocated in iovs,
    // normally it should be freed in after_write_cb;
    //
    folly::Future< MultiBlkId > write_sgs(uint64_t io_size, cshared< sisl::sg_list >& sg, uint32_t num_iovs) {
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

        MultiBlkId out_bid;
        return inst()
            .async_alloc_write(*(sg.get()), blk_alloc_hints{}, out_bid, false /* part_of_batch*/)
            .thenValue([sg, this, out_bid](auto const err) {
                assert(!err);
                LOGINFO("bid: {}", bid.to_string());
                return folly::makeFuture< MultiBlkd >(std::move(out_bid));
            });
    }

    void add_read_delay() {
#ifdef _PRERELEASE
        flip::FlipClient* fc = iomgr_flip::client_instance();

        flip::FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);

        // Delay read op by 500ms
        fc->inject_delay_flip("simulate_drive_delay",
                              {fc->create_condition("devname", flip::Operator::DONT_CARE, std::string("")),
                               fc->create_condition("op_type", flip::Operator::EQUAL, std::string("READ")),
                               fc->create_condition("reactor_id", flip::Operator::DONT_CARE, 0)},
                              freq, 500000);
#endif
    }

private:
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool m_io_job_done{false};
    std::unique_ptr< BlkDataService > m_data_service;
    std::atomic< bool > m_free_blk_done{false};
    std::atomic< bool > m_read_blk_done{false};
};

//
// single vector in sg_list;
//
TEST_F(BlkDataServiceTest, TestBasicWrite) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    const auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

TEST_F(BlkDataServiceTest, TestWriteMultiplePagesSingleIov) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    const auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

TEST_F(BlkDataServiceTest, TestWriteMultiplePagesMultiIovs) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    const auto io_size = 4 * Mi;
    const auto num_iovs = 4;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, and {} iovs", io_size, num_iovs);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size, num_iovs]() { this->write_io(io_size, num_iovs); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

TEST_F(BlkDataServiceTest, TestWriteThenReadVerify) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io_verify(io_size); });

    LOGINFO("Step 3: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 4: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

// Free_blk test, no read involved;
TEST_F(BlkDataServiceTest, TestWriteThenFreeBlk) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, then free blk.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_io_free_blk(io_size); });

    LOGINFO("Step 3: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 4: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

//
// write, read, then free the blk after read completes, free should succeed
//
TEST_F(BlkDataServiceTest, TestWriteReadThenFreeBlkAfterReadComp) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: Run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_read_free_blk(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

TEST_F(BlkDataServiceTest, TestWriteReadThenFreeBeforeReadComp) {
    LOGINFO("Step 0: Starting homestore.");
    test_common::HSTestHelper::start_homestore("test_data_service", 5.0, 0, 0, 80.0, 0, nullptr);

    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: Run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_free_blk_before_read_comp(io_size); });

    LOGINFO("Step 4: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 5: I/O completed, do shutdown.");
    test_common::HSTestHelper::shutdown_homestore();
}

// Stream related test

SISL_OPTION_GROUP(test_data_service,
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("30"), "number"),
                  (num_io, "", "num_io", "number of io", ::cxxopts::value< uint64_t >()->default_value("300"),
                   "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_data_service, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_data_service");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    gp.run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    gp.num_io = SISL_OPTIONS["num_io"].as< uint64_t >();

    return RUN_ALL_TESTS();
}
