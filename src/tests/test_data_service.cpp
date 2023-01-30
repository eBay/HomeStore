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

#include <homestore/blk.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "blkalloc/blk_allocator.h"
#include "test_common/bits_generator.hpp"
#include "test_common/homestore_test_common.hpp"

#include <homestore/blkdata_service.hpp>

using namespace homestore;

RCU_REGISTER_INIT
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_data_service)
SISL_LOGGING_DECL(test_data_service)

constexpr uint64_t Ki{1024};
constexpr uint64_t Mi{Ki * Ki};
constexpr uint64_t Gi{Ki * Mi};

struct Param {
    uint64_t num_io;
    uint64_t run_time;
    uint32_t num_threads;
    bool is_spdk{false};
    std::vector< std::string > dev_names;
};

static Param gp;

static const std::string DATA_SVC_FILE_PREFIX{"/tmp/test_data_service_"};

ENUM(DataSvcOp, uint8_t, WRITE, READ, FREE_BLK, COMMIT_BLK, RESERVE_STREAM, ALLOC_STREAM, FREE_STREAM)

static void start_homestore(const uint32_t ndevices, const uint64_t dev_size, const uint32_t nthreads) {
    std::vector< dev_info > device_info;
    if (gp.dev_names.size()) {
        /* if user customized file/disk names */
        for (uint32_t i{0}; i < gp.dev_names.size(); ++i) {
            const std::filesystem::path fpath{gp.dev_names[i]};
            device_info.emplace_back(gp.dev_names[i], HSDevType::Data);
        }
    } else {
        /* create files */
        LOGINFO("creating {} device files with each of size {} ", ndevices, in_bytes(dev_size));
        for (uint32_t i{0}; i < ndevices; ++i) {
            const std::filesystem::path fpath{DATA_SVC_FILE_PREFIX + std::to_string(i + 1)};
            std::ofstream ofs{fpath.string(), std::ios::binary | std::ios::out};
            std::filesystem::resize_file(fpath, dev_size); // set the file size
            device_info.emplace_back(std::filesystem::canonical(fpath).string(), HSDevType::Data);
        }
    }
    LOGINFO("Starting iomgr with {} threads", nthreads);
    ioenvironment.with_iomgr(nthreads, gp.is_spdk);

    const uint64_t app_mem_size = ((ndevices * dev_size) * 15) / 100;
    LOGINFO("Initialize and start HomeBlks with app_mem_size = {}", in_bytes(app_mem_size));

    hs_input_params params;
    params.app_mem_size = app_mem_size;
    params.data_devices = device_info;

    test_common::set_random_http_port();
    HomeStore::instance()->with_params(params).with_data_service(80.0).with_meta_service(5.0).init(
        true /* wait_for_init */);
}

bool free_blk_cb_called{false};
// global free_blk callback
static void free_cb(std::error_condition err) {
    LOGINFO("completed async_free_blk");
    assert(!err);
    assert(!free_blk_cb_called);
    free_blk_cb_called = true;
}

typedef std::function< void(std::error_condition err, std::shared_ptr< std::vector< BlkId > > out_bids) >
    after_write_cb_t;

class BlkDataServiceTest : public testing::Test {
public:
    BlkDataService& inst() { return hs()->data_service(); }

    void remove_files() {
        /* no need to delete the user created file/disk */
        if (gp.dev_names.size() == 0) {
            auto const ndevices = SISL_OPTIONS["num_devs"].as< uint32_t >();
            for (uint32_t i{0}; i < ndevices; ++i) {
                const std::filesystem::path fpath{DATA_SVC_FILE_PREFIX + std::to_string(i + 1)};
                if (std::filesystem::exists(fpath) && std::filesystem::is_regular_file(fpath)) {
                    std::filesystem::remove(fpath);
                }
            }
        }
    }

    void shutdown() {
        LOGINFO("shutting down homeblks");
        remove_files();
        HomeStore::instance()->shutdown();
        LOGINFO("stopping iomgr");
        iomanager.stop();
    }

    void free_sg_buf(std::shared_ptr< sisl::sg_list > sg) {
        for (auto x : sg->iovs) {
            iomanager.iobuf_free(s_cast< uint8_t* >(x.iov_base));
            x.iov_base = nullptr;
            x.iov_len = 0;
        }

        sg->size = 0;
        // delete sg;
    }

    void print_bids(const std::vector< BlkId >& out_bids) {
        for (auto i = 0ul; i < out_bids.size(); ++i) {
            LOGINFO("bid[{}]: {}", i, out_bids[i].to_string());
        }
    }

    // free_blk after read completes
    void write_read_free_blk(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write = std::make_shared< sisl::sg_list >();
        write_io(io_size, sg_write, 1 /* num_iovs */,
                 [this, sg_write](std::error_condition err, std::shared_ptr< std::vector< BlkId > > sout_bids) {
                     // write completed, now we trigger read on a blkid and in read cmopletion routine, we do a free
                     // blk;

                     LOGINFO("after_write_cb: Write completed;");
                     // sg_write buffer is no longer needed;
                     free_sg_buf(sg_write);

                     LOGINFO("Write blk ids: ");
                     const auto out_bids = *(sout_bids.get());
                     print_bids(out_bids);

                     HS_DBG_ASSERT_GE(out_bids.size(), 1);

                     // pick the 1st blk id to issue read;
                     const auto num_iovs = out_bids.size();
                     std::shared_ptr< sisl::sg_list > sg_read = std::make_shared< sisl::sg_list >();

                     struct iovec iov;
                     iov.iov_len = out_bids[0].get_nblks() * inst().get_page_size();
                     iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                     sg_read->iovs.push_back(iov);
                     sg_read->size += iov.iov_len;

                     LOGINFO("Step 2: async read on blkid: {}", out_bids[0].to_string());
                     auto free_bid = out_bids[0];
                     inst().async_read(out_bids[0], *(sg_read.get()), sg_read->size,
                                       [sg_read, free_bid, this](std::error_condition err) {
                                           // read completes, now we free the same blk id (free_bid);
                                           assert(!err);

                                           LOGINFO("read completed;");
                                           free_sg_buf(sg_read);

                                           LOGINFO("Step 3: started async_free_blk: {}", free_bid.to_string());
                                           inst().async_free_blk(free_bid, [this, free_bid](std::error_condition err) {
                                               LOGINFO("completed async_free_blk: {}", free_bid.to_string());
                                               assert(!err);
                                               {
                                                   std::lock_guard lk(this->m_mtx);
                                                   this->m_io_job_done = true;
                                               }

                                               this->m_cv.notify_one();
                                           });
                                       });
                 });
    }

    // free_blk before read completes
    void write_free_blk_before_read_comp(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write = std::make_shared< sisl::sg_list >();
        write_io(io_size, sg_write, 1 /* num_iovs */,
                 [this, sg_write](std::error_condition err, std::shared_ptr< std::vector< BlkId > > sout_bids) {
                     // write completed, now we trigger read on a blkid and in read cmopletion routine, we do a
                     // free blk;

                     LOGINFO("after_write_cb: Write completed;");
                     // sg_write buffer is no longer needed;
                     free_sg_buf(sg_write);

                     LOGINFO("Write blk ids: ");
                     const auto out_bids = *(sout_bids.get());
                     print_bids(out_bids);

                     HS_DBG_ASSERT_GE(out_bids.size(), 1);

                     // pick the 1st blk id to issue read;
                     const auto num_iovs = out_bids.size();
                     std::shared_ptr< sisl::sg_list > sg_read = std::make_shared< sisl::sg_list >();

                     struct iovec iov;
                     iov.iov_len = out_bids[0].get_nblks() * inst().get_page_size();
                     iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                     sg_read->iovs.push_back(iov);
                     sg_read->size += iov.iov_len;

                     // inject read delay flip
                     LOGINFO("Step 2a: inject read delay on blkid: {}", out_bids[0].to_string());

                     LOGINFO("Step 2b: async read on blkid: {}", out_bids[0].to_string());
                     auto free_bid = out_bids[0];

                     bool read_blk_cb_called{false};
                     inst().async_read(out_bids[0], *(sg_read.get()), sg_read->size,
                                       [sg_read, &read_blk_cb_called, this](std::error_condition err) {
                                           // if we are here, free_blk callback must have been called already,
                                           // because data service layer trigger the free_blk cb firstly then
                                           // send read complete cb back to caller;
                                           assert(!err);
                                           read_blk_cb_called = true;
                                           LOGINFO("read completed;");
                                           free_sg_buf(sg_read);

                                           {
                                               std::lock_guard lk(this->m_mtx);
                                               this->m_io_job_done = true;
                                           }

                                           this->m_cv.notify_one();
                                       });

                     LOGINFO("Step 3: started async_free_blk: {}", free_bid.to_string());
                     inst().async_free_blk(free_bid, free_cb); // XXX: free_cb can't be another lambda which will cause
                                                               // SEGV as outside io thread could be returned;

                     // free_blk callback should not be triggered before read completes;
                     if (!read_blk_cb_called) {
                         LOGINFO("read has not completed on blkid: {} yet.", out_bids[0].to_string());
                         HS_DBG_ASSERT_EQ(free_blk_cb_called, false,
                                          "free blk callback should not be called before read blk completes");
                     } else {
                         LOGINFO("read has completed on blkid: {}", out_bids[0].to_string());
                         HS_DBG_ASSERT_EQ(free_blk_cb_called, true,
                                          "free blk callback should not be called before read blk completes");
                     }
                 });
    }

    void write_io_free_blk(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write = std::make_shared< sisl::sg_list >();
        write_io(io_size, sg_write, 1 /* num_iovs */,
                 [sg_write, this](std::error_condition err, std::shared_ptr< std::vector< BlkId > > sout_bids) {
                     LOGINFO("after_write_cb: Write completed;");
                     free_sg_buf(sg_write);

                     const auto out_bids = *(sout_bids.get());
                     const auto num_blks = out_bids.size();
                     std::atomic< uint32_t > free_blk_cnt_comp{0};

                     for (uint32_t i = 0; i < num_blks; ++i) {
                         const auto free_bid = out_bids[i];
                         LOGINFO("Step 2: started async_free_blk: {}", free_bid.to_string());
                         inst().async_free_blk(
                             free_bid, [this, &free_bid, &num_blks, &free_blk_cnt_comp](std::error_condition err) {
                                 assert(!err);
                                 free_blk_cnt_comp++;
                                 LOGINFO("completed async_free_blk: {}", free_bid.to_string());
                                 if (free_blk_cnt_comp == num_blks) {
                                     std::lock_guard lk(this->m_mtx);
                                     this->m_io_job_done = true;
                                 }

                                 if (this->m_io_job_done) { this->m_cv.notify_one(); }
                             });
                     }
                 });
    }

    void write_io_verify(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write = std::make_shared< sisl::sg_list >();
        write_io(io_size, sg_write, 1 /* num_iovs */,
                 [sg_write, this](std::error_condition err, std::shared_ptr< std::vector< BlkId > > sout_bids) {
                     // this will be called in write io completion cb;
                     LOGINFO("after_write_cb: Write completed;");

                     const auto out_bids = *(sout_bids.get());

                     // TODO: verify multiple read blks;
                     HS_DBG_ASSERT_EQ(out_bids.size(), 1);

                     const auto num_iovs = out_bids.size();
                     std::shared_ptr< sisl::sg_list > sg_read = std::make_shared< sisl::sg_list >();

                     for (auto i = 0ul; i < num_iovs; ++i) {
                         struct iovec iov;
                         iov.iov_len = out_bids[i].get_nblks() * inst().get_page_size();
                         iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                         sg_read->iovs.push_back(iov);
                         sg_read->size += iov.iov_len;
                     }

                     LOGINFO("Step 2: async read on blkid: {}", out_bids[0].to_string());
                     inst().async_read(out_bids[0], *(sg_read.get()), sg_read->size,
                                       [sg_read, sg_write, this](std::error_condition err) {
                                           assert(!err);

                                           assert(verify_read(sg_read, sg_write));

                                           LOGINFO("Read completed;");
                                           free_sg_buf(sg_write);
                                           free_sg_buf(sg_read);

                                           {
                                               std::lock_guard lk(this->m_mtx);
                                               this->m_io_job_done = true;
                                           }

                                           this->m_cv.notify_one();
                                       });
                 });
    }

    bool verify_read(std::shared_ptr< sisl::sg_list > read_sg, std::shared_ptr< sisl::sg_list > write_sg) {
        if ((write_sg->size != read_sg->size)) {
            LOGINFO("sg_list of read size: {} mismatch with write size: {}, ", read_sg->size, write_sg->size);
            return false;
        }

        if (write_sg->iovs.size() != read_sg->iovs.size()) {
            LOGINFO("sg_list num of iovs mismatch: read: {}, write: {}", read_sg->iovs.size(), write_sg->iovs.size());
            return false;
        }

        const auto num_iovs = write_sg->iovs.size();
        for (auto i = 0ul; i < num_iovs; ++i) {
            if (write_sg->iovs[i].iov_len != read_sg->iovs[i].iov_len) {
                LOGINFO("iov_len of iov[{}] mismatch, read: {}, write: {}", i, read_sg->iovs[i].iov_len,
                        write_sg->iovs[i].iov_len);
                return false;
            }
            auto ret = std::memcmp(write_sg->iovs[i].iov_base, read_sg->iovs[i].iov_base, read_sg->iovs[i].iov_len);
            if (ret != 0) {
                LOGINFO("memcmp return false for iovs[{}] between read and write.", i);
                return false;
            }
        }

        LOGINFO("verify_read passed! data size: {}, num_iovs: {}", read_sg->size, read_sg->iovs.size());
        return true;
    }

    void fill_data_buf(uint8_t* buf, uint64_t size) {
        for (uint64_t i = 0ul; i < size; ++i) {
            *(buf + i) = (i % 256);
        }
    }

    //
    // this api is for caller who is not interested with the write buffer and blkids;
    //
    void write_io(const uint64_t io_size, const uint32_t num_iovs = 1) {
        std::shared_ptr< sisl::sg_list > sg = std::make_shared< sisl::sg_list >();
        write_io(io_size, sg, num_iovs,
                 [this, sg](std::error_condition err, std::shared_ptr< std::vector< BlkId > > sout_bids) {
                     free_sg_buf(sg);
                     {
                         std::lock_guard lk(this->m_mtx);
                         this->m_io_job_done = true;
                     }
                     // notify any one who is waiting for this write to complete;
                     this->m_cv.notify_one();
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
    void write_io(const uint64_t io_size, std::shared_ptr< sisl::sg_list > sg, const uint32_t num_iovs,
                  const after_write_cb_t& after_write_cb = nullptr) {
        // TODO: What if iov_len is not multiple of 4Ki?
        HS_DBG_ASSERT_EQ(io_size % (4 * Ki * num_iovs), 0, "Expecting iov_len : {} to be multiple of {}.",
                         io_size / num_iovs, 4 * Ki);
        const auto iov_len = io_size / num_iovs;
        for (auto i = 0ul; i < num_iovs; ++i) {
            struct iovec iov;
            iov.iov_len = iov_len;
            iov.iov_base = iomanager.iobuf_alloc(512, iov_len);
            fill_data_buf(r_cast< uint8_t* >(iov.iov_base), iov.iov_len);
            sg->iovs.push_back(iov);
            sg->size += iov_len;
        }

        blk_alloc_hints hints; // default hints

        std::shared_ptr< std::vector< BlkId > > out_bids_ptr = std::make_shared< std::vector< BlkId > >();
        out_bids_ptr->clear();

        inst().async_write(*(sg.get()), hints, *(out_bids_ptr.get()),
                           [sg, this, after_write_cb, out_bids_ptr](std::error_condition err) {
                               LOGINFO("async_write completed, err: {}", err.message());
                               assert(!err);
                               const auto out_bids = *(out_bids_ptr.get());

                               for (auto i = 0ul; i < out_bids.size(); ++i) {
                                   LOGINFO("bid-{}: {}", i, out_bids[i].to_string());
                               }

                               if (after_write_cb != nullptr) { after_write_cb(err, out_bids_ptr); }
                           },
                           false /* part_of_batch */);
    }

private:
    std::mutex m_mtx;
    std::condition_variable m_cv;
    bool m_io_job_done{false};
    std::unique_ptr< BlkDataService > m_data_service;
};

//
// single vector in sg_list;
//
TEST_F(BlkDataServiceTest, TestBasicWrite) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    const auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size](iomgr::io_thread_addr_t a) { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    this->shutdown();
}

TEST_F(BlkDataServiceTest, TestWriteMultiplePagesSingleIov) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    const auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size](iomgr::io_thread_addr_t a) { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    this->shutdown();
}

TEST_F(BlkDataServiceTest, TestWriteMultiplePagesMultiIovs) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    const auto io_size = 4 * Mi;
    const auto num_iovs = 4;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, and {} iovs", io_size, num_iovs);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size, &num_iovs](iomgr::io_thread_addr_t a) { this->write_io(io_size, num_iovs); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
    this->shutdown();
}

TEST_F(BlkDataServiceTest, TestWriteThenReadVerify) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size](iomgr::io_thread_addr_t a) { this->write_io_verify(io_size); });

    LOGINFO("Step 3: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 4: I/O completed, do shutdown.");
    this->shutdown();
}

// Free_blk test, no read involved;
TEST_F(BlkDataServiceTest, TestWriteThenFreeBlk) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, then free blk.", io_size);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size](iomgr::io_thread_addr_t a) { this->write_io_free_blk(io_size); });

    LOGINFO("Step 3: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 4: I/O completed, do shutdown.");
    this->shutdown();
}

//
// write, read, then free the blk after read completes, free should succeed
//
TEST_F(BlkDataServiceTest, TestWriteReadThenFreeBlkAfterReadComp) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: Run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size](iomgr::io_thread_addr_t a) { this->write_read_free_blk(io_size); });

    LOGINFO("Step 4: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 5: I/O completed, do shutdown.");
    this->shutdown();
}

// TEST_F(BlkDataServiceTest, TestWriteReadThenFreeBeforeReadComp) {
TEST_F(BlkDataServiceTest, aa) {
    LOGINFO("Step 0: Starting homestore.");
    start_homestore(SISL_OPTIONS["num_devs"].as< uint32_t >(),
                    SISL_OPTIONS["dev_size_gb"].as< uint64_t >() * 1024 * 1024 * 1024, gp.num_threads);

    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: Run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on(iomgr::thread_regex::random_worker,
                     [this, &io_size](iomgr::io_thread_addr_t a) { this->write_free_blk_before_read_comp(io_size); });

    LOGINFO("Step 4: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 5: I/O completed, do shutdown.");
    this->shutdown();
}

// Stream related test

SISL_OPTION_GROUP(test_data_service,
                  (num_threads, "", "num_threads", "number of threads",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (num_devs, "", "num_devs", "number of devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("30"), "number"),
                  (num_io, "", "num_io", "number of io", ::cxxopts::value< uint64_t >()->default_value("300"),
                   "number"),
                  (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"),
                  (dev_size_gb, "", "dev_size_gb", "size of each device in GB",
                   ::cxxopts::value< uint64_t >()->default_value("5"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_data_service);
    sisl::logging::SetLogger("test_data_service");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    gp.num_threads = SISL_OPTIONS["num_threads"].as< uint32_t >();
    gp.run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    gp.num_io = SISL_OPTIONS["num_io"].as< uint64_t >();
    gp.is_spdk = SISL_OPTIONS["spdk"].as< bool >();

    const auto ret{RUN_ALL_TESTS()};
    return ret;
}
