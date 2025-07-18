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
#include <random>
#include <unordered_set>
#include <farmhash.h>

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/fds/buffer.hpp>
#include <gtest/gtest.h>
#include <iomgr/iomgr_flip.hpp>
#include <folly/concurrency/ConcurrentHashMap.h>

#include <homestore/blk.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include "device/device.h"
#include "device/physical_dev.hpp"
#include "device/virtual_dev.hpp"
#include "device/chunk.h"
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

constexpr uint64_t Ki{1024};
constexpr uint64_t Mi{Ki * Ki};
constexpr uint64_t Gi{Ki * Mi};

struct Param {
    uint64_t num_io{1000};
    uint64_t run_time{200};        // in seconds
    uint32_t min_io_size{4 * Ki};  // blk_size aligned;
    uint32_t max_io_size{32 * Mi}; // blk_size aligned;
};

static Param gp;

VENUM(DataSvcOp_t, uint8_t, async_alloc_write = 1, async_read = 2, async_free = 3, max_op = 4);

typedef std::function< void(std::error_condition err, std::shared_ptr< std::vector< BlkId > > out_bids) >
    after_write_cb_t;

class BlkDataServiceTest : public testing::Test {
public:
    BlkDataService& inst() { return homestore::data_service(); }

    virtual void SetUp() override {
        m_blk_crc_map.clear();
        m_helper.start_homestore("test_data_service",
                                 {{HS_SERVICE::META, {.size_pct = 5.0}}, {HS_SERVICE::DATA, {.size_pct = 80.0}}});

        if (gp.min_io_size % homestore::data_service().get_blk_size() ||
            gp.max_io_size % homestore::data_service().get_blk_size()) {
            gp.min_io_size = sisl::round_up(gp.min_io_size, homestore::data_service().get_blk_size());
            gp.max_io_size = sisl::round_up(gp.max_io_size, homestore::data_service().get_blk_size());
            LOGWARN("adjusted to min_io_size: {} and max_io_size: {} which must be multiple of blk_size: {}",
                    gp.min_io_size, gp.max_io_size, homestore::data_service().get_blk_size());
        }
    }

    virtual void TearDown() override { m_helper.shutdown_homestore(); }

    void free(sisl::sg_list& sg) { test_common::HSTestHelper::free(sg); }

    // free_blk after read completes
    void write_read_free_blk(uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();
        auto test_blkid_ptr = std::make_shared< MultiBlkId >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */, *test_blkid_ptr)
            .thenValue([this, sg_write_ptr, sg_read_ptr, test_blkid_ptr](auto&& err) {
                RELEASE_ASSERT(!err, "Write error");
                LOGINFO("after_write_cb: Write completed;");
                // sg_write buffer is no longer needed;
                free(*sg_write_ptr);

                LOGINFO("Write blk ids: {}", test_blkid_ptr->to_string());
                HS_REL_ASSERT_GE(test_blkid_ptr->num_pieces(), 1);

                struct iovec iov;
                iov.iov_len = test_blkid_ptr->blk_count() * inst().get_blk_size();
                iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                sg_read_ptr->iovs.push_back(iov);
                sg_read_ptr->size = iov.iov_len;

                LOGINFO("Step 2: async read on blkid: {}", test_blkid_ptr->to_string());
                return inst().async_read(*test_blkid_ptr, *sg_read_ptr, sg_read_ptr->size);
            })
            .thenValue([this, sg_read_ptr, test_blkid_ptr](auto&& err) {
                RELEASE_ASSERT(!err, "Read error");
                LOGINFO("read completed;");
                free(*sg_read_ptr);
                return inst().async_free_blk(*test_blkid_ptr);
            })
            .thenValue([this, test_blkid_ptr](auto&& err) {
                RELEASE_ASSERT(!err, "free_blk error");
                LOGINFO("completed async_free_blk: {}", test_blkid_ptr->to_string());
                this->finish_and_notify();
            });
    }

    // free_blk before read completes
    void write_free_blk_before_read_comp(const uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();
        auto test_blkid_ptr = std::make_shared< MultiBlkId >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */, *test_blkid_ptr)
            .thenValue([this, sg_write_ptr, sg_read_ptr, test_blkid_ptr](auto&& err) {
                RELEASE_ASSERT(!err, "Write error");
                LOGINFO("after_write_cb: Write completed;");
                free(*sg_write_ptr); // sg_write buffer is no longer needed;

                LOGINFO("Write blk ids: {}", test_blkid_ptr->to_string());
                HS_REL_ASSERT_GE(test_blkid_ptr->num_pieces(), 1);

                struct iovec iov;
                iov.iov_len = test_blkid_ptr->blk_count() * inst().get_blk_size();
                iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                sg_read_ptr->iovs.push_back(iov);
                sg_read_ptr->size = iov.iov_len;

                LOGINFO("Step 2a: inject read delay and read on blkid: {}", test_blkid_ptr->to_string());
                add_read_delay();
                inst()
                    .async_read(*test_blkid_ptr, *sg_read_ptr, sg_read_ptr->size)
                    .thenValue([sg_read_ptr, this](auto&& err) {
                        RELEASE_ASSERT(!err, "Read error");

                        // if we are here, free_blk callback must have been called already, because data service layer
                        // trigger the free_blk cb firstly then send read complete cb back to caller;
                        m_read_blk_done = true;
                        LOGINFO("read completed;");
                        HS_REL_ASSERT_EQ(m_free_blk_done.load(), true,
                                         "free blk callback should not be called before read blk completes");

                        free(*sg_read_ptr);
                        this->finish_and_notify();
                    });

                LOGINFO("Step 3: started async_free_blk: {}", test_blkid_ptr->to_string());
                inst().async_free_blk(*test_blkid_ptr).thenValue([this](auto&& err) {
                    RELEASE_ASSERT(!err, "free_blk error");
                    LOGINFO("completed async_free_blk");
                    HS_REL_ASSERT_EQ(m_free_blk_done.load(), false, "Duplicate free blk completion");
                    m_free_blk_done = true;
                });
            });
    }

    void write_io_free_blk(const uint64_t io_size) {
        std::shared_ptr< sisl::sg_list > sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto test_blkid_ptr = std::make_shared< MultiBlkId >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */, *test_blkid_ptr)
            .thenValue([sg_write_ptr, this, test_blkid_ptr](auto&& err) {
                RELEASE_ASSERT(!err, "Write error");
                LOGINFO("after_write_cb: Write completed;");
                free(*sg_write_ptr);

                LOGINFO("Step 2: started async_free_blk: {}", test_blkid_ptr->to_string());
                inst().async_free_blk(*test_blkid_ptr).thenValue([this](auto&& err) {
                    RELEASE_ASSERT(!err, "Free error");
                    LOGINFO("completed async_free_blks");
                    this->finish_and_notify();
                });
            });
    }

    void write_io_verify(const uint64_t io_size) {
        auto sg_write_ptr = std::make_shared< sisl::sg_list >();
        auto sg_read_ptr = std::make_shared< sisl::sg_list >();
        auto test_blkid_ptr = std::make_shared< MultiBlkId >();

        write_sgs(io_size, sg_write_ptr, 1 /* num_iovs */, *test_blkid_ptr)
            .thenValue([sg_write_ptr, sg_read_ptr, test_blkid_ptr, this](auto&& err) {
                RELEASE_ASSERT(!err, "Write error");

                // this will be called in write io completion cb;
                LOGINFO("after_write_cb: Write completed;");

                // TODO: verify multiple read blks;
                HS_DBG_ASSERT_EQ(test_blkid_ptr->num_pieces(), 1);

                struct iovec iov;
                iov.iov_len = test_blkid_ptr->blk_count() * inst().get_blk_size();
                iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
                sg_read_ptr->iovs.push_back(iov);
                sg_read_ptr->size = iov.iov_len;

                LOGINFO("Step 2: async read on blkid: {}", test_blkid_ptr->to_string());
                return inst().async_read(*test_blkid_ptr, *sg_read_ptr, sg_read_ptr->size);
            })
            .thenValue([this, sg_write_ptr, sg_read_ptr](auto&& err) mutable {
                RELEASE_ASSERT(!err, "Read error");

                const auto equal = test_common::HSTestHelper::compare(*sg_read_ptr, *sg_write_ptr);
                RELEASE_ASSERT(equal, "Read after write data mismatch");

                LOGINFO("Read completed;");
                free(*sg_write_ptr);
                free(*sg_read_ptr);

                this->finish_and_notify();
            });
    }

    void write_and_restart_with_missing_data_drive(const uint64_t io_size) {
        vdev_info vinfo;
        auto data_vdev = inst().open_vdev(vinfo, true);

        // get all the pdevs of this vdev
        auto drives = data_vdev->get_pdevs();
        RELEASE_ASSERT_EQ(drives.size() > 1, true, "missing drive test expecting at least 2 Data drives");
        auto it = drives.begin();
        // missing_pdev is the pdev that will be missing after restart;
        auto missing_pdev = (*it++);
        // living_pdev is the pdev that will be living after restart;
        auto living_pdev = *it;

        // get all the chunks of this vdev
        auto chunks = data_vdev->get_chunks();

        // try to find a chunk for each pdev
        shared< Chunk > chunk_in_missing_pdev;
        shared< Chunk > chunk_in_living_pdev;

        // we can keep all the chunks of a pdev in a vector, but that will be only used for this test,
        // so, we do not do this for now. we can modify the logic here if we add that vector in the future.
        for (auto& [_, chunk] : chunks) {
            if (!chunk) continue;
            if (chunk_in_missing_pdev && chunk_in_living_pdev) break;
            if (!chunk_in_missing_pdev && (chunk->physical_dev() == missing_pdev)) {
                chunk_in_missing_pdev = chunk;
                continue;
            }
            if (!chunk_in_living_pdev && chunk->physical_dev() == living_pdev) {
                chunk_in_living_pdev = chunk;
                continue;
            }
        }

        RELEASE_ASSERT(chunk_in_missing_pdev, "can not find a chunk on missing drive");
        RELEASE_ASSERT(chunk_in_living_pdev, "can not find a chunk on living drive");

        LOGINFO("Step 2: write data to these two chunks.");
        // write blks to both of the chunks
        MultiBlkId missing_drive_blk;
        MultiBlkId living_drive_blk;

        blk_alloc_hints hints;

        auto sg_write_ptr1 = std::make_shared< sisl::sg_list >();
        hints.chunk_id_hint = chunk_in_living_pdev->chunk_id();
        ++m_outstanding_io_cnt;
        write_sgs(io_size, sg_write_ptr1, 4, living_drive_blk, hints).thenValue([this](auto&& err) {
            RELEASE_ASSERT(!err, "Write error");
            // do not free , use it when test write
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });

        hints.chunk_id_hint = chunk_in_missing_pdev->chunk_id();
        auto sg_write_ptr2 = std::make_shared< sisl::sg_list >();
        ++m_outstanding_io_cnt;
        write_sgs(io_size, sg_write_ptr2, 4, missing_drive_blk, hints).thenValue([this](auto&& err) {
            RELEASE_ASSERT(!err, "Write error");
            // free(*sg_write_ptr2); do not free , use it when test write
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });

        // Wait for write operations to complete
        wait_for_outstanding_io_done();

        LOGINFO("Step 3: restart with missing data drive(pdev).");
        auto dev_mgr = homestore::HomeStore::instance()->device_mgr();
        std::vector< dev_info > start_with_devices;
        auto fast_pdevs = dev_mgr->get_pdevs_by_dev_type(homestore::HSDevType::Fast);
        for (auto& pdev : fast_pdevs) {
            // can not lose fast drive
            start_with_devices.emplace_back(pdev->get_devname(), homestore::HSDevType::Fast);
        }

        // lose one data drive
        for (auto& pdev : drives) {
            if (pdev->pdev_id() != missing_pdev->pdev_id()) {
                start_with_devices.emplace_back(living_pdev->get_devname(), homestore::HSDevType::Data);
            }
        }

        // restart with the given drive list
        m_helper.change_device_list(start_with_devices);
        m_helper.restart_homestore();

        LOGINFO("Step 4: read the blk from missing data drive");
        auto sg = std::make_shared< sisl::sg_list >();
        sg->size = io_size;
        struct iovec iov;
        iov.iov_len = io_size;
        iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
        sg->iovs.push_back(iov);

        ++m_outstanding_io_cnt;
        inst().async_read(missing_drive_blk, *sg, io_size).thenValue([this](auto&& err) {
            RELEASE_ASSERT_EQ(err == std::make_error_code(std::errc::resource_unavailable_try_again), true,
                              "should not be able to read blk on missing drive");
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });

        ++m_outstanding_io_cnt;
        LOGINFO("Step 5: read the blk from living data drive");
        inst().async_read(living_drive_blk, *sg, io_size).thenValue([this, sg](auto&& err) {
            RELEASE_ASSERT(!err, "should be able to read blk on living drive");
            free(*sg);
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });

        wait_for_outstanding_io_done();

        LOGINFO("Step 6: write the blk to living data drive");
        ++m_outstanding_io_cnt;
        inst()
            .async_write(*(sg_write_ptr1.get()), living_drive_blk, false)
            .thenValue([this, sg_write_ptr1](auto&& err) {
                RELEASE_ASSERT(!err, "should not be able to write blk on living drive");
                free(*sg_write_ptr1);
                --m_outstanding_io_cnt;
                ++m_total_io_comp_cnt;
            });

        LOGINFO("Step 7: write the blk to missing data drive");
        ++m_outstanding_io_cnt;
        inst()
            .async_write(*(sg_write_ptr2.get()), missing_drive_blk, false)
            .thenValue([this, sg_write_ptr2](auto&& err) {
                RELEASE_ASSERT_EQ(err == std::make_error_code(std::errc::resource_unavailable_try_again), true,
                                  "should not be able to write blk on living drive");
                free(*sg_write_ptr2);
                --m_outstanding_io_cnt;
                ++m_total_io_comp_cnt;
            });

        wait_for_outstanding_io_done();

        LOGINFO("Step 8: free the blk from missing data drive");
        ++m_outstanding_io_cnt;
        inst().async_free_blk(missing_drive_blk).thenValue([this](auto&& err) {
            RELEASE_ASSERT_EQ(err == std::make_error_code(std::errc::resource_unavailable_try_again), true,
                              "should not be able to free blk on living drive");
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });

        LOGINFO("Step 9: free the blk from living data drive");
        ++m_outstanding_io_cnt;
        inst().async_free_blk(living_drive_blk).thenValue([this](auto&& err) {
            RELEASE_ASSERT(!err, "should be able to free blk on living drive");
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });
    }

    //
    // this api is for caller who is not interested with the write buffer and blkids;
    //
    void write_io(uint64_t io_size, uint32_t num_iovs = 1) {
        auto sg = std::make_shared< sisl::sg_list >();
        MultiBlkId blkid;
        write_sgs(io_size, sg, num_iovs, blkid).thenValue([this, sg](auto) {
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

    // wait for all io jobs to complete;
    void wait_for_all_io_complete() {
        std::unique_lock lk(m_mtx);
        m_cv.wait(lk, [this] { return this->m_io_job_done; });
    }

    ////////////////////////// Load Test APIS ////////////////////////////////
    void write_io_load(uint64_t io_size, uint32_t num_iovs = 1) {
        auto sg = std::make_shared< sisl::sg_list >();
        auto out_bids = std::make_shared< MultiBlkId >();
        ++m_outstanding_io_cnt;
        // out_bids are returned syncronously;
        write_sgs(io_size, sg, num_iovs, *out_bids).thenValue([this, sg, out_bids](auto) {
            cal_write_blk_crc(*sg, *out_bids);
            free(*sg);
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });
    }

    // read_io has to process and send async_read all the blkids before it can exit and yielf to next io;
    // because next io could be free_blk which can also pick up the same blkid, that has been generated for read, but
    // hasn't been sent yet.
    void read_io(uint32_t io_size) {
        auto remaining_io_size = io_size;
        while (remaining_io_size > 0) {
            auto const bid = get_rand_blkid_to_read(remaining_io_size);
            if (!bid.is_valid()) {
                // didn't find any block to read, either write blk map is empty or
                // all blks are pending on free.
                return;
            }

            // every piece in bid is a single block, e.g.  nblks = 1
            auto const nbids = bid.num_pieces();
            auto sub_io_size = nbids * inst().get_blk_size();
            HS_REL_ASSERT_LE(sub_io_size, remaining_io_size, "not expecting sub_io_size to exceed remaining_io_size");

            // we pass crc from lambda becaues if there is any async_free_blk, the written blks in the blkcrc map will
            // be removed by the time read thenVlue is called;
            // this must be called before we send to iomgr worker thread, because worker thread might pick it up running
            // later but outer for loop will continue to run to free this same blk;
            auto read_crc_vec = get_crc_vector(bid);

            iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, read_crc_vec, bid, sub_io_size]() {
                this->do_read_io(bid, sub_io_size, read_crc_vec);
            });
            remaining_io_size -= sub_io_size;
        }
    }

    void free_blk(MultiBlkId bid) {
        RELEASE_ASSERT(bid.is_valid(), "expecting valid bid and single blkid, is_valid: {}", bid.is_valid());

        ++m_outstanding_io_cnt;
        inst().async_free_blk(bid).thenValue([this, bid](auto&& err) {
            RELEASE_ASSERT(!err, "Free error");
            LOGINFO("completed async_free_blks, bid freed: {}", bid.to_string());
            // remove from ouststanding free blk set and written blk crc map;
            {
                std::scoped_lock l(m_free_mtx, m_blkmap_mtx);
                // loop bid for every piece of blkid;
                auto bid_it = bid.iterate();

                while (auto b = bid_it.next()) {
                    LOGINFO("removing bid from map: {}", bid.to_string());
                    m_outstanding_free_bid.erase(b->to_integer());
                    m_blk_crc_map.erase(b->to_integer());
                }
            }
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });
    }

    // wait for all outstanding io to complete
    void wait_for_outstanding_io_done() {
        while (this->m_outstanding_io_cnt.load() != 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }

        LOGINFO("m_total_io_comp_cnt: {}", m_total_io_comp_cnt.load());
    }
    /**
     * @brief Generates a random I/O size based on configurated min/max I/O sizes, rounded up to the block size.
     *
     * @return uint64_t The generated I/O size.
     */
    uint64_t gen_rand_io_size() {
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< long long unsigned > io_size{gp.min_io_size, gp.max_io_size};

        // result won't exceed max_io_size becaues max_io_size is blk_size aligned;
        return sisl::round_up(io_size(re), inst().get_blk_size());
    }

    /**
     * @brief Generates a random DataSvcOp_t operation type.
     *
     * @return A random DataSvcOp_t operation type.
     * TODO: Support IO ratio based on IO type:
     * .write: 0.5
     * .read: 0.3
     * .free: 0.2
     */
    DataSvcOp_t gen_rand_op_type() {
        // gererate randome op type based on the ratio;
        // write op ratio: 50%
        // read op ratio : 30%, free op ratio: 20%
        static thread_local std::random_device rd{};
        static thread_local std::default_random_engine re{rd()};
        std::uniform_int_distribution< uint8_t > op_type{1, static_cast< uint8_t >(DataSvcOp_t::max_op) - 1};

        return static_cast< DataSvcOp_t >(op_type(re));
    }

    MultiBlkId get_rand_blkid_to_free() {
        MultiBlkId ret_b{};
        {
            std::scoped_lock l(m_blkmap_mtx);
            // alow some warm up before we do free;
            if (m_blk_crc_map.size() < 10) { return ret_b; }
        }

        auto retry_cnt = 0ul;
        while (!ret_b.is_valid() && retry_cnt++ <= 10) {
            {
                std::scoped_lock l(m_blkmap_mtx, m_free_mtx);
                auto it = m_blk_crc_map.begin();
                std::advance(it, rand() % std::min(100ul, m_blk_crc_map.size()));

                if (m_outstanding_free_bid.find(it->first /* bid_integer */) == m_outstanding_free_bid.end()) {
                    // add to outstanding free blk set;
                    m_outstanding_free_bid.insert(it->first);
                    ret_b = MultiBlkId{BlkId{it->first}};
                }

                // else this is bid is already pending on free, continue while loop to pick another random one;
            }
        }

        return ret_b;
    }

    bool is_outstanding_free_bid(uint64_t bid_integer) {
        std::scoped_lock l(m_free_mtx);
        return m_outstanding_free_bid.find(bid_integer) != m_outstanding_free_bid.end();
    }

    // the returned blkid might be less than io_size.
    // Caller will have to redo to cover the rest of io_size;
    MultiBlkId get_rand_blkid_to_read(uint32_t io_size) {
        std::scoped_lock l(m_blkmap_mtx);
        // allow some warm up on write before reading;
        if (m_blk_crc_map.size() < 20) { return MultiBlkId{}; }

        MultiBlkId mb;
        // pick a random single bid from the map;
        auto skip_nbids = rand() % m_blk_crc_map.size(); // randomly skip between [0, size() - 1]
        auto nbids = io_size / inst().get_blk_size();    // number of blks to read;

        // nbids should not exceed max pieces that MultiBlkId can hold;
        nbids = std::min(nbids, MultiBlkId::max_addln_pieces);

        // make sure skip + nbids are in the range of m_blk_crc_map;
        if (skip_nbids + nbids > m_blk_crc_map.size()) { skip_nbids = m_blk_crc_map.size() - nbids; }

        // skip to the random position in the map;
        auto it = m_blk_crc_map.cbegin();
        std::advance(it, skip_nbids);

        for (; mb.num_pieces() < nbids && it != m_blk_crc_map.cend(); ++it) {
            if (is_outstanding_free_bid(it->first)) {
                // read should not happen on ouststanding free bids;
                continue;
            }

            // MultiBlkId can only add piece from same chunk;
            if (!mb.is_valid()) {
                mb.add(BlkId{it->first /* bid integer */});
            } else {
                BlkId blk{it->first /* bid integer */};
                if (blk.chunk_num() == mb.chunk_num()) { mb.add(blk); }
            }
        }

        // if we still can't find enough blks to read, then we need to start from the beginning of the map until the
        // skipped point;
        auto next_round_cnt = 0ul;
        for (it = m_blk_crc_map.cbegin(); mb.num_pieces() < nbids && next_round_cnt < skip_nbids;
             ++next_round_cnt, ++it) {
            if (is_outstanding_free_bid(it->first)) {
                // read should not happen on ouststanding free bids;
                continue;
            }
            // MultiBlkId can only add piece from same chunk;
            if (!mb.is_valid()) {
                mb.add(BlkId{it->first /* bid integer */});
            } else {
                BlkId blk{it->first /* bid integer */};
                if (blk.chunk_num() == mb.chunk_num()) { mb.add(blk); }
            }
        }

        // it is possible that we still can't find enough blks to read, which means all blks are pending on free,
        // which is extreamly rare case.
        HS_REL_ASSERT_LE(mb.num_pieces(), nbids, "not expecting num_pieces to exceed nbids");

        return mb;
    }
    ////////////////////////// End of Load Test APIS ////////////////////////////////

private:
    //
    // call this api when caller needs the write buffer and blkids;
    // caller is responsible to free the sg buffer;
    //
    // caller should be responsible to call free(sg) to free the iobuf allocated in iovs,
    // normally it should be freed in after_write_cb;
    //
    folly::Future< std::error_code > write_sgs(uint64_t io_size, cshared< sisl::sg_list > sg, uint32_t num_iovs,
                                               MultiBlkId& out_bids,
                                               std::optional< blk_alloc_hints > hints = std::nullopt) {
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
        auto fut = inst().async_alloc_write(*(sg.get()), hints.value_or(blk_alloc_hints{}), out_bids,
                                            false /* part_of_batch*/);
        inst().commit_blk(out_bids);
        return fut;
    }

    void verify_read_blk_crc(sisl::sg_list& sg, std::vector< uint64_t > read_crc_vec) {
        auto const blk_size = inst().get_blk_size();
        auto const blk_count = sg.iovs[0].iov_len / blk_size;
        auto const blk_base = r_cast< uint8_t* >(sg.iovs[0].iov_base);
        auto blk_base_offset = 0ul;

        RELEASE_ASSERT_EQ(sg.iovs.size(), 1, "not expecting iovs size to be greater than 1");
        RELEASE_ASSERT_EQ(sg.iovs[0].iov_len % inst().get_blk_size(), 0,
                          "iov_len expected to be aligned with blk_size");
        RELEASE_ASSERT_EQ(blk_count, read_crc_vec.size(), "expecting blk_count to be equal to crc vec size");

        for (auto i = 0ul; i < blk_count; ++i) {
            auto blk_crc = util::Hash64((const char*)(blk_base + blk_base_offset), blk_size);
            HS_REL_ASSERT_EQ(read_crc_vec[i], blk_crc, "blk crc mismatch");
            blk_base_offset += blk_size;
        }
    }

#if 0
    void verify_read_blk_crc(sisl::sg_list& sg, MultiBlkId bid) {
        auto const blk_size = inst().get_blk_size();
        auto const blk_count = sg.iovs[0].iov_len / blk_size;
        auto const blk_base = r_cast< uint8_t* >(sg.iovs[0].iov_base);
        auto const blk_base_offset = 0ul;

        RELEASE_ASSERT_EQ(sg.iovs.size(), 1, "not expecting iovs size to be greater than 1");
        RELEASE_ASSERT_EQ(sg.iovs[0].iov_len % inst().get_blk_size(), 0,
                          "iov_len expected to be aligned with blk_size");
        RELEASE_ASSERT_EQ(blk_count, bid.num_pieces(), "expecting blk_count to be equal to num_pieces");

        {
            std::scoped_lock l(m_blkmap_mtx);
            auto bid_it = bid.iterate();
            while (b = bid_it.next()) {
                // move to next piece of BlkId, ever piece of BlkId is a single block whose nblks equals to 1;
                auto it = m_blk_crc_map.find(b.to_integer());
                HS_REL_ASSERT(it != m_blk_crc_map.end(), "expecting blk to be in the map");

                auto blk_crc = util::Hash64((const char*)(blk_base + blk_base_offset), blk_size);
                HS_REL_ASSERT_EQ(it->second, blk_crc, "blk crc mismatch");
                blk_base_offset += blk_size;
            }
        }
    }
#endif
    // copy crc from m_blk_crc_map to a vector;
    cshared< std::vector< uint64_t > > get_crc_vector(MultiBlkId bid) {
        auto crc_vec = std::make_shared< std::vector< uint64_t > >();
        auto bid_it = bid.iterate();
        while (auto const b = bid_it.next()) {
            std::scoped_lock l(m_blkmap_mtx);
            // LOGINFO("getting crc for blk: {}, is_multi: {}, integer:{}", b->to_string(), b->is_multi(),
            // b->to_integer());
            auto it = m_blk_crc_map.find(b->to_integer());
            HS_REL_ASSERT(it != m_blk_crc_map.end(), "expecting blk:{} to be in the map", b->to_string());
            crc_vec->push_back(it->second);
        }

        return crc_vec;
    }

    void do_read_io(MultiBlkId bid, uint32_t io_size, cshared< std::vector< uint64_t > > read_crc_vec) {
        auto sg = std::make_shared< sisl::sg_list >();
        sg->size = io_size;
        struct iovec iov;
        iov.iov_len = io_size;
        iov.iov_base = iomanager.iobuf_alloc(512, iov.iov_len);
        sg->iovs.push_back(iov);
        ++m_outstanding_io_cnt;
        inst().async_read(bid, *sg, io_size).thenValue([this, bid, sg, read_crc_vec](auto&& err) {
            // if there is any pending free blk on this read, and if we arrive here, the free blk callback has
            // already been called;
            RELEASE_ASSERT(!err, "Read error");
            // LOGINFO("read completed, bid: {}", bid.to_string());

            // now verify read data crc equals which was previous saved on write;
            verify_read_blk_crc(*sg, *read_crc_vec);

            free(*sg);
            --m_outstanding_io_cnt;
            ++m_total_io_comp_cnt;
        });
    }

    /**
     * Calculates and writes the CRC for a given scatter-gather list and block ID.
     *
     * The crc will be calcuated based on per-block-size and save them to m_blk_crc_map;
     * this map is used for read verfication;
     *
     * @param sg The scatter-gather list to calculate the CRC for.
     * @param bid The ID of the block to calculate the CRC for.
     */
    void cal_write_blk_crc(sisl::sg_list& sg, MultiBlkId bid) {
        RELEASE_ASSERT_EQ(sg.iovs.size(), 1, "Only expect one iov.");

        // calculate crc blk by blk and save them to m_blk_crc_map;
        auto const iov = sg.iovs[0];
        auto const blk_size = inst().get_blk_size();
        auto const blk_count = iov.iov_len / blk_size;
        auto const blk_base = r_cast< uint8_t* >(iov.iov_base);
        auto blk_base_offset = 0ul;
        std::vector< BlkId > single_blkid_vec{};
        auto bid_it = bid.iterate();
        // loop bid for every piece of blkid and convert them into single blkid, nblks=1;
        auto total_single_blks_cnt{0ul};
        while (auto b = bid_it.next()) {
            for (auto i = 0u; i < b->blk_count(); ++i) {
                single_blkid_vec.push_back(BlkId{b->blk_num() + i /* blk_num */, 1 /* nblks */, b->chunk_num()});
                RELEASE_ASSERT_EQ(single_blkid_vec[i].is_multi(), false, "not expecting multile blkid");
                ++total_single_blks_cnt;
            }
        }

        RELEASE_ASSERT_EQ(blk_count, total_single_blks_cnt,
                          "expecting blk_count to be equal to total blks found in bid");

        // now insert blk crc to its corresponding blk id in m_blk_crc_map;
        for (auto i = 0ul; i < blk_count; ++i) {
            auto blk_crc = util::Hash64((const char*)(blk_base + blk_base_offset), blk_size);
            blk_base_offset += blk_size;
            // also works for overwritten blks;
            {
                std::scoped_lock l(m_blkmap_mtx);
                auto [it, inserted] = m_blk_crc_map.insert_or_assign(single_blkid_vec[i].to_integer(), blk_crc);
                RELEASE_ASSERT_EQ(inserted, true);
                LOGDEBUG("blk inserted: {}, is_multi:{}, crc: {}, integer: {}", single_blkid_vec[i].to_string(),
                         single_blkid_vec[i].is_multi(), blk_crc, single_blkid_vec[i].to_integer());
            }
        }
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
    std::atomic< bool > m_free_blk_done{false};
    std::atomic< bool > m_read_blk_done{false};

    // blk to crc mapping, the crc is calculated from the data buffer that is pointed by this blk for each blk_size.
    // e.g. if data service blk size is 4K, then crc is calculated for every 4K data buffer;
    std::mutex m_blkmap_mtx;
    std::unordered_map< uint64_t, uint64_t > m_blk_crc_map{gp.num_io};
    std::mutex m_free_mtx;
    std::unordered_set< uint64_t > m_outstanding_free_bid;
    std::atomic< uint64_t > m_outstanding_io_cnt{0};
    std::atomic< uint64_t > m_total_io_comp_cnt{0};
    test_common::HSTestHelper m_helper;
};

//
// single vector in sg_list;
//
TEST_F(BlkDataServiceTest, TestBasicWrite) {
    // start io in worker thread;
    const auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(BlkDataServiceTest, TestWriteMultiplePagesSingleIov) {
    // start io in worker thread;
    const auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(BlkDataServiceTest, TestWriteMultiplePagesMultiIovs) {
    // start io in worker thread;
    const auto io_size = 4 * Mi;
    const auto num_iovs = 4;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, and {} iovs", io_size, num_iovs);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size, num_iovs]() { this->write_io(io_size, num_iovs); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(BlkDataServiceTest, TestWriteThenReadVerify) {
    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() { this->write_io_verify(io_size); });

    LOGINFO("Step 3: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 4: I/O completed, do shutdown.");
}

// Free_blk test, no read involved;
TEST_F(BlkDataServiceTest, TestWriteThenFreeBlk) {
    // start io in worker thread;
    auto io_size = 4 * Mi;
    LOGINFO("Step 1: run on worker thread to schedule write for {} Bytes, then free blk.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_io_free_blk(io_size); });

    LOGINFO("Step 3: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 4: I/O completed, do shutdown.");
}

//
// write, read, then free the blk after read completes, free should succeed
//
TEST_F(BlkDataServiceTest, TestWriteReadThenFreeBlkAfterReadComp) {
    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: Run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_read_free_blk(io_size); });

    LOGINFO("Step 2: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 3: I/O completed, do shutdown.");
}

TEST_F(BlkDataServiceTest, TestWriteReadThenFreeBeforeReadComp) {
    // start io in worker thread;
    auto io_size = 4 * Ki;
    LOGINFO("Step 1: Run on worker thread to schedule write for {} Bytes.", io_size);
    iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                            [this, io_size]() { this->write_free_blk_before_read_comp(io_size); });

    LOGINFO("Step 4: Wait for I/O to complete.");
    wait_for_all_io_complete();

    LOGINFO("Step 5: I/O completed, do shutdown.");
}

/**
 * @brief Tests the random read-write-free load functionality of the BlkDataService.
 *  Random write, read-verify, free blks;
 */
TEST_F(BlkDataServiceTest, TestRandMixIOLoad) {
    // Define the test parameters
    auto const run_time = gp.run_time;
    auto const num_io = gp.num_io;

    // Start the I/O operations
    for (uint64_t i = 0; i < num_io; ++i) {
        // Generate a random I/O size round up to blk_size;
        uint32_t const io_size = gen_rand_io_size();

        // Generate a random I/O operation
        auto const io_op = gen_rand_op_type();

        // Perform the I/O operation
        switch (io_op) {
        case DataSvcOp_t::async_alloc_write: // Write
            iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() {
                // num_iovs defaulted to 1;
                this->write_io_load(io_size);
            });
            break;
        case DataSvcOp_t::async_read: // Read

            // iomanager.run_on_forget(iomgr::reactor_regex::random_worker, [this, io_size]() {
            // this->read_io(io_size);});
            this->read_io(io_size);
            break;
        case DataSvcOp_t::async_free: // free
        {
            auto const blkid = get_rand_blkid_to_free();
            if (blkid.is_valid()) {
                iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                                        [this, blkid]() { this->free_blk(blkid); });
            }
            // else skip this free request as not able to find a good free candidate;
            // it can happen if there is little blk left in the map, and all of them are already pending
            // free;
            break;
        }
        case DataSvcOp_t::max_op:
        default:
            RELEASE_ASSERT(false, "Unexpected I/O operation type");
            break;
        }
    }

    // Wait for the I/O operations to complete
    wait_for_outstanding_io_done();
}

/**
 * @brief homestore can be started with a missing drive.
 * 1 all the blks in the missing drive can not be read.
 * 2 all the blks in the alive drives should be able to read;
 *
 * we do not support restart with a missing Fast Drive, where meta data is stored;
 */
TEST_F(BlkDataServiceTest, TestRestartWithMissingDrive) {
    auto io_size = 4 * Mi;
    LOGINFO("Step 1: find two chunks in different pdevs.");
    write_and_restart_with_missing_data_drive(io_size);
    LOGINFO("Step 10: wait for read and verify done.");
    wait_for_outstanding_io_done();
    LOGINFO("Step 11: I/O completed, do shutdown.");
}

// Stream related test

SISL_OPTION_GROUP(test_data_service,
                  (run_time, "", "run_time", "running time in seconds",
                   ::cxxopts::value< uint64_t >()->default_value("30"), "number"),
                  (min_io_size, "", "min_io_size", "mim io size", ::cxxopts::value< uint32_t >()->default_value("4096"),
                   "number"),
                  (max_io_size, "", "max_io_size", "max io size", ::cxxopts::value< uint32_t >()->default_value("4096"),
                   "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_data_service, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_data_service");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");
    gp.run_time = SISL_OPTIONS["run_time"].as< uint64_t >();
    gp.num_io = SISL_OPTIONS["num_io"].as< uint64_t >();

    gp.min_io_size = SISL_OPTIONS["min_io_size"].as< uint32_t >();
    gp.max_io_size = SISL_OPTIONS["max_io_size"].as< uint32_t >();
    return RUN_ALL_TESTS();
}
