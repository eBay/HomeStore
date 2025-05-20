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

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <iomgr/iomgr_flip.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/fds/buffer.hpp>
#include <gtest/gtest.h>

#include <homestore/blk.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"
#include "test_common/homestore_test_common.hpp"
#include "replication/service/generic_repl_svc.h"
#define private public
#include "replication/repl_dev/solo_repl_dev.h"

////////////////////////////////////////////////////////////////////////////
//                                                                        //
//     This test is to test solo repl device                              //
//                                                                        //
////////////////////////////////////////////////////////////////////////////

using namespace homestore;
using namespace test_common;

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_solo_repl_dev, iomgr, test_common_setup)
SISL_LOGGING_DECL(test_solo_repl_dev)

static thread_local std::random_device g_rd{};
static thread_local std::default_random_engine g_re{g_rd()};
static uint32_t g_block_size;

static constexpr uint64_t Ki{1024};
static constexpr uint64_t Mi{Ki * Ki};
static constexpr uint64_t Gi{Ki * Mi};

struct test_repl_req : public repl_req_ctx {
    sisl::byte_array header;
    sisl::byte_array key;
    sisl::sg_list write_sgs;
    std::vector< MultiBlkId > written_blkids;

    test_repl_req() { write_sgs.size = 0; }
    ~test_repl_req() {
        for (auto const& iov : write_sgs.iovs) {
            iomanager.iobuf_free(uintptr_cast(iov.iov_base));
        }
    }

    struct journal_header {
        uint32_t key_size;
        uint64_t key_pattern;
        uint64_t data_size;
        uint64_t data_pattern;
    };
};

class SoloReplDevTest : public testing::Test {
public:
    class Listener : public ReplDevListener {
    private:
        SoloReplDevTest& m_test;

    public:
        Listener(SoloReplDevTest& test) : m_test{test} {}
        virtual ~Listener() = default;

        void on_commit(int64_t lsn, sisl::blob const& header, sisl::blob const& key,
                       std::vector< MultiBlkId > const& blkids, cintrusive< repl_req_ctx >& ctx) override {
            LOGINFO("Received on_commit lsn={}", lsn);
            if (ctx == nullptr) {
                m_test.validate_replay(*repl_dev(), lsn, header, key, blkids);
            } else {
                auto req = boost::static_pointer_cast< test_repl_req >(ctx);
                req->written_blkids = std::move(blkids);
                m_test.on_write_complete(*repl_dev(), req);
            }
        }

        AsyncReplResult<> create_snapshot(shared< snapshot_context > context) override {
            return make_async_success<>();
        }
        int read_snapshot_obj(shared< snapshot_context > context, shared< snapshot_obj > snp_data) override {
            return 0;
        }
        void write_snapshot_obj(shared< snapshot_context > context, shared< snapshot_obj > snp_data) override {}
        bool apply_snapshot(shared< snapshot_context > context) override { return true; }
        shared< snapshot_context > last_snapshot() override { return nullptr; }
        void free_user_snp_ctx(void*& user_snp_ctx) override {}
        bool on_pre_commit(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                           cintrusive< repl_req_ctx >& ctx) override {
            return true;
        }

        void on_rollback(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                         cintrusive< repl_req_ctx >& ctx) override {}

        ReplResult< blk_alloc_hints > get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size,
                                                          cintrusive< homestore::repl_req_ctx >& hs_ctx) override {
            return blk_alloc_hints{};
        }

        void on_restart() override { LOGINFO("ReplDev restarted"); }

        void on_error(ReplServiceError error, const sisl::blob& header, const sisl::blob& key,
                      cintrusive< repl_req_ctx >& ctx) override {
            LOGINFO("Received error={} on repl_dev", enum_name(error));
        }
        void on_start_replace_member(const replica_member_info& member_out, const replica_member_info& member_in,
                                     trace_id_t tid) override {}
        void on_complete_replace_member(const replica_member_info& member_out, const replica_member_info& member_in,
                                        trace_id_t tid) override {}
        void on_destroy(const group_id_t& group_id) override {}
        void notify_committed_lsn(int64_t lsn) override {}
        void on_config_rollback(int64_t lsn) override {}
        void on_no_space_left(repl_lsn_t lsn, chunk_num_t chunk_id) override {}
    };

    class Application : public ReplApplication {
    private:
        SoloReplDevTest& m_test;

    public:
        Application(SoloReplDevTest& test) : m_test{test} {}
        virtual ~Application() = default;

        repl_impl_type get_impl_type() const override { return repl_impl_type::solo; }
        bool need_timeline_consistency() const { return true; }
        shared< ReplDevListener > create_repl_dev_listener(uuid_t) override {
            return std::make_shared< Listener >(m_test);
        }
        void destroy_repl_dev_listener(uuid_t) override {}
        void on_repl_devs_init_completed() { LOGINFO("Repl dev init completed CB called"); }
        std::pair< std::string, uint16_t > lookup_peer(uuid_t uuid) const override { return std::make_pair("", 0u); }
        replica_id_t get_my_repl_id() const override { return hs_utils::gen_random_uuid(); }
    };

protected:
    test_common::Runner m_io_runner;
    test_common::Waiter m_task_waiter;
    shared< ReplDev > m_repl_dev1;
    shared< ReplDev > m_repl_dev2;
    uuid_t m_uuid1;
    uuid_t m_uuid2;
    test_common::HSTestHelper m_helper;

public:
    virtual void SetUp() override {
        m_helper.start_homestore(
            "test_solo_repl_dev",
            {{HS_SERVICE::META, {.size_pct = 5.0}},
             {HS_SERVICE::REPLICATION, {.size_pct = 60.0, .repl_app = std::make_unique< Application >(*this)}},
             {HS_SERVICE::LOG,
              {.size_pct = 22.0,
               .chunk_size = 32 * 1024 * 1024,
               .vdev_size_type = vdev_size_type_t::VDEV_SIZE_DYNAMIC}}});
        m_uuid1 = hs_utils::gen_random_uuid();
        m_uuid2 = hs_utils::gen_random_uuid();
        m_repl_dev1 = hs()->repl_service().create_repl_dev(m_uuid1, {}).get().value();
        m_repl_dev2 = hs()->repl_service().create_repl_dev(m_uuid2, {}).get().value();
    }

    shared< ReplDev > repl_dev1() { return m_repl_dev1; }
    shared< ReplDev > repl_dev2() { return m_repl_dev2; }

    virtual void TearDown() override {
        m_repl_dev1.reset();
        m_repl_dev2.reset();
        m_helper.shutdown_homestore();
    }

    void restart() {
        m_repl_dev1.reset();
        m_repl_dev2.reset();
        m_helper.restart_homestore();

        m_repl_dev1 = hs()->repl_service().get_repl_dev(m_uuid1).value();
        m_repl_dev2 = hs()->repl_service().get_repl_dev(m_uuid2).value();
    }

    void write_io(uint32_t key_size, uint64_t data_size, uint32_t max_size_per_iov) {
        auto req = intrusive< test_repl_req >(new test_repl_req());
        req->header = sisl::make_byte_array(sizeof(test_repl_req::journal_header));
        auto hdr = r_cast< test_repl_req::journal_header* >(req->header->bytes());
        hdr->key_size = key_size;
        hdr->key_pattern = ((long long)rand() << 32) | rand();
        hdr->data_size = data_size;
        hdr->data_pattern = ((long long)rand() << 32) | rand();

        if (key_size != 0) {
            req->key = sisl::make_byte_array(key_size);
            HSTestHelper::fill_data_buf(req->key->bytes(), key_size, hdr->key_pattern);
        }

        if (data_size != 0) {
            req->write_sgs = HSTestHelper::create_sgs(data_size, max_size_per_iov, hdr->data_pattern);
        }

        auto& rdev = (rand() % 2) ? m_repl_dev1 : m_repl_dev2;

        auto const cap = hs()->repl_service().get_cap_stats();
        LOGDEBUG("Before write, cap stats: used={} total={}", cap.used_capacity, cap.total_capacity);

        rdev->async_alloc_write(*req->header, req->key ? *req->key : sisl::blob{}, req->write_sgs, req);
    }

    intrusive< test_repl_req > async_write_data_and_journal(uint32_t key_size, uint64_t data_size,
                                                            uint32_t max_size_per_iov, bool rand_dev = true) {
        data_size = data_size == 0 ? g_block_size : data_size;
        auto req = intrusive< test_repl_req >(new test_repl_req());
        req->header = sisl::make_byte_array(sizeof(test_repl_req::journal_header));
        auto hdr = r_cast< test_repl_req::journal_header* >(req->header->bytes());
        hdr->key_size = key_size;
        hdr->key_pattern = ((long long)rand() << 32) | rand();
        hdr->data_size = data_size;
        hdr->data_pattern = ((long long)rand() << 32) | rand();

        if (key_size != 0) {
            req->key = sisl::make_byte_array(key_size);
            HSTestHelper::fill_data_buf(req->key->bytes(), key_size, hdr->key_pattern);
        }

        req->write_sgs = HSTestHelper::create_sgs(data_size, max_size_per_iov, hdr->data_pattern);

        auto rdev = m_repl_dev1;
        if (rand_dev) { rdev = (rand() % 2) ? m_repl_dev1 : m_repl_dev2; }

        auto const cap = hs()->repl_service().get_cap_stats();
        LOGDEBUG("Before write, cap stats: used={} total={}", cap.used_capacity, cap.total_capacity);

        std::vector< MultiBlkId > blkids;
        blk_alloc_hints hints;
        auto err = rdev->alloc_blks(data_size, hints, blkids);
        RELEASE_ASSERT(!err, "Error during alloc_blks");
        RELEASE_ASSERT(!blkids.empty(), "Empty blkids");

        rdev->async_write(blkids, req->write_sgs).thenValue([this, rdev, blkids, data_size, req](auto&& err) {
            RELEASE_ASSERT(!err, "Error during async_write");
            rdev->async_write_journal(blkids, *req->header, req->key ? *req->key : sisl::blob{}, data_size, req);
        });
        return req;
    }

    void validate_replay(ReplDev& rdev, int64_t lsn, sisl::blob const& header, sisl::blob const& key,
                         std::vector< MultiBlkId > const& blkids) {
        if (blkids.empty()) {
            m_task_waiter.one_complete();
            return;
        }

        auto const jhdr = r_cast< test_repl_req::journal_header const* >(header.cbytes());
        HSTestHelper::validate_data_buf(key.cbytes(), key.size(), jhdr->key_pattern);
        uint64_t total_io = blkids.size();
        auto io_count = std::make_shared< std::atomic< uint64_t > >(0);
        for (const auto& blkid : blkids) {
            uint32_t size = blkid.blk_count() * g_block_size;
            if (size) {
                auto read_sgs = HSTestHelper::create_sgs(size, size);
                LOGDEBUG("[{}] Validating replay of lsn={} blkid = {}", boost::uuids::to_string(rdev.group_id()), lsn,
                         blkid.to_string());
                rdev.async_read(blkid, read_sgs, size)
                    .thenValue([this, io_count, total_io, hdr = *jhdr, read_sgs, lsn, blkid, &rdev](auto&& err) {
                        RELEASE_ASSERT(!err, "Error during async_read");
                        // HS_REL_ASSERT_EQ(hdr.data_size, read_sgs.size,
                        //                  "journal hdr data size mismatch with actual size");

                        for (auto const& iov : read_sgs.iovs) {
                            HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len, hdr.data_pattern);
                            iomanager.iobuf_free(uintptr_cast(iov.iov_base));
                        }
                        LOGDEBUG("[{}] Replay of lsn={} blkid={} validated successfully",
                                 boost::uuids::to_string(rdev.group_id()), lsn, blkid.to_string());

                        io_count->fetch_add(1);
                        if (*io_count == total_io) { m_task_waiter.one_complete(); }
                    });
            } else {
                m_task_waiter.one_complete();
            }
        }
    }

    void validate_sync(shared< ReplDev > rdev, intrusive< test_repl_req > req) {
        auto const hdr = r_cast< test_repl_req::journal_header const* >(req->header->cbytes());
        for (const auto& blkid : req->written_blkids) {
            uint32_t size = blkid.blk_count() * g_block_size;
            auto read_sgs = HSTestHelper::create_sgs(size, size);
            auto err = rdev->async_read(blkid, read_sgs, size).get();
            RELEASE_ASSERT(!err, "Error during async_read");
            for (auto const& iov : read_sgs.iovs) {
                HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len, hdr->data_pattern);
                iomanager.iobuf_free(uintptr_cast(iov.iov_base));
            }
            LOGDEBUG("[{}] Validating of blkid={} validated successfully", boost::uuids::to_string(rdev->group_id()),
                     blkid.to_string());
        }
    }

    void on_write_complete(ReplDev& rdev, intrusive< test_repl_req > req) {
        if (req->written_blkids.empty()) {
            m_io_runner.next_task();
            return;
        }

        // If we did send some data to the repl_dev, validate it by doing async_read
        auto io_count = std::make_shared< std::atomic< uint64_t > >(0);
        for (const auto blkid : req->written_blkids) {
            if (req->write_sgs.size != 0) {
                auto const cap = hs()->repl_service().get_cap_stats();
                LOGDEBUG("Write complete with cap stats: used={} total={}", cap.used_capacity, cap.total_capacity);

                auto sgs_size = blkid.blk_count() * g_block_size;
                auto read_sgs = HSTestHelper::create_sgs(sgs_size, sgs_size);
                rdev.async_read(blkid, read_sgs, read_sgs.size)
                    .thenValue([this, io_count, blkid, &rdev, sgs_size, read_sgs, req](auto&& err) {
                        RELEASE_ASSERT(!err, "Error during async_read");

                        LOGINFO("[{}] Write complete with lsn={} for size={} blkid={}",
                                boost::uuids::to_string(rdev.group_id()), req->lsn(), sgs_size, blkid.to_string());
                        auto hdr = r_cast< test_repl_req::journal_header* >(req->header->bytes());
                        // HS_REL_ASSERT_EQ(hdr->data_size, read_sgs.size,
                        //                  "journal hdr data size mismatch with actual size");

                        for (auto const& iov : read_sgs.iovs) {
                            LOGDEBUG("Read data blkid={} len={} data={}", blkid.to_integer(), iov.iov_len,
                                     *(uint64_t*)iov.iov_base);
                            HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len, hdr->data_pattern);
                            iomanager.iobuf_free(uintptr_cast(iov.iov_base));
                        }
                        io_count->fetch_add(1);
                        if (*io_count == req->written_blkids.size()) { m_io_runner.next_task(); }
                    });
            } else {
                m_io_runner.next_task();
            }
        }
    }

    void trigger_cp_flush() { homestore::hs()->cp_mgr().trigger_cp_flush(true /* force */).get(); }
    void truncate_and_verify(shared< ReplDev > repl_dev) {
        auto solo_dev = std::dynamic_pointer_cast< SoloReplDev >(repl_dev);
        // Truncate and verify the CP LSN's
        solo_dev->truncate();

        auto& sb = solo_dev->m_rd_sb;
        RELEASE_ASSERT(sb->last_checkpoint_lsn_2 <= sb->last_checkpoint_lsn_1, "invalid cp lsn");
        RELEASE_ASSERT(sb->last_checkpoint_lsn_1 <= sb->checkpoint_lsn, "invalid cp lsn");

        auto [last_trunc_lsn, trunc_ld_key, tail_lsn] = solo_dev->m_data_journal->truncate_info();
        RELEASE_ASSERT(sb->last_checkpoint_lsn_2 == last_trunc_lsn, "invalid trunc lsn");
    }

#ifdef _PRERELEASE
    void set_flip_point(const std::string flip_name) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(2);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        LOGINFO("Flip {} set", flip_name);
    }
#endif

private:
#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
#endif
};

TEST_F(SoloReplDevTest, TestSingleDataBlock) {
    LOGINFO("Step 1: run on worker threads to schedule write for {} Bytes.", g_block_size);
    this->m_io_runner.set_task([this]() { this->write_io(0u, g_block_size, g_block_size); });
    this->m_io_runner.execute().get();

    LOGINFO("Step 2: Restart homestore and validate replay data.", g_block_size);
    this->m_task_waiter.start([this]() { this->restart(); }).get();
}

TEST_F(SoloReplDevTest, TestRandomSizedDataBlock) {
    LOGINFO("Step 1: run on worker threads to schedule write for random bytes ranging {}-{}.", 0, 1 * Mi);
    this->m_io_runner.set_task([this]() {
        uint32_t nblks = rand() % ((1 * Mi) / g_block_size);
        uint32_t key_size = rand() % 512 + 8;
        this->write_io(key_size, nblks * g_block_size, g_block_size);
    });

    this->m_io_runner.execute().get();
    LOGINFO("Step 2: Restart homestore and validate replay data.", g_block_size);
    this->m_task_waiter.start([this]() { this->restart(); }).get();
}

TEST_F(SoloReplDevTest, TestHeaderOnly) {
    LOGINFO("Step 1: run on worker threads to schedule write");
    this->m_io_runner.set_task([this]() { this->write_io(0u, 0u, g_block_size); });
    this->m_io_runner.execute().get();
    LOGINFO("Step 2: Restart homestore and validate replay data.", g_block_size);
    this->m_task_waiter.start([this]() { this->restart(); }).get();
}

TEST_F(SoloReplDevTest, TestAsyncWriteJournal) {
    LOGINFO("Step 1: run on worker threads to schedule write for random bytes ranging {}-{}.", 0, 1 * Mi);
    this->m_io_runner.set_task([this]() {
        uint32_t nblks = rand() % ((1 * Mi) / g_block_size);
        uint32_t key_size = rand() % 512 + 8;
        this->async_write_data_and_journal(key_size, nblks * g_block_size, g_block_size);
    });

    this->m_io_runner.execute().get();
    LOGINFO("Step 2: Restart homestore and validate replay data.", g_block_size);
    this->m_task_waiter.start([this]() { this->restart(); }).get();
}

#ifdef _PRERELEASE
TEST_F(SoloReplDevTest, TestTruncate) {
    // Write and truncate on repl dev.
    LOGINFO("Step 1: run on worker threads to schedule write and truncate");

    set_flip_point("solo_repl_dev_manual_truncate");

    m_io_runner.set_task([this]() mutable {
        this->async_write_data_and_journal(0u, g_block_size, g_block_size, false /* rand_dev */);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        truncate_and_verify(repl_dev1());
    });
    m_io_runner.execute().get();
    std::this_thread::sleep_for(std::chrono::seconds(1));
}
#endif

SISL_OPTION_GROUP(test_solo_repl_dev,
                  (block_size, "", "block_size", "block size to io",
                   ::cxxopts::value< uint32_t >()->default_value("4096"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_solo_repl_dev, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_solo_repl_dev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    // TODO make it part of the test case.
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        // Checkpoint taken every 1s
        s.generic.cp_timer_us = 1000000;
    });
    HS_SETTINGS_FACTORY().save();

    g_block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
    return RUN_ALL_TESTS();
}
