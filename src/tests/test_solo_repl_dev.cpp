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
    sisl::sg_list read_sgs;
    MultiBlkId written_blkids;

    test_repl_req() {
        write_sgs.size = 0;
        read_sgs.size = 0;
    }
    ~test_repl_req() {
        for (auto const& iov : write_sgs.iovs) {
            iomanager.iobuf_free(uintptr_cast(iov.iov_base));
        }

        for (auto const& iov : read_sgs.iovs) {
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

        void on_commit(int64_t lsn, sisl::blob const& header, sisl::blob const& key, MultiBlkId const& blkids,
                       cintrusive< repl_req_ctx >& ctx) override {
            if (ctx == nullptr) {
                m_test.validate_replay(*repl_dev(), lsn, header, key, blkids);
            } else {
                auto req = boost::static_pointer_cast< test_repl_req >(ctx);
                req->written_blkids = std::move(blkids);
                m_test.on_write_complete(*repl_dev(), req);
            }
        }

        AsyncReplResult<> create_snapshot(repl_snapshot& s) override { return make_async_success<>(); }

        bool on_pre_commit(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                           cintrusive< repl_req_ctx >& ctx) override {
            return true;
        }

        void on_rollback(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                         cintrusive< repl_req_ctx >& ctx) override {}

        ReplResult< blk_alloc_hints > get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) override {
            return blk_alloc_hints{};
        }

        void on_restart() override { LOGINFO("ReplDev restarted"); }

        void on_error(ReplServiceError error, const sisl::blob& header, const sisl::blob& key,
                      cintrusive< repl_req_ctx >& ctx) override {
            LOGINFO("Received error={} on repl_dev", enum_name(error));
        }
        void on_destroy() override {}
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

    void validate_replay(ReplDev& rdev, int64_t lsn, sisl::blob const& header, sisl::blob const& key,
                         MultiBlkId const& blkids) {
        auto const jhdr = r_cast< test_repl_req::journal_header const* >(header.cbytes());
        HSTestHelper::validate_data_buf(key.cbytes(), key.size(), jhdr->key_pattern);

        uint32_t size = blkids.blk_count() * g_block_size;
        if (size) {
            auto read_sgs = HSTestHelper::create_sgs(size, size);
            LOGDEBUG("[{}] Validating replay of lsn={} blkid = {}", boost::uuids::to_string(rdev.group_id()), lsn,
                     blkids.to_string());
            rdev.async_read(blkids, read_sgs, size)
                .thenValue([this, hdr = *jhdr, read_sgs, lsn, blkids, &rdev](auto&& err) {
                    RELEASE_ASSERT(!err, "Error during async_read");
                    HS_REL_ASSERT_EQ(hdr.data_size, read_sgs.size, "journal hdr data size mismatch with actual size");

                    for (auto const& iov : read_sgs.iovs) {
                        HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len, hdr.data_pattern);
                        iomanager.iobuf_free(uintptr_cast(iov.iov_base));
                    }
                    LOGDEBUG("[{}] Replay of lsn={} blkid={} validated successfully",
                             boost::uuids::to_string(rdev.group_id()), lsn, blkids.to_string());
                    m_task_waiter.one_complete();
                });
        } else {
            m_task_waiter.one_complete();
        }
    }

    void on_write_complete(ReplDev& rdev, intrusive< test_repl_req > req) {
        // If we did send some data to the repl_dev, validate it by doing async_read
        if (req->write_sgs.size != 0) {
            req->read_sgs = HSTestHelper::create_sgs(req->write_sgs.size, req->write_sgs.size);

            auto const cap = hs()->repl_service().get_cap_stats();
            LOGDEBUG("Write complete with cap stats: used={} total={}", cap.used_capacity, cap.total_capacity);

            rdev.async_read(req->written_blkids, req->read_sgs, req->read_sgs.size)
                .thenValue([this, &rdev, req](auto&& err) {
                    RELEASE_ASSERT(!err, "Error during async_read");

                    LOGDEBUG("[{}] Write complete with lsn={} for size={} blkids={}",
                             boost::uuids::to_string(rdev.group_id()), req->lsn(), req->write_sgs.size,
                             req->written_blkids.to_string());
                    auto hdr = r_cast< test_repl_req::journal_header* >(req->header->bytes());
                    HS_REL_ASSERT_EQ(hdr->data_size, req->read_sgs.size,
                                     "journal hdr data size mismatch with actual size");

                    for (auto const& iov : req->read_sgs.iovs) {
                        HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len, hdr->data_pattern);
                    }
                    m_io_runner.next_task();
                });
        } else {
            m_io_runner.next_task();
        }
    }
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
    this->m_task_waiter.start([this]() { this->restart(); }).get();
}

TEST_F(SoloReplDevTest, TestHeaderOnly) {
    LOGINFO("Step 1: run on worker threads to schedule write");
    this->m_io_runner.set_task([this]() { this->write_io(0u, 0u, g_block_size); });
    this->m_io_runner.execute().get();
    this->m_task_waiter.start([this]() { this->restart(); }).get();
}

SISL_OPTION_GROUP(test_solo_repl_dev,
                  (block_size, "", "block_size", "block size to io",
                   ::cxxopts::value< uint32_t >()->default_value("4096"), "number"));

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_solo_repl_dev, iomgr, test_common_setup);
    sisl::logging::SetLogger("test_solo_repl_dev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    g_block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
    return RUN_ALL_TESTS();
}
