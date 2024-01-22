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
 *
 *********************************************************************************/
#include <vector>
#include <iostream>
#include <filesystem>
#include <thread>

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/fds/buffer.hpp>
#include <folly/init/Init.h>
#include <folly/executors/GlobalExecutor.h>
#include <gtest/gtest.h>
#include <iomgr/iomgr_flip.hpp>
#include <homestore/blk.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"
#include "test_common/hs_repl_test_common.hpp"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/raft_repl_dev.h"

using namespace homestore;

SISL_LOGGING_DEF(test_raft_repl_dev)
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)

SISL_OPTION_GROUP(test_raft_repl_dev,
                  (block_size, "", "block_size", "block size to io",
                   ::cxxopts::value< uint32_t >()->default_value("4096"), "number"));
SISL_OPTIONS_ENABLE(logging, test_raft_repl_dev, iomgr, test_common_setup, test_repl_common_setup)

static std::unique_ptr< test_common::HSReplTestHelper > g_helper;

class TestReplicatedDB : public homestore::ReplDevListener {
public:
    struct Key {
        uint64_t id_;
        bool operator<(Key const& other) const { return id_ < other.id_; }
    };

    struct Value {
        int64_t lsn_;
        uint64_t data_size_;
        uint64_t data_pattern_;
        MultiBlkId blkid_;
    };

    struct test_req : public repl_req_ctx {
        struct journal_header {
            uint64_t data_size;
            uint64_t data_pattern;
        };

        journal_header jheader;
        uint64_t key_id;
        sisl::sg_list write_sgs;
        sisl::sg_list read_sgs;

        sisl::blob header_blob() { return sisl::blob(uintptr_cast(&jheader), sizeof(journal_header)); }
        sisl::blob key_blob() { return sisl::blob{uintptr_cast(&key_id), sizeof(uint64_t)}; }

        test_req() {
            write_sgs.size = 0;
            read_sgs.size = 0;
            key_id = (uint64_t)rand() << 32 | rand();
        }

        ~test_req() {
            for (auto const& iov : write_sgs.iovs) {
                iomanager.iobuf_free(uintptr_cast(iov.iov_base));
            }

            for (auto const& iov : read_sgs.iovs) {
                iomanager.iobuf_free(uintptr_cast(iov.iov_base));
            }
        }
    };

    TestReplicatedDB() = default;
    virtual ~TestReplicatedDB() = default;

    void on_commit(int64_t lsn, sisl::blob const& header, sisl::blob const& key, MultiBlkId const& blkids,
                   cintrusive< repl_req_ctx >& ctx) override {
        LOGINFO("[Replica={}] Received commit on lsn={}", g_helper->replica_num(), lsn);
        ASSERT_EQ(header.size(), sizeof(test_req::journal_header));

        auto jheader = r_cast< test_req::journal_header const* >(header.cbytes());
        Key k{.id_ = *(r_cast< uint64_t const* >(key.cbytes()))};
        Value v{
            .lsn_ = lsn, .data_size_ = jheader->data_size, .data_pattern_ = jheader->data_pattern, .blkid_ = blkids};

        {
            std::unique_lock lk(db_mtx_);
            inmem_db_.insert_or_assign(k, v);
        }

        if (ctx->is_proposer) { g_helper->runner().next_task(); }
    }

    bool on_pre_commit(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                       cintrusive< repl_req_ctx >& ctx) override {
        LOGINFO("[Replica={}] Received pre-commit on lsn={}", g_helper->replica_num(), lsn);
        return true;
    }

    void on_rollback(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                     cintrusive< repl_req_ctx >& ctx) override {
        LOGINFO("[Replica={}] Received rollback on lsn={}", g_helper->replica_num(), lsn);
    }

    blk_alloc_hints get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) override {
        return blk_alloc_hints{};
    }

    void on_replica_stop() override {}

    void db_write(uint64_t data_size, uint32_t max_size_per_iov) {
        auto req = intrusive< test_req >(new test_req());
        req->jheader.data_size = data_size;
        req->jheader.data_pattern = ((long long)rand() << 32) | rand();
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();

        if (data_size != 0) {
            req->write_sgs =
                test_common::HSTestHelper::create_sgs(data_size, max_size_per_iov, req->jheader.data_pattern);
        }

        repl_dev()->async_alloc_write(req->header_blob(), req->key_blob(), req->write_sgs, req);
    }

    void validate_db_data() {
        g_helper->runner().set_num_tasks(inmem_db_.size());

        LOGINFO("[{}]: Total {} keys committed, validating them", boost::uuids::to_string(repl_dev()->group_id()),
                inmem_db_.size());
        auto it = inmem_db_.begin();
        g_helper->runner().set_task([this, &it]() {
            Key k;
            Value v;
            {
                std::unique_lock lk(db_mtx_);
                std::tie(k, v) = *it;
                ++it;
            }
            auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
            auto read_sgs = test_common::HSTestHelper::create_sgs(v.data_size_, block_size);

            repl_dev()->async_read(v.blkid_, read_sgs, v.data_size_).thenValue([read_sgs, k, v](auto const ec) {
                RELEASE_ASSERT(!ec, "Read of blkid={} for key={} error={}", v.blkid_.to_string(), k.id_, ec.message());
                for (auto const& iov : read_sgs.iovs) {
                    test_common::HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len,
                                                                 v.data_pattern_);
                    iomanager.iobuf_free(uintptr_cast(iov.iov_base));
                }
                g_helper->runner().next_task();
            });
        });
        g_helper->runner().execute().get();
    }

    uint64_t db_size() const {
        std::shared_lock lk(db_mtx_);
        return inmem_db_.size();
    }

private:
    std::map< Key, Value > inmem_db_;
    std::shared_mutex db_mtx_;
};

class RaftReplDevTest : public testing::Test {
public:
    void SetUp() override {
        // By default it will create one db
        auto db = std::make_shared< TestReplicatedDB >();
        g_helper->register_listener(db);
        dbs_.emplace_back(std::move(db));
    }

    void generate_writes(uint64_t data_size, uint32_t max_size_per_iov) {
        pick_one_db().db_write(data_size, max_size_per_iov);
    }

    void wait_for_all_writes(uint64_t exp_writes) {
        while (true) {
            uint64_t total_writes{0};
            for (auto const& db : dbs_) {
                total_writes += db->db_size();
            }

            if (total_writes >= exp_writes) { break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void validate_all_data() {
        for (auto const& db : dbs_) {
            db->validate_db_data();
        }
    }

    TestReplicatedDB& pick_one_db() { return *dbs_[0]; }

#ifdef _PRERELEASE
    void set_flip_point(const std::string flip_name) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(1);
        freq.set_percent(100);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        LOGDEBUG("Flip {} set", flip_name);
    }
#endif

private:
    std::vector< std::shared_ptr< TestReplicatedDB > > dbs_;
#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
#endif
};
#if 0
TEST_F(RaftReplDevTest, All_Append) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    if (g_helper->replica_num() == 0) {
        g_helper->sync_dataset_size(SISL_OPTIONS["num_io"].as< uint64_t >());
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_task([this, block_size]() { this->generate_writes(block_size, block_size); });
        g_helper->runner().execute().get();
    }

    this->wait_for_all_writes(g_helper->dataset_size());

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_all_data();

    g_helper->sync_for_cleanup_start();
}
#endif
TEST_F(RaftReplDevTest, All_Append_with_Fetch_Remote_Data) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    set_flip_point("simulate_fetch_remote_data");

    if (g_helper->replica_num() == 0) {
        g_helper->sync_dataset_size(SISL_OPTIONS["num_io"].as< uint64_t >());
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_task([this, block_size]() { this->generate_writes(block_size, block_size); });
        g_helper->runner().execute().get();
    }

    this->wait_for_all_writes(g_helper->dataset_size());

    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_all_data();

    g_helper->sync_for_cleanup_start();
}

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    char** orig_argv = argv;

    ::testing::InitGoogleTest(&parsed_argc, argv);
    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, test_raft_repl_dev, iomgr, test_common_setup, test_repl_common_setup);

    FLAGS_folly_global_cpu_executor_threads = 4;
    g_helper = std::make_unique< test_common::HSReplTestHelper >("test_raft_repl_dev", orig_argv);
    g_helper->setup();

    (g_helper->replica_num() == 0) ? ::testing::GTEST_FLAG(filter) = "*Primary_*:*All_*"
                                   : ::testing::GTEST_FLAG(filter) = "*Secondary_*::*All_*";

    auto ret = RUN_ALL_TESTS();
    g_helper->teardown();
    return ret;
}
