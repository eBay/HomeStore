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
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS, nuraft_mesg)

SISL_OPTION_GROUP(test_raft_repl_dev,
                  (block_size, "", "block_size", "block size to io",
                   ::cxxopts::value< uint32_t >()->default_value("4096"), "number"),
                  (num_raft_groups, "", "num_raft_groups", "number of raft groups per test",
                   ::cxxopts::value< uint32_t >()->default_value("1"), "number"));

SISL_OPTIONS_ENABLE(logging, test_raft_repl_dev, iomgr, config, test_common_setup, test_repl_common_setup)

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
        ASSERT_EQ(header.size(), sizeof(test_req::journal_header));

        auto jheader = r_cast< test_req::journal_header const* >(header.cbytes());
        Key k{.id_ = *(r_cast< uint64_t const* >(key.cbytes()))};
        Value v{
            .lsn_ = lsn, .data_size_ = jheader->data_size, .data_pattern_ = jheader->data_pattern, .blkid_ = blkids};

        LOGINFO("[Replica={}] Received commit on lsn={} key={} value[blkid={} pattern={}]", g_helper->replica_num(),
                lsn, k.id_, v.blkid_.to_string(), v.data_pattern_);

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

    void on_error(ReplServiceError error, const sisl::blob& header, const sisl::blob& key,
                  cintrusive< repl_req_ctx >& ctx) override {
        LOGINFO("[Replica={}] Received error={} on key={}", g_helper->replica_num(), enum_name(error),
                *(r_cast< uint64_t const* >(key.cbytes())));
    }

    blk_alloc_hints get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) override {
        return blk_alloc_hints{};
    }

    void on_replica_stop() override {}

    void db_write(uint64_t data_size, uint32_t max_size_per_iov) {
        static std::atomic< uint32_t > s_uniq_num{0};
        auto req = intrusive< test_req >(new test_req());
        req->jheader.data_size = data_size;
        req->jheader.data_pattern = ((long long)rand() << 32) | ++s_uniq_num;
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
                LOGINFO("Validated successfully key={} value[blkid={} pattern={}]", k.id_, v.blkid_.to_string(),
                        v.data_pattern_);
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
        for (uint32_t i{0}; i < SISL_OPTIONS["num_raft_groups"].as< uint32_t >(); ++i) {
            auto db = std::make_shared< TestReplicatedDB >();
            g_helper->register_listener(db);
            dbs_.emplace_back(std::move(db));
        }
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

    void switch_all_db_leader() {
        for (auto const& db : dbs_) {
            do {
                auto result = db->repl_dev()->become_leader().get();
                if (result.hasError()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                } else {
                    break;
                }
            } while (true);
        }
    }

private:
    std::vector< std::shared_ptr< TestReplicatedDB > > dbs_;
#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
#endif
};

TEST_F(RaftReplDevTest, All_Append_Restart_Append) {

    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    uint64_t exp_entries = SISL_OPTIONS["num_io"].as< uint64_t >();
    if (g_helper->replica_num() == 0) {
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_task([this, block_size]() { this->generate_writes(block_size, block_size); });
        g_helper->runner().execute().get();
    }
    this->wait_for_all_writes(exp_entries);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_all_data();
    g_helper->sync_for_cleanup_start();

    LOGINFO("Restart all the homestore replicas");
    g_helper->restart();
    g_helper->sync_for_test_start();

    exp_entries += SISL_OPTIONS["num_io"].as< uint64_t >();
    if (g_helper->replica_num() == 0) {
        LOGINFO("Switch the leader to replica_num = 0");
        this->switch_all_db_leader();

        LOGINFO("Post restart write the data again");
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        g_helper->runner().set_task([this, block_size]() { this->generate_writes(block_size, block_size); });
        g_helper->runner().execute().get();
    }
    this->wait_for_all_writes(exp_entries);

    LOGINFO("Validate all data written (including pre-restart data) by reading them");
    this->validate_all_data();
    g_helper->sync_for_cleanup_start();
}

TEST_F(RaftReplDevTest, All_Append_Fetch_Remote_Data) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

#ifdef _PRERELEASE
    set_flip_point("simulate_fetch_remote_data");
#endif

    if (g_helper->replica_num() == 0) {
        // g_helper->sync_dataset_size(SISL_OPTIONS["num_io"].as< uint64_t >());
        g_helper->sync_dataset_size(100);
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_task([this, block_size]() {
            this->generate_writes(block_size /* data_size */, block_size /* max_size_per_iov */);
        });
        g_helper->runner().execute().get();
    }

    this->wait_for_all_writes(g_helper->dataset_size());

    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_all_data();

    g_helper->sync_for_cleanup_start();
}

// do some io before restart;
TEST_F(RaftReplDevTest, All_restart_one_follower_inc_resync) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // step-0: do some IO before restart one member;
    uint64_t exp_entries = 20;
    if (g_helper->replica_num() == 0) {
        g_helper->runner().set_num_tasks(20);
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_task([this, block_size]() {
            this->generate_writes(block_size /* data_size */, block_size /* max_size_per_iov */);
        });
        g_helper->runner().execute().get();
    }

    // step-1: wait for all writes to be completed
    this->wait_for_all_writes(exp_entries);

    // step-2: restart one non-leader replica
    if (g_helper->replica_num() == 1) {
        LOGINFO("Restart homestore: replica_num = 1");
        g_helper->restart();
        g_helper->sync_for_test_start();
    }

    exp_entries += SISL_OPTIONS["num_io"].as< uint64_t >();
    // step-3: on leader, wait for a while for replica-1 to finish shutdown so that it can be removed from raft-groups
    // and following I/O issued by leader won't be pushed to relica-1;
    if (g_helper->replica_num() == 0) {
        LOGINFO("Wait for grpc connection to replica-1 to expire and removed from raft-groups.");
        std::this_thread::sleep_for(std::chrono::seconds{5});

        g_helper->runner().set_num_tasks(SISL_OPTIONS["num_io"].as< uint64_t >());

        // before replica-1 started, issue I/O so that replica-1 is lagging behind;
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_task([this, block_size]() {
            this->generate_writes(block_size /* data_size */, block_size /* max_size_per_iov */);
        });
        g_helper->runner().execute().get();
    }

    this->wait_for_all_writes(exp_entries);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_all_data();
    g_helper->sync_for_cleanup_start();
}

// TODO
// double restart:
// 1. restart one follower(F1) while I/O keep running.
// 2. after F1 reboots and leader is resyncing with F1 (after sending the appended entries), this leader also retarts.
// 3. F1 should receive error from grpc saying originator not there.
// 4. F2 should be appending entries to F1 and F1 should be able to catch up with F2 (fetch data from F2).
//

int main(int argc, char* argv[]) {
    int parsed_argc{argc};
    char** orig_argv = argv;

    ::testing::InitGoogleTest(&parsed_argc, argv);

    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, config, test_raft_repl_dev, iomgr, test_common_setup,
                      test_repl_common_setup);

    FLAGS_folly_global_cpu_executor_threads = 4;
    g_helper = std::make_unique< test_common::HSReplTestHelper >("test_raft_repl_dev", orig_argv);
    g_helper->setup();

    (g_helper->replica_num() == 0) ? ::testing::GTEST_FLAG(filter) = "*Primary_*:*All_*"
                                   : ::testing::GTEST_FLAG(filter) = "*Secondary_*::*All_*";

    auto ret = RUN_ALL_TESTS();
    g_helper->teardown();
    return ret;
}
