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
#include <boost/uuid/nil_generator.hpp>

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
static std::random_device g_rd{};
static std::default_random_engine g_re{g_rd()};

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

        m_num_commits.fetch_add(1, std::memory_order_relaxed);

        ASSERT_EQ(header.size(), sizeof(test_req::journal_header));

        auto jheader = r_cast< test_req::journal_header const* >(header.cbytes());
        Key k{.id_ = *(r_cast< uint64_t const* >(key.cbytes()))};
        Value v{
            .lsn_ = lsn, .data_size_ = jheader->data_size, .data_pattern_ = jheader->data_pattern, .blkid_ = blkids};

        LOGINFOMOD(replication, "[Replica={}] Received commit on lsn={} dsn={} key={} value[blkid={} pattern={}]",
                   g_helper->replica_num(), lsn, ctx->dsn(), k.id_, v.blkid_.to_string(), v.data_pattern_);

        {
            std::unique_lock lk(db_mtx_);
            inmem_db_.insert_or_assign(k, v);
            ++commit_count_;
        }

        if (ctx->is_proposer) { g_helper->runner().next_task(); }
    }

    bool on_pre_commit(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                       cintrusive< repl_req_ctx >& ctx) override {
        LOGINFOMOD(replication, "[Replica={}] Received pre-commit on lsn={} dsn={}", g_helper->replica_num(), lsn,
                   ctx->dsn());
        return true;
    }

    void on_rollback(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                     cintrusive< repl_req_ctx >& ctx) override {
        LOGINFOMOD(replication, "[Replica={}] Received rollback on lsn={}", g_helper->replica_num(), lsn);
    }

    void on_error(ReplServiceError error, const sisl::blob& header, const sisl::blob& key,
                  cintrusive< repl_req_ctx >& ctx) override {
        LOGINFOMOD(replication, "[Replica={}] Received error={} on key={}", g_helper->replica_num(), enum_name(error),
                   *(r_cast< uint64_t const* >(key.cbytes())));
    }

    ReplResult< blk_alloc_hints > get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) override {
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

        LOGINFOMOD(replication, "[{}]: Total {} keys committed, validating them",
                   boost::uuids::to_string(repl_dev()->group_id()), inmem_db_.size());
        auto it = inmem_db_.begin();
        g_helper->runner().set_task([this, &it]() {
            Key k;
            Value v;
            {
                std::unique_lock lk(db_mtx_);
                std::tie(k, v) = *it;
                ++it;
            }

            if (v.data_size_ != 0) {
                auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
                auto read_sgs = test_common::HSTestHelper::create_sgs(v.data_size_, block_size);

                repl_dev()->async_read(v.blkid_, read_sgs, v.data_size_).thenValue([read_sgs, k, v](auto const ec) {
                    LOGINFOMOD(replication, "Validating key={} value[blkid={} pattern={}]", k.id_, v.blkid_.to_string(),
                               v.data_pattern_);
                    RELEASE_ASSERT(!ec, "Read of blkid={} for key={} error={}", v.blkid_.to_string(), k.id_,
                                   ec.message());
                    for (auto const& iov : read_sgs.iovs) {
                        test_common::HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len,
                                                                     v.data_pattern_);
                        iomanager.iobuf_free(uintptr_cast(iov.iov_base));
                    }
                    g_helper->runner().next_task();
                });
            } else {
                g_helper->runner().next_task();
            }
        });
        g_helper->runner().execute().get();
    }

    uint64_t db_commit_count() const {
        std::shared_lock lk(db_mtx_);
        return commit_count_;
    }

    uint64_t db_size() const {
        std::shared_lock lk(db_mtx_);
        return inmem_db_.size();
    }

private:
    std::map< Key, Value > inmem_db_;
    uint64_t commit_count_{0};
    std::shared_mutex db_mtx_;
    std::atomic< uint64_t > m_num_commits;
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

    void wait_for_all_commits() { wait_for_commits(written_entries_); }

    void wait_for_commits(uint64_t exp_writes) {
        uint64_t total_writes{0};
        while (true) {
            total_writes = 0;
            for (auto const& db : dbs_) {
                total_writes += db->db_commit_count();
            }

            if (total_writes >= exp_writes) { break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        LOGINFO("Replica={} has received {} commits as expected", g_helper->replica_num(), total_writes);
    }

    void validate_data() {
        for (auto const& db : dbs_) {
            db->validate_db_data();
        }
    }

    TestReplicatedDB& pick_one_db() { return *dbs_[0]; }

#ifdef _PRERELEASE
    void set_basic_flip(const std::string flip_name, uint32_t count = 1, uint32_t percent = 100) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        m_fc.inject_noreturn_flip(flip_name, {null_cond}, freq);
        LOGDEBUG("Flip {} set", flip_name);
    }

    void set_delay_flip(const std::string flip_name, uint64_t delay_usec, uint32_t count = 1, uint32_t percent = 100) {
        flip::FlipCondition null_cond;
        flip::FlipFrequency freq;
        freq.set_count(count);
        freq.set_percent(percent);
        m_fc.inject_delay_flip(flip_name, {null_cond}, freq, delay_usec);
        LOGDEBUG("Flip {} set", flip_name);
    }
#endif

    void assign_leader(uint16_t replica) {
        LOGINFO("Switch the leader to replica_num = {}", replica);
        if (g_helper->replica_num() == replica) {
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
        } else {
            for (auto const& db : dbs_) {
                homestore::replica_id_t leader_uuid;
                while (true) {
                    leader_uuid = db->repl_dev()->get_leader_id();
                    if (!leader_uuid.is_nil() && (g_helper->member_id(leader_uuid) == replica)) { break; }

                    LOGINFO("Waiting for replica={} to become leader", replica);
                    std::this_thread::sleep_for(std::chrono::milliseconds{500});
                }
            }
        }
    }

    void write_on_leader(uint32_t num_entries, bool wait_for_commit = true) {
        do {
            auto leader_uuid = dbs_[0]->repl_dev()->get_leader_id();

            if (leader_uuid.is_nil()) {
                LOGINFO("Waiting for leader to be elected");
                std::this_thread::sleep_for(std::chrono::milliseconds{500});
            } else if (leader_uuid == g_helper->my_replica_id()) {
                LOGINFO("Writing {} entries since I am the leader my_uuid={}", num_entries,
                        boost::uuids::to_string(g_helper->my_replica_id()));
                auto const block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
                g_helper->runner().set_num_tasks(num_entries);

                LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
                g_helper->runner().set_task([this, block_size]() {
                    static std::normal_distribution<> num_blks_gen{3.0, 2.0};
                    this->generate_writes(std::abs(std::round(num_blks_gen(g_re))) * block_size, block_size);
                });
                g_helper->runner().execute().get();
                break;
            } else {
                LOGINFO("{} entries were written on the leader_uuid={} my_uuid={}", num_entries,
                        boost::uuids::to_string(leader_uuid), boost::uuids::to_string(g_helper->my_replica_id()));
                break;
            }
        } while (true);

        written_entries_ += num_entries;
        if (wait_for_commit) { this->wait_for_all_commits(); }
    }

    void restart_replica(uint16_t replica, uint32_t shutdown_delay_sec = 5u) {
        if (g_helper->replica_num() == replica) {
            LOGINFO("Restart homestore: replica_num = {}", replica);
            g_helper->restart(shutdown_delay_sec);
            // g_helper->sync_for_test_start();
        } else {
            LOGINFO("Wait for replica={} to completely go down and removed from alive raft-groups", replica);
            std::this_thread::sleep_for(std::chrono::seconds{5});
        }
    }

private:
    std::vector< std::shared_ptr< TestReplicatedDB > > dbs_;
    uint32_t written_entries_{0};

#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
#endif
};

TEST_F(RaftReplDevTest, Write_Restart_Write) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();

    LOGINFO("Restart all the homestore replicas");
    g_helper->restart();
    g_helper->sync_for_test_start();

    // Reassign the leader to replica 0, in case restart switched leaders
    this->assign_leader(0);

    LOGINFO("Post restart write the data again on the leader");
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    LOGINFO("Validate all data written (including pre-restart data) by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}

#ifdef _PRERELEASE
TEST_F(RaftReplDevTest, Follower_Fetch_OnActive_ReplicaGroup) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    if (g_helper->replica_num() != 0) {
        LOGINFO("Set flip to fake fetch data request on data channel");
        set_basic_flip("drop_push_data_request");
    }
    this->write_on_leader(100, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();

    g_helper->sync_for_cleanup_start();
}
#endif

// do some io before restart;
TEST_F(RaftReplDevTest, Follower_Incremental_Resync) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // step-0: do some IO before restart one member and wait for all writes to be completed
    this->write_on_leader(20, true /* wait for commit on all */);

    // step-1: Modify the settings to force multiple fetch batches
    uint32_t prev_max{2 * 1024 * 1024};

    LOGINFO("Set the max fetch to be fairly small to force multiple batches")
    HS_SETTINGS_FACTORY().modifiable_settings([&prev_max](auto& s) {
        prev_max = s.consensus.data_fetch_max_size_kb;
        s.consensus.data_fetch_max_size_kb = SISL_OPTIONS["block_size"].as< uint32_t >() * 2; // Make it max 2 blocks
    });
    HS_SETTINGS_FACTORY().save();

    // step-2: restart one non-leader replica
    this->restart_replica(1, 10 /* shutdown_delay_sec */);

    // step-3 before replica-1 started, issue I/O so that replica-1 is lagging behind and get resynced
    this->write_on_leader(SISL_OPTIONS["num_io"].as< uint64_t >(), true /* wait for commit on all*/);

    // step-4 validate for all the data writes
    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();

    // step-5: Set the settings back and save. This is needed (if we ever give a --config in the test)
    LOGINFO("Set the max fetch back to previous value={}", prev_max);
    HS_SETTINGS_FACTORY().modifiable_settings([prev_max](auto& s) {
        s.consensus.data_fetch_max_size_kb = prev_max; //
    });
    HS_SETTINGS_FACTORY().save();

    g_helper->sync_for_cleanup_start();
}

#ifdef _PRERELEASE
TEST_F(RaftReplDevTest, Follower_Reject_Append) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    if (g_helper->replica_num() != 0) {
        LOGINFO("Set flip to fake reject append entries in both data and raft channels. We slow down data channel "
                "occassionally so that raft channel reject can be hit");
        set_basic_flip("fake_reject_append_data_channel", 5, 10);
        set_basic_flip("fake_reject_append_raft_channel", 10, 100);
        set_delay_flip("slow_down_data_channel", 10000ull, 10, 10);
    }

    LOGINFO("Write to leader and then wait for all the commits on all replica despite drop/slow_down");
    this->write_on_leader(SISL_OPTIONS["num_io"].as< uint64_t >(), true /* wait_for_all_commits */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}
#endif

TEST_F(RaftReplDevTest, Resync_From_Non_Originator) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // Step 1: Fill up entries on all replicas
    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    this->write_on_leader(entries_per_attempt, true /* wait for commit on all */);

    // Step 2: Restart replica-2 (follower) with a very long delay so that it is lagging behind
    this->restart_replica(2, 10 /* shutdown_delay_sec */);

    // Step 3: While one follower is down, insert more entries on remaining replicas
    LOGINFO("After one follower is shutdown, insert more entries");
    this->write_on_leader(entries_per_attempt, true /* no need to wait for commit */);

    // Step 4: Switch to a new leader (replica-1)  and then add more entries
    LOGINFO("Switch to a new leader and insert more entries");
    this->assign_leader(1); // Assign replica-1 as new leader
    this->write_on_leader(entries_per_attempt, true /* no need to wait for commit */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}

TEST_F(RaftReplDevTest, Leader_Restart) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // Step 1: Fill up entries on all replicas
    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    this->write_on_leader(entries_per_attempt, true /* wait for commit on all replicas */);

    // Step 2: Restart replica-0 (Leader) with a very long delay so that it is lagging behind
    this->restart_replica(0, 10 /* shutdown_delay_sec */);

    // Step 3: While the original leader is down, write entries into the new leader
    LOGINFO("After original leader is shutdown, insert more entries into the new leader");
    this->write_on_leader(entries_per_attempt, true /* wait for commit on all replicas */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}

#if 0
TEST_F(RaftReplDevTest, Drop_Raft_Entry_Switch_Leader) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    LOGINFO("Aim of this test is to drop raft entry and ensure that they are retried. In addition, we drop raft entry  "
            "and we also switch leader to ensure that the dropped entry is retried by the new leader");

    if (g_helper->replica_num() == 2) {
        LOGINFO("Set flip to fake drop append entries in raft channel of replica=2");
        set_basic_flip("fake_drop_append_raft_channel", 2, 75);
    }

    uint64_t exp_entries = SISL_OPTIONS["num_io"].as< uint64_t >();
    if (g_helper->replica_num() == 0) { this->write_on_leader(); }
    LOGINFO(
        "Even after drop on replica=2, lets validate that data written is synced on all members (after retry to 2)");
    this->wait_for_all_commits();

    if (g_helper->replica_num() == 2) {
        LOGINFO("Set flip to fake drop append entries in raft channel of replica=2 again");
        set_basic_flip("fake_drop_append_raft_channel", 1, 100);
    } else {
        g_helper->sync_dataset_size(1);
        if (g_helper->replica_num() == 0) { this->write_on_leader(); }

        exp_entries += 1;
        this->wait_for_all_commits();
    }
}
#endif

// TODO
// double restart:
// 1. restart one follower(F1) while I/O keep running.
// 2. after F1 reboots and leader is resyncing with F1 (after sending the appended entries), this leader also retarts.
// 3. F1 should receive error from grpc saying originator not there.
// 4. F2 should be appending entries to F1 and F1 should be able to catch up with F2 (fetch data from F2).
//

int main(int argc, char* argv[]) {
    int parsed_argc = argc;
    char** orig_argv = argv;

    // Save the args for replica use
    std::vector< std::string > args;
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    ::testing::InitGoogleTest(&parsed_argc, argv);

    SISL_OPTIONS_LOAD(parsed_argc, argv, logging, config, test_raft_repl_dev, iomgr, test_common_setup,
                      test_repl_common_setup);

    // Entire test suite assumes that once a replica takes over as leader, it stays until it is explicitly yielded.
    // Otherwise it is very hard to control or accurately test behavior. Hence we forcibly override the
    // leadership_expiry time.
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) { s.consensus.leadership_expiry_ms = -1; });
    HS_SETTINGS_FACTORY().save();

    FLAGS_folly_global_cpu_executor_threads = 4;
    g_helper = std::make_unique< test_common::HSReplTestHelper >("test_raft_repl_dev", args, orig_argv);
    g_helper->setup();

#if 0
    (g_helper->replica_num() == 0) ? ::testing::GTEST_FLAG(filter) = "*Primary_*:*All_*"
                                   : ::testing::GTEST_FLAG(filter) = "*Secondary_*::*All_*";
#endif

    auto ret = RUN_ALL_TESTS();
    g_helper->teardown();
    return ret;
}
