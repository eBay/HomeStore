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

#define private public
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
                   ::cxxopts::value< uint32_t >()->default_value("1"), "number"),
                  // for below replication parameter, their default value always get from dynamic config, only used
                  // when specified by user
                  (snapshot_distance, "", "snapshot_distance", "distance between snapshots",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "number"),
                  (num_raft_logs_resv, "", "num_raft_logs_resv", "number of raft logs reserved",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "number"),
                  (res_mgr_audit_timer_ms, "", "res_mgr_audit_timer_ms", "resource manager audit timer",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "number"));

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

        if (ctx->is_proposer()) { g_helper->runner().next_task(); }
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

    AsyncReplResult<> create_snapshot(repl_snapshot& s) override { return make_async_success<>(); }

    ReplResult< blk_alloc_hints > get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size) override {
        return blk_alloc_hints{};
    }

    void on_destroy() override {
        LOGINFOMOD(replication, "[Replica={}] Group={} is being destroyed", g_helper->replica_num(),
                   boost::uuids::to_string(repl_dev()->group_id()));
        g_helper->unregister_listener(repl_dev()->group_id());
    }

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

    void TearDown() override {
        for (auto const& db : dbs_) {
            run_on_leader(db, [this, db]() {
                auto err = hs()->repl_service().remove_repl_dev(db->repl_dev()->group_id()).get();
                ASSERT_EQ(err, ReplServiceError::OK) << "Error in destroying the group";
            });
        }

        for (auto const& db : dbs_) {
            auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
            do {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
                raft_repl_svc.gc_repl_devs();
                LOGINFO("Waiting for repl dev to get destroyed");
            } while (!repl_dev->is_destroyed());
        }
    }

    void generate_writes(uint64_t data_size, uint32_t max_size_per_iov, shared< TestReplicatedDB > db = nullptr) {
        if (db == nullptr) { db = pick_one_db(); }
        LOGINFO("Writing on group_id={}", db->repl_dev()->group_id());
        db->db_write(data_size, max_size_per_iov);
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

    shared< TestReplicatedDB > pick_one_db() { return dbs_[0]; }

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

    void run_on_leader(std::shared_ptr< TestReplicatedDB > db, auto&& lambda) {
        do {
            auto leader_uuid = db->repl_dev()->get_leader_id();

            if (leader_uuid.is_nil()) {
                LOGINFO("Waiting for leader to be elected");
                std::this_thread::sleep_for(std::chrono::milliseconds{500});
            } else if (leader_uuid == g_helper->my_replica_id()) {
                lambda();
                break;
            } else {
                break;
            }
        } while (true);
    }

    void write_on_leader(uint32_t num_entries, bool wait_for_commit = true, shared< TestReplicatedDB > db = nullptr) {
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
                g_helper->runner().set_task([this, block_size, db]() {
                    static std::normal_distribution<> num_blks_gen{3.0, 2.0};
                    this->generate_writes(std::abs(std::round(num_blks_gen(g_re))) * block_size, block_size, db);
                });
                if (wait_for_commit) { g_helper->runner().execute().get(); }
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

    void remove_db(std::shared_ptr< TestReplicatedDB > db, bool wait_for_removal) {
        this->run_on_leader(db, [this, db]() {
            auto err = hs()->repl_service().remove_repl_dev(db->repl_dev()->group_id()).get();
            ASSERT_EQ(err, ReplServiceError::OK) << "Error in destroying the group";
        });

        // Remove the db from the dbs_ list and check if count matches with repl_device
        for (auto it = dbs_.begin(); it != dbs_.end(); ++it) {
            if (*it == db) {
                dbs_.erase(it);
                break;
            }
        }

        if (wait_for_removal) { wait_for_listener_destroy(dbs_.size()); }
    }

    void wait_for_listener_destroy(uint64_t exp_listeners) {
        while (true) {
            auto total_listeners = g_helper->num_listeners();
            if (total_listeners == exp_listeners) { break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
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

protected:
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
        g_helper->set_basic_flip("drop_push_data_request");
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
        g_helper->set_basic_flip("fake_reject_append_data_channel", 5, 10);
        g_helper->set_basic_flip("fake_reject_append_raft_channel", 10, 100);
        g_helper->set_delay_flip("slow_down_data_channel", 10000ull, 10, 10);
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
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Step 2: Restart replica-0 (Leader) with a very long delay so that it is lagging behind
    LOGINFO("Restart leader");
    this->restart_replica(0, 15 /* shutdown_delay_sec */);
    std::this_thread::sleep_for(std::chrono::seconds(3));

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
        test_common::HSTestHelper::set_basic_flip("fake_drop_append_raft_channel", 2, 75);
    }

    uint64_t exp_entries = SISL_OPTIONS["num_io"].as< uint64_t >();
    if (g_helper->replica_num() == 0) { this->write_on_leader(); }
    LOGINFO(
        "Even after drop on replica=2, lets validate that data written is synced on all members (after retry to 2)");
    this->wait_for_all_commits();

    if (g_helper->replica_num() == 2) {
        LOGINFO("Set flip to fake drop append entries in raft channel of replica=2 again");
        test_common::HSTestHelper::set_basic_flip("fake_drop_append_raft_channel", 1, 100);
    } else {
        g_helper->sync_dataset_size(1);
        if (g_helper->replica_num() == 0) { this->write_on_leader(); }

        exp_entries += 1;
        this->wait_for_all_commits();
    }
}
#endif

//
// This test case should be run in long running mode to see the effect of snapshot and compaction
// Example:
// ./bin/test_raft_repl_dev --gtest_filter=*Snapshot_and_Compact* --log_mods replication:debug --num_io=999999
// --snapshot_distance=200 --num_raft_logs_resv=20000 --res_mgr_audit_timer_ms=120000
//
TEST_F(RaftReplDevTest, Snapshot_and_Compact) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit on all replicas */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}

TEST_F(RaftReplDevTest, RemoveReplDev) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());

    // Step 1: Create 2 more repldevs
    LOGINFO("Create 2 more ReplDevs");
    for (uint32_t i{0}; i < 2; ++i) {
        auto db = std::make_shared< TestReplicatedDB >();
        g_helper->register_listener(db);
        this->dbs_.emplace_back(std::move(db));
    }
    g_helper->sync_for_test_start();

    // Step 2: While IO is ongoing, we remove one of the repl_dev
    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    LOGINFO("Inserting {} entries on the leader and concurrently remove that repl_dev while IO is ongoing",
            entries_per_attempt);
    this->write_on_leader(entries_per_attempt, false /* wait for commit on all */, dbs_.back());
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    this->remove_db(dbs_.back(), true /* wait_for_removal */);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Step 3: Shutdown one of the follower and remove another repl_dev, once the follower is up, it should remove the
    // repl_dev and proceed
    LOGINFO("Shutdown one of the followers (replica=1) and then remove dbs on other members. Expect replica=1 to "
            "remove after it is up");
    this->restart_replica(1, 15 /* shutdown_delay_sec */);
    LOGINFO("After restart replica 1 {}", dbs_.size());
    this->remove_db(dbs_.back(), true /* wait_for_removal */);
    LOGINFO("Remove last db {}", dbs_.size());
    // TODO: Once generic crash flip/test_infra is available, use flip to crash during removal and restart them to see
    // if records are being removed
    g_helper->sync_for_cleanup_start();
}

#ifdef _PRERELEASE
// Garbage collect the replication requests
// 0. Simulate data push is dropped so that fetch data can be triggered (if both data and raft channel received, we
// won't have timeout rreqs).
TEST_F(RaftReplDevTest, GCReplReqs) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    uint32_t prev_timeout_sec{0};
    LOGINFO("Set the repl_req_timout_sec to be fairly small to force GC to kick in");
    HS_SETTINGS_FACTORY().modifiable_settings([&prev_timeout_sec](auto& s) {
        prev_timeout_sec = s.consensus.repl_req_timeout_sec;
        s.consensus.repl_req_timeout_sec = 5;
    });
    HS_SETTINGS_FACTORY().save();

    if (g_helper->replica_num() != 0) {
        LOGINFO("Set flip to fake fetch data request on data channel");
        set_basic_flip("drop_push_data_request");
    }

    this->write_on_leader(100 /* num_entries */, true /* wait_for_commit */);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Step 2: Restart replica-0 (Leader)
    this->restart_replica(0, 10);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    LOGINFO("After original leader is shutdown, insert more entries into the new leader");
    this->write_on_leader(100, true /* wait for commit on all replicas */);

    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();

    // step-5: Set the settings back and save. This is needed (if we ever give a --config in the test)
    LOGINFO("Set the repl_req_timeout back to previous value={}", prev_timeout_sec);
    HS_SETTINGS_FACTORY().modifiable_settings(
        [prev_timeout_sec](auto& s) { s.consensus.repl_req_timeout_sec = prev_timeout_sec; });
    HS_SETTINGS_FACTORY().save();

    g_helper->sync_for_cleanup_start();
}
#endif

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

    //
    // Entire test suite assumes that once a replica takes over as leader, it stays until it is explicitly yielded.
    // Otherwise it is very hard to control or accurately test behavior. Hence we forcibly override the
    // leadership_expiry time.
    //
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.consensus.leadership_expiry_ms = -1; // -1 means never expires;
        s.generic.repl_dev_cleanup_interval_sec = 0;

        // only reset when user specified the value for test;
        if (SISL_OPTIONS.count("snapshot_distance")) {
            s.consensus.snapshot_freq_distance = SISL_OPTIONS["snapshot_distance"].as< uint32_t >();
        }
        if (SISL_OPTIONS.count("num_raft_logs_resv")) {
            s.resource_limits.raft_logstore_reserve_threshold = SISL_OPTIONS["num_raft_logs_resv"].as< uint32_t >();
        }
        if (SISL_OPTIONS.count("res_mgr_audit_timer_ms")) {
            s.resource_limits.resource_audit_timer_ms = SISL_OPTIONS["res_mgr_audit_timer_ms"].as< uint32_t >();
        }
    });
    HS_SETTINGS_FACTORY().save();

    FLAGS_folly_global_cpu_executor_threads = 4;
    g_helper = std::make_unique< test_common::HSReplTestHelper >("test_raft_repl_dev", args, orig_argv);
    g_helper->setup();

    auto ret = RUN_ALL_TESTS();
    g_helper->teardown();

    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);

    return ret;
}
