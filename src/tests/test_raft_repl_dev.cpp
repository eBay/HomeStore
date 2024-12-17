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
#include "test_common/raft_repl_test_base.hpp"

class RaftReplDevTest : public RaftReplDevTestBase {};
TEST_F(RaftReplDevTest, Write_Duplicated_Data) {
    uint64_t total_writes = 1;
    g_helper->runner().qdepth_ = total_writes;
    g_helper->runner().total_tasks_ = total_writes;
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();
    auto leader_uuid = wait_and_get_leader_id();

    uint64_t id;
    TestReplicatedDB::Key stored_key;
    TestReplicatedDB::Value stored_val;
    if (leader_uuid == g_helper->my_replica_id()) {
        id = (uint64_t)rand() << 32 | rand();
        LOGINFO("going to write data with id={}", id);
        this->write_with_id(id, true /* wait_for_commit */);
        stored_key = dbs_[0]->inmem_db_.cbegin()->first;
        ASSERT_EQ(id, stored_key.id_);
    } else {
        LOGINFO("I am not leader, leader_uuid={} my_uuid={}, do nothing",
                boost::uuids::to_string(leader_uuid), boost::uuids::to_string(g_helper->my_replica_id()));
    }
    wait_for_commits(total_writes);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    /* test duplication
    if duplication found in leader proposal, reject it;
    if duplication found in the followers, skip it.
    */
    //1. write the same data again on leader, should fail
    if (leader_uuid == g_helper->my_replica_id()) {
        auto err = this->write_with_id(id, true /* wait_for_commit */);
        ASSERT_EQ(ReplServiceError::DATA_DUPLICATED, err);

        //2. delete it from the db to simulate duplication in followers(skip the duplication check in leader side)
        dbs_[0]->inmem_db_.erase(stored_key);
        LOGINFO("data with id={} has been deleted from db", id);
        err = this->write_with_id(id, true /* wait_for_commit */);
        ASSERT_EQ(ReplServiceError::OK, err);
    }
    if (leader_uuid != g_helper->my_replica_id()) {
        wait_for_commits(total_writes + 1);
        ASSERT_EQ(dbs_[0]->inmem_db_.size(), total_writes);
    }

    g_helper->sync_for_cleanup_start();
}

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

#if 0

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

#if 0
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
    LOGINFO("After remove db replica={} num_db={}", g_helper->replica_num(), dbs_.size());

    // Step 3: Shutdown one of the follower and remove another repl_dev, once the follower is up, it should remove the
    // repl_dev and proceed
    LOGINFO("Shutdown one of the followers (replica=1) and then remove dbs on other members. Expect replica=1 to "
            "remove after it is up");
    this->restart_replica(1, 15 /* shutdown_delay_sec */);
    LOGINFO("After restart replica={} num_db={}", g_helper->replica_num(), dbs_.size());

    // Since leader and follower 2 left the cluster, follower 1 is the only member in the raft group and need atleast
    // 2 members to start leader election. In this case follower 1 can't be removed and goes to zombie state for this
    // repl dev.
    if (g_helper->replica_num() == 1) {
        // Skip deleting this group during teardown.
        LOGINFO("Set zombie on group={}", dbs_.back()->repl_dev()->group_id());
        dbs_.back()->set_zombie();
    } else {
        this->remove_db(dbs_.back(), true /* wait_for_removal */);
        LOGINFO("Remove last replica={} num_db={}", g_helper->replica_num(), dbs_.size());
    }

    if (g_helper->replica_num() == 0) {
        // Leader sleeps here because follower-1 needs some time to find the leader after restart.
        std::this_thread::sleep_for(std::chrono::seconds(20));
    }

    // TODO: Once generic crash flip/test_infra is available, use flip to crash during removal and restart them to
    // see if records are being removed
    g_helper->sync_for_cleanup_start();
}
#endif

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
        g_helper->set_basic_flip("drop_push_data_request");
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

TEST_F(RaftReplDevTest, BaselineTest) {
    // Testing the baseline resync where leader creates snapshot and truncate entries.
    // To simulate that write 50 entries to leader. Shutdown follower 1.
    // Write to leader again to create num_io entries which follower 1 doesnt have.
    // This is the baseline data. Truncate and snapshot on leader. Wait for commit for leader
    // and follower 2. Write to leader again 50 entries after snapshot to create entries
    // for incremental resync. We can create snapshot manually or triggered by raft.
    // Verify all nodes got entries.
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // Write some entries on leader.
    uint64_t entries_per_attempt = 50;

    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    // Shutdown replica 1.
    LOGINFO("Shutdown replica 1");
    this->shutdown_replica(1);

    // Write lot of entries on leader.
    entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    if (g_helper->replica_num() == 0 || g_helper->replica_num() == 2) {
        this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

        // Wait for commmit on leader and follower 2
        this->wait_for_all_commits();
        LOGINFO("Got all commits for replica 0 and 2");

        if (g_helper->replica_num() == 0) {
            // Leader does manual snapshot and truncate
            LOGINFO("Leader create snapshot and truncate");
            this->create_snapshot();
            this->truncate(0);
        }
    }

    // Wait till all writes are down and snapshot is created.
    g_helper->sync_for_verify_start();

    // Start replica 1 after this.
    LOGINFO("Start replica 1");
    this->start_replica(1);
    g_helper->sync_for_test_start();

    // Write on leader to have some entries for increment resync.
    entries_per_attempt = 50;
    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);
    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
    LOGINFO("BaselineTest done");
}

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
        s.generic.repl_dev_cleanup_interval_sec = 1;

        // Disable implicit flush and timer.
        s.logstore.flush_threshold_size = 0;
        s.logstore.flush_timer_frequency_us = 0;

        // Snapshot and truncation tests needs num reserved to be 0 and distance 10.
        s.consensus.num_reserved_log_items = 0;
        s.resource_limits.resource_audit_timer_ms = 0;

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
    // No spare replica's are created. Test cases in this file expects fixed number of replica's.
    g_helper->setup(SISL_OPTIONS["replicas"].as< uint32_t >());

    auto ret = RUN_ALL_TESTS();
    g_helper->teardown();

    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);

    return ret;
}
