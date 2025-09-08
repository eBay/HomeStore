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
        LOGINFO("I am not leader, leader_uuid={} my_uuid={}, do nothing", boost::uuids::to_string(leader_uuid),
                boost::uuids::to_string(g_helper->my_replica_id()));
    }
    wait_for_commits(total_writes);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    /* test duplication
    if duplication found in leader proposal, reject it;
    if duplication found in the followers, skip it.
    */
    // 1. write the same data again on leader, should fail
    if (leader_uuid == g_helper->my_replica_id()) {
        auto err = this->write_with_id(id, true /* wait_for_commit */);
        ASSERT_EQ(ReplServiceError::DATA_DUPLICATED, err);

        // 2. delete it from the db to simulate duplication in followers(skip the duplication check in leader side)
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

TEST_F(RaftReplDevTest, Write_With_Diabled_Leader_Push_Data) {
    g_helper->set_basic_flip("disable_leader_push_data", std::numeric_limits< int >::max(), 100);
    LOGINFO("Homestore replica={} setup completed, all the push_data from leader are disabled",
            g_helper->replica_num());
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    this->write_on_leader(20, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();

    g_helper->sync_for_cleanup_start();
    g_helper->remove_flip("disable_leader_push_data");
}

TEST_F(RaftReplDevTest, Write_With_Handling_No_Space_Left) {
    g_helper->set_basic_flip("simulate_no_space_left", std::numeric_limits< int >::max(), 50);
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    this->write_on_leader(20, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();

    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();

    g_helper->sync_for_cleanup_start();
    g_helper->remove_flip("simulate_no_space_left");
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
            // this->truncate(0);
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

TEST_F(RaftReplDevTest, LargeDataWrite) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // TODO: Increase the data size (e.g., to 16MB) for testing.
    // For now, use 4MB to ensure the test passes since there are issues with larger IO sizes on the uring drive.
    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    uint64_t data_size = 4 * 1024 * 1024;
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */, nullptr, &data_size);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}

TEST_F(RaftReplDevTest, PriorityLeaderElection) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();
    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    if (g_helper->replica_num() == 0) {
        auto leader = this->wait_and_get_leader_id();
        ASSERT_EQ(leader, g_helper->my_replica_id());
    }
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();

    LOGINFO("Restart leader");
    if (g_helper->replica_num() == 0) { g_helper->restart_homestore(); }
    g_helper->sync_for_test_start();

    LOGINFO("Validate leader switched");
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    auto leader = this->wait_and_get_leader_id();
    if (g_helper->replica_num() == 0) { ASSERT_NE(leader, g_helper->my_replica_id()); }
    g_helper->sync_for_verify_start();

    if (leader == g_helper->my_replica_id()) {
        LOGINFO("Resign and trigger a priority leader election");
        // resign and trigger a priority leader election
        g_helper->restart_homestore();
    }
    g_helper->sync_for_test_start();

    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    leader = this->wait_and_get_leader_id();
    LOGINFO("Validate leader switched back to initial replica");
    if (g_helper->replica_num() == 0) { ASSERT_EQ(leader, g_helper->my_replica_id()); }
    g_helper->sync_for_verify_start();

    LOGINFO("Post restart write the data again on the leader");
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    LOGINFO("Validate all data written (including pre-restart data) by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();
}

TEST_F(RaftReplDevTest, ComputePriority) {
    g_helper->sync_for_test_start();
    auto& raftService = dynamic_cast< RaftReplService& >(hs()->repl_service());

    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) { s.consensus.max_wait_rounds_of_priority_election = 0; });
    HS_SETTINGS_FACTORY().save();
    ASSERT_EQ(raftService.compute_raft_follower_priority(), raft_leader_priority);

    for (auto i = 1; i <= int(raft_priority_election_round_upper_limit); i++) {
        HS_SETTINGS_FACTORY().modifiable_settings(
            [i](auto& s) { s.consensus.max_wait_rounds_of_priority_election = i; });
        HS_SETTINGS_FACTORY().save();
        auto follower_priority = raftService.compute_raft_follower_priority();
        // Simulate nuraft algorithm
        auto decayed_priority = raft_leader_priority;
        for (auto j = 1; j <= i; j++) {
            int gap = std::max((int)10, decayed_priority / 5);
            decayed_priority = std::max(1, decayed_priority - gap);
        }
        LOGINFO("Follower priority={} decayed_priority={}", follower_priority, decayed_priority);
        ASSERT_TRUE(follower_priority >= decayed_priority);
    }
    // Set back to default value
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) { s.consensus.max_wait_rounds_of_priority_election = 2; });
    HS_SETTINGS_FACTORY().save();
    g_helper->sync_for_cleanup_start();
}

TEST_F(RaftReplDevTest, RaftLogTruncationTest) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    auto pre_raft_logstore_reserve_threshold = 0;
    HS_SETTINGS_FACTORY().modifiable_settings([&pre_raft_logstore_reserve_threshold](auto& s) {
        pre_raft_logstore_reserve_threshold = s.resource_limits.raft_logstore_reserve_threshold;
        s.resource_limits.raft_logstore_reserve_threshold = 200;
    });
    HS_SETTINGS_FACTORY().save();

    uint64_t entries_per_attempt = 100;
    uint64_t total_entires = 0;

    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);
    total_entires += entries_per_attempt;
    // wait for commmit on all members
    this->wait_for_commits(total_entires);
    test_common::HSTestHelper::trigger_cp(true /* wait */);
    g_helper->sync_for_verify_start();

    // trigger snapshot to update log truncation upper limit
    // sleep 1s to ensure the new truncation upper limit is updated
    this->create_snapshot();
    std::this_thread::sleep_for(std::chrono::seconds{1});
    ASSERT_GT(this->get_truncation_upper_limit(), 0);
    LOGINFO("After 100 entries written, truncation upper limit became {}", this->get_truncation_upper_limit());

    // shutdown replica 1.
    LOGINFO("Shutdown replica 1");
    this->shutdown_replica(1);

    // write another 100 entries on leader.
    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    if (g_helper->replica_num() == 0 || g_helper->replica_num() == 2) {
        this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);
        // Wait for commmit on leader and follower 2
        this->wait_for_all_commits();
        LOGINFO("Got all commits for replica 0 and 2");
        test_common::HSTestHelper::trigger_cp(true /* wait */);
        LOGINFO("Trigger cp after writing 100 entries for replica 0 and 2");
    }
    total_entires += entries_per_attempt;

    // trigger snapshot and check the truncation upper limit on leader
    // it should not larger than 200 because replica 1 is shutdown
    if (g_helper->replica_num() == 0) {
        this->create_snapshot();
        std::this_thread::sleep_for(std::chrono::seconds{1});
        ASSERT_LT(this->get_truncation_upper_limit(), 200);
        LOGINFO("After another 100 entries written, truncation upper limit {}", this->get_truncation_upper_limit());
    }

    g_helper->sync_for_test_start();

    // start replica 1 after this.
    LOGINFO("Start replica 1");
    this->start_replica(1);

    // write on leader to have some entries saved in raft log store.
    entries_per_attempt = 50;
    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);
    total_entires += entries_per_attempt;

    // wait till all writes are down.
    this->wait_for_commits(total_entires);
    test_common::HSTestHelper::trigger_cp(true /* wait */);
    g_helper->sync_for_verify_start();

    // trigger snapshot and check the truncation upper limit
    // it should no less than 250 on because all replicas has committed upto 250
    this->create_snapshot();
    std::this_thread::sleep_for(std::chrono::seconds{1});
    ASSERT_GE(this->get_truncation_upper_limit(), 250);
    LOGINFO("After another 50 entries written, truncation upper limit became {}", this->get_truncation_upper_limit());

    // wait all members sync and test raft_logstore_reserve_threshold limitation
    g_helper->sync_for_test_start();

    // shutdown replica1 again
    LOGINFO("Shutdown replica 1 again");
    this->shutdown_replica(1);

    // write another 300 entries on leader to test one member lagged too much
    entries_per_attempt = 300;
    LOGINFO("Write on leader num_entries={}", entries_per_attempt);
    if (g_helper->replica_num() == 0 || g_helper->replica_num() == 2) {
        this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);
        // Wait for commmit on leader and follower 2
        this->wait_for_all_commits();
        LOGINFO("Got all commits for replica 0 and 2");
        test_common::HSTestHelper::trigger_cp(true /* wait */);
        LOGINFO("Trigger cp after writing 300 entries for replica 0 and 2");
    }
    total_entires += entries_per_attempt;

    // trigger snapshot and check the truncation upper limit on leader
    // this time leader will use its commit_idx - resource_limits.raft_logstore_reserve_threshold >= 550 - 200 = 350
    if (g_helper->replica_num() == 0) {
        this->create_snapshot();
        std::this_thread::sleep_for(std::chrono::seconds{1});
        ASSERT_GE(this->get_truncation_upper_limit(), 350);
        ASSERT_LT(this->get_truncation_upper_limit(), 550);
        LOGINFO("After another 300 entries written, truncation upper limit {}", this->get_truncation_upper_limit());
    }
    g_helper->sync_for_verify_start();

    // start replica1 again, wait for replica1 catch up
    LOGINFO("Start replica 1 again");
    this->start_replica(1);
    g_helper->sync_for_test_start();
    this->wait_for_commits(total_entires);
    g_helper->sync_for_verify_start();

    // validate all data written so far by reading them
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();

    // set the settings back and save.
    LOGINFO("Set the raft_logstore_reserve_threshold back to previous value={}", pre_raft_logstore_reserve_threshold);
    HS_SETTINGS_FACTORY().modifiable_settings([pre_raft_logstore_reserve_threshold](auto& s) {
        s.resource_limits.raft_logstore_reserve_threshold = pre_raft_logstore_reserve_threshold;
    });
    HS_SETTINGS_FACTORY().save();

    g_helper->sync_for_cleanup_start();
    LOGINFO("RaftLogTruncationTest done");
}

TEST_F(RaftReplDevTest, WriteWithSSL) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();

    // Enable SSL for the repl_dev
    LOGINFO("Setup SSL for the repl_dev");
    static const std::string test_data_dir = "test_data";
    static const std::string cert_file = "/tmp/cert.pem";
    static const std::string key_file = "/tmp/key.pem";

    std::filesystem::copy(fmt::format("{}/cert.pem", test_data_dir), cert_file,
                          std::filesystem::copy_options::overwrite_existing);
    std::filesystem::copy(fmt::format("{}/key.pem", test_data_dir), key_file,
                          std::filesystem::copy_options::overwrite_existing);

    std::string prev_ssl_ca_file = "";
    HS_SETTINGS_FACTORY().modifiable_settings([&prev_ssl_ca_file](auto& s) {
        prev_ssl_ca_file = s.consensus.ssl_ca_file;
        s.consensus.ssl_ca_file = "/tmp/cert.pem";
    });
    HS_SETTINGS_FACTORY().save();

    // init sisl info
    ioenvironment.set_ssl_certs(cert_file, key_file);
    g_helper->sync_for_verify_start();

    LOGINFO("Restart all the replicas with SSL enabled");
    g_helper->restart();
    g_helper->sync_for_test_start();

    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();

    // Set the settings back and save.
    LOGINFO("Set the ssl_ca_file back to previous value={}", prev_ssl_ca_file);
    HS_SETTINGS_FACTORY().modifiable_settings(
        [prev_ssl_ca_file](auto& s) { s.consensus.ssl_ca_file = prev_ssl_ca_file; });
    HS_SETTINGS_FACTORY().save();
}

TEST_F(RaftReplDevTest, ReconcileLeader) {
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    g_helper->sync_for_test_start();
    uint64_t entries_per_attempt = SISL_OPTIONS["num_io"].as< uint64_t >();
    if (g_helper->replica_num() == 0) {
        auto leader = this->wait_and_get_leader_id();
        ASSERT_EQ(leader, g_helper->my_replica_id());
        LOGINFO("Initial leader is replica={}", leader);
    }
    this->write_on_leader(entries_per_attempt, true /* wait_for_commit */);

    g_helper->sync_for_verify_start();
    LOGINFO("Validate all data written so far by reading them");
    this->validate_data();
    g_helper->sync_for_cleanup_start();

    LOGINFO("Yield leader");
    auto expected_leader_num = 1;
    auto expected_leader = g_helper->replica_id(expected_leader_num);
    if (g_helper->replica_num() == 0) { this->yield_leadership(dbs_[0], false, expected_leader); }
    g_helper->sync_for_verify_start();
    LOGINFO("Validate leader switched");
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    auto leader = this->wait_and_get_leader_id();
    ASSERT_EQ(leader, expected_leader);

    g_helper->sync_for_test_start();
    LOGINFO("Trigger reconcile leader on follower, expected no change")
    if (g_helper->replica_num() == 2) { this->reconcile_leader(dbs_[0]); }
    g_helper->sync_for_verify_start();
    LOGINFO("Validate leader unchanged");
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    leader = this->wait_and_get_leader_id();
    ASSERT_EQ(leader, expected_leader);

    g_helper->sync_for_test_start();
    if (g_helper->replica_num() == 0) {
        LOGINFO("Request leadership on replica=0");
        this->reconcile_leader(dbs_[0]);
    }
    g_helper->sync_for_verify_start();
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});
    leader = this->wait_and_get_leader_id();
    LOGINFO("Validate leader switched back to initial replica");
    if (g_helper->replica_num() == 0) { ASSERT_EQ(leader, g_helper->my_replica_id()); }
    g_helper->sync_for_cleanup_start();

    LOGINFO("Yield leader again");
    if (g_helper->replica_num() == 0) { this->yield_leadership(dbs_[0], false, expected_leader); }
    g_helper->sync_for_verify_start();
    LOGINFO("Validate leader switched");
    std::this_thread::sleep_for(std::chrono::milliseconds{500});
    leader = this->wait_and_get_leader_id();
    ASSERT_EQ(leader, expected_leader);
    g_helper->sync_for_test_start();

    if (g_helper->my_replica_id() == leader) {
        LOGINFO("Yield leadership on replica={}", g_helper->replica_num());
        this->reconcile_leader(dbs_[0]);
    }
    g_helper->sync_for_verify_start();
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});
    leader = this->wait_and_get_leader_id();
    LOGINFO("Validate leader switched back to initial replica, leader={}", leader);
    if (g_helper->replica_num() == 0) { ASSERT_EQ(leader, g_helper->my_replica_id()); }
    g_helper->sync_for_cleanup_start();
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
