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
#include <boost/uuid/random_generator.hpp>
#include "common/homestore_config.hpp"

// Dynamic tests spawn spare replica's also which can be used to add and remove from a repl dev.
class ReplDevDynamicTest : public RaftReplDevTestBase {
private:
    bool is_replica_num_in(const std::set< uint32_t >& replicas) {
        // Check if the current replica process is in this set.
        return replicas.count(g_helper->replica_num()) != 0 ? true : false;
    }
};

#ifdef _PRERELEASE
TEST_F(ReplDevDynamicTest, ReplaceMember) {
    LOGINFO("ReplaceMember test started replica={}", g_helper->replica_num());
    g_helper->set_basic_flip("skip_monitor_replace_member_replication_status", 1000);
    // Write some IO's, replace a member, validate all members data except which is out.
    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the last member in the group with index(num_replicas - 1) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = num_replicas - 1;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);
    std::string task_id = "task_id";
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::TASK_NOT_FOUND);
    });
    if (g_helper->replica_num() < num_replicas) {
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    } else if (g_helper->replica_num() == member_in) {
        LOGINFO("Wait for commits replica={}", g_helper->replica_num());
        wait_for_commits(num_io_entries);
    }

    g_helper->sync_for_verify_start(num_members);
    LOGINFO("sync_for_verify_state replica={} ", g_helper->replica_num());
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::IN_PROGRESS);
        std::string new_task_id = "mismatched_task_id";
        replace_member(db, new_task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in), 0,
                       ReplServiceError::REPLACE_MEMBER_TASK_MISMATCH);
    });
    // If the manual monitor_replace_member_replication_status fails, restore the periodical check.
    // restore the periodical check.
    LOGINFO("restore monitor_replace_member_replication_status")
    g_helper->remove_flip("skip_monitor_replace_member_replication_status");

    if (is_replica_num_in({0, 1, member_in})) {
        // Skip the member which is going to be replaced. Validate data on all other replica's.
        LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
        this->validate_data();
    }
    g_helper->sync_for_verify_start(num_members);
    LOGINFO("data synced, sync_for_verify_state replica={} ", g_helper->replica_num());

    // wait for background reaper thread to trigger complete_replace_member
    if (g_helper->replica_num() == member_out) {
        // The out member will have the repl dev destroyed.
        auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
        while (repl_dev && !repl_dev->is_destroyed()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
            raft_repl_svc.gc_repl_devs();
            LOGINFO("Waiting for repl dev to get destroyed on out member replica={}", g_helper->replica_num());
        }
        LOGINFO("Repl dev destroyed on out member replica={}", g_helper->replica_num());
    }

    g_helper->sync_for_cleanup_start(num_members);
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::COMPLETED);
    });
    LOGINFO("ReplaceMember test done replica={}", g_helper->replica_num());
}

// After replace member is in progress, rollback replace member operation(complete_replace_member will be disabled)
TEST_F(ReplDevDynamicTest, ReplaceMemberRollback) {
    LOGINFO("ReplaceMember test started replica={}", g_helper->replica_num());
    // don't execute complete_replace_member in the background reaper thread within this test.
    g_helper->set_basic_flip("skip_monitor_replace_member_replication_status", 1000);
    // Write some IO's, replace a member, validate all members data except which is out.
    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the last member in the group with index(num_replicas - 1) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = num_replicas - 1;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);
    std::string task_id = "task_id";
    if (g_helper->replica_num() < num_replicas) {
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    } else if (g_helper->replica_num() == member_in) {
        LOGINFO("Wait for being added to group, replica ={}", g_helper->replica_num());
        while (!group_exists(db)) {
            LOGDEBUG("Not added to group yet")
            std::this_thread::sleep_for(std::chrono::microseconds(300));
        }
        // Need to wait for log being caught up. There is a known issue that if the removed member can not catch up
        // within 5*HB since respond leave_cluster_request, it has no chance to detect itself removed from the group.
        // Unlike other tests, what we remove is a normal member who has all logs, here we remove new member which is
        // very likely to be behind.
        wait_for_commits(num_io_entries);
        LOGINFO("Member in got all commits");
    }

    g_helper->sync_for_verify_start(num_members);
    LOGINFO("sync_for_verify_start replica={} ", g_helper->replica_num());
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::IN_PROGRESS);
    });
    g_helper->sync_for_test_start();
    remove_member(db, g_helper->replica_id(member_in));
    flip_learner(db, g_helper->replica_id(member_out), false /* target */);
    clean_replace_member_task(db, task_id);

    g_helper->sync_for_verify_start(num_members);
    LOGINFO("rollback triggered, sync_for_verify_start replica={} ", g_helper->replica_num());

    if (g_helper->replica_num() == member_in) {
        auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
        while (repl_dev && !repl_dev->is_destroyed()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
            raft_repl_svc.gc_repl_devs();
            LOGINFO("Waiting for repl dev to get destroyed on out member replica={}", g_helper->replica_num());
        }
        db->set_zombie();
        LOGINFO("Repl dev destroyed on in member replica={}", g_helper->replica_num());
    } else {
        check_replace_member_rollback_result(db, task_id, g_helper->replica_id(member_out),
                                             g_helper->replica_id(member_in));
        if (is_replica_num_in({0, 1, member_out})) {
            // Skip the member which is going to be replaced. Validate data on all other replica's.
            LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
            this->validate_data();
        }
    }

    g_helper->sync_for_cleanup_start(num_members);
    g_helper->remove_flip("skip_monitor_replace_member_replication_status");
    LOGINFO("ReplaceMember test done replica={}", g_helper->replica_num());
}

TEST_F(ReplDevDynamicTest, TwoMemberDown) {
    LOGINFO("TwoMemberDown test started replica={}", g_helper->replica_num());
    g_helper->set_basic_flip("skip_monitor_replace_member_replication_status", 1000);
    // Make two members down in a group and leader cant reach a quorum.
    // We set the custom quorum size to 1 and call replace member.
    // Leader should do some writes to validate it has reach quorum size.
    LOGINFO("Homestore replica={} setup completed", g_helper->replica_num());
    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();

    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the last member in the group with index(num_replicas - 1) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = num_replicas - 1;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);

    // Shutdown replica 1 and replica 2 to simulate two member down.
    if (g_helper->replica_num() == 1) {
        this->shutdown_replica(1);
        LOGINFO("Shutdown replica 1");
    }

    if (g_helper->replica_num() == 2) {
        this->shutdown_replica(2);
        LOGINFO("Shutdown replica 2");
    }

    std::string task_id = "task_id";
    if (g_helper->replica_num() == 0) {
        // Replace down replica 2 with spare replica 3 with commit quorum 1
        // so that leader can go ahead with replacing member.
        LOGINFO("Replace member started, task_id={}", task_id);
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in),
                       1 /* commit quorum*/);
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);
        LOGINFO("Leader completed num_io={}", num_io_entries);
    }

    if (g_helper->replica_num() == member_in) {
        wait_for_commits(num_io_entries);
        LOGINFO("Member in got all commits");
    }

    if (is_replica_num_in({0, member_in})) {
        // Validate data on leader replica 0 and replica 3
        LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
        this->validate_data();
    }
    g_helper->sync_for_verify_start(num_members);
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::IN_PROGRESS);
    });

    if (g_helper->replica_num() == 1) {
        LOGINFO("Start replica 1");
        db->set_zombie();
        this->start_replica(1);
    }
    if (g_helper->replica_num() == 2) {
        LOGINFO("Start replica 2");
        db->set_zombie();
        this->start_replica(2);
    }

    g_helper->sync_for_cleanup_start(num_members);
    g_helper->remove_flip("skip_monitor_replace_member_replication_status");
    LOGINFO("TwoMemberDown test done replica={}", g_helper->replica_num());
}

TEST_F(ReplDevDynamicTest, OutMemberDown) {
    // replica0(leader) and replica1 up, replica2 is down. Replace replica2 with replica3.
    // replica0 should be able to baseline resync to replica4(new member).
    // Write some IO's, replace a member, validate all members data except which is out.
    LOGINFO("OutMemberDown test started replica={}", g_helper->replica_num());
    g_helper->set_basic_flip("skip_monitor_replace_member_replication_status", 1000);
    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the last member in the group with index(num_replicas - 1) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = num_replicas - 1;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);

    std::this_thread::sleep_for(std::chrono::seconds(3));
    if (g_helper->replica_num() == 0) {
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);
    }
    // shut down before replace member
    this->shutdown_replica(2);
    LOGINFO("Shutdown replica 2");

    std::string task_id = "task_id";
    if (g_helper->replica_num() == 0) {
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    } else if (g_helper->replica_num() == member_in) {
        LOGINFO("Wait for commits replica={}", g_helper->replica_num());
        wait_for_commits(num_io_entries);
    }

    g_helper->sync_for_verify_start(num_members);
    LOGINFO("sync_for_verify_state replica={} ", g_helper->replica_num());
    if (is_replica_num_in({0, 1, member_in})) {
        // Skip the member which is going to be replaced. Validate data on all other replica's.
        LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
        this->validate_data();
    }

    // shutdown after becoming learner, in this case, the member_out won't remove replDev after restart.
    // this->shutdown_replica(2);
    // LOGINFO("Shutdown replica 2");
    // std::this_thread::sleep_for(std::chrono::seconds(2));

    // data synced, waiting for removing learner
    LOGINFO("data synced, sync for completing replace member, replica={}", g_helper->replica_num());
    g_helper->sync_for_verify_start(num_members);
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::IN_PROGRESS);
    });
    LOGINFO("restore monitor_replace_member_replication_status")
    g_helper->remove_flip("skip_monitor_replace_member_replication_status");
    // Since the out_member stopped, it cannot response to remove_srv req, as a result the first time will get CANCELLED
    // error, so waiting time is longer than other tests.
    if (g_helper->replica_num() == 2) {
        LOGINFO("Start replica 2");
        this->start_replica(2);
        // The out member will have the repl dev destroyed.
        auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
        while (repl_dev && !repl_dev->is_destroyed()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
            raft_repl_svc.gc_repl_devs();
            LOGINFO("Waiting for repl dev to get destroyed on out member replica={}", g_helper->replica_num());
        }
        LOGINFO("Repl dev destroyed on out member replica={}", g_helper->replica_num());
        db->set_zombie();
    }
    g_helper->sync_for_test_start(num_members);
    if (g_helper->replica_num() != 2) {
        this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
            while (check_replace_member_status(
                       db, task_id, g_helper->replica_id(member_out),
                       // out_member is down, so it can not response to remove req. Based on nuraft logic, leader will
                       // wait for timeout and remove it automatically. Simulate next complete_replace_member retry.
                       g_helper->replica_id(member_in)) == ReplaceMemberStatus::IN_PROGRESS) {
                LOGINFO("wait for reaper thread to complete_replace_member");
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            ASSERT_EQ(check_replace_member_status(db, task_id, g_helper->replica_id(member_out),
                                                  g_helper->replica_id(member_in)),
                      ReplaceMemberStatus::COMPLETED);
        });
    }
    g_helper->sync_for_cleanup_start(num_members);
    LOGINFO("OutMemberDown test done replica={}", g_helper->replica_num());
}

TEST_F(ReplDevDynamicTest, LeaderReplace) {
    g_helper->set_basic_flip("skip_monitor_replace_member_replication_status", 1000);
    // replica0(leader) and replica1 and replica2 is up. Replace replica0(leader) with replica3.
    // replica0 will yield leadership and any other replica will be come leader  and leader
    // will do baseline resync to replica4(new member).
    // Write some IO's, replace a member, validate all members data except which is out.
    LOGINFO("LeaderReplace test started replica={}", g_helper->replica_num());
    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the leader in the group with index(0) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = 0;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);
    std::string task_id = "task_id";
    if (g_helper->replica_num() == member_out) {
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);

        // Leader will return error NOT_LEADER and yield leadership, sleep and connect again
        // to the new leader.
        LOGINFO("Replace old leader");
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in), 0,
                       ReplServiceError::NOT_LEADER);
        LOGINFO("Replace member leader yield done");
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));
    if (g_helper->replica_num() != member_in) {
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in));
        LOGINFO("Replace member old leader done");
    }

    if (g_helper->replica_num() == member_in) {
        LOGINFO("Wait for commits replica={}", g_helper->replica_num());
        wait_for_commits(num_io_entries);
    }

    g_helper->sync_for_verify_start(num_members);
    if (is_replica_num_in({0, 1, member_in})) {
        // Skip the member which is going to be replaced. Validate data on all other replica's.
        LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
        this->validate_data();
    }

    LOGINFO("data synced, sync_for_verify_state replica={} ", g_helper->replica_num());
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::IN_PROGRESS);
    });
    // restore the periodical check.
    LOGINFO("restore monitor_replace_member_replication_status")
    g_helper->remove_flip("skip_monitor_replace_member_replication_status");
    if (g_helper->replica_num() == member_out) {
        // The out member will have the repl dev destroyed.
        auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
        while (repl_dev && !repl_dev->is_destroyed()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
            raft_repl_svc.gc_repl_devs();
            LOGINFO("Waiting for repl dev to get destroyed on out member replica={}", g_helper->replica_num());
        }
        LOGINFO("Repl dev destroyed on out member replica={}", g_helper->replica_num());
        db->set_zombie();
    }

    g_helper->sync_for_cleanup_start(num_members);
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::COMPLETED);
    });
    LOGINFO("LeaderReplace test done replica={}", g_helper->replica_num());
}

TEST_F(ReplDevDynamicTest, OneMemberRestart) {
    // replica0(leader) is up and replica1 is restated, replica2 is down. Replace replica2 with replica3.
    // replica0 should be able to baseline resync to replica4(new member).
    // Write some IO's, replace a member, validate all members data except which is out.
    LOGINFO("OneMemberRestart test started replica={}", g_helper->replica_num());
    g_helper->set_basic_flip("skip_monitor_replace_member_replication_status", 1000);
    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the last member in the group with index(num_replicas - 1) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = num_replicas - 1;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);
    if (g_helper->replica_num() == 1) {
        LOGINFO("Restart replica 1, ");
        this->restart_replica(15);
    }
    std::string task_id = "task_id";
    if (g_helper->replica_num() == 0) {
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);

        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    } else if (g_helper->replica_num() == member_in) {
        LOGINFO("Wait for commits replica={}", g_helper->replica_num());
        wait_for_commits(num_io_entries);
    }

    g_helper->sync_for_verify_start(num_members);
    LOGINFO("sync_for_verify_state replica={} ", g_helper->replica_num());
    if (is_replica_num_in({0, 1, member_in})) {
        // Skip the member which is going to be replaced. Validate data on all other replica's.
        LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
        this->validate_data();
    }

    LOGINFO("data synced, sync_for_verify_state replica={} ", g_helper->replica_num());
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::IN_PROGRESS);
    });
    LOGINFO("restore monitor_replace_member_replication_status")
    g_helper->remove_flip("skip_monitor_replace_member_replication_status");

    if (g_helper->replica_num() == member_out) {
        // The out member will have the repl dev destroyed.
        auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
        while (repl_dev && !repl_dev->is_destroyed()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
            raft_repl_svc.gc_repl_devs();
            LOGINFO("Waiting for repl dev to get destroyed on out member replica={}", g_helper->replica_num());
        }
        LOGINFO("Repl dev destroyed on out member replica={}", g_helper->replica_num());
    }

    g_helper->sync_for_cleanup_start(num_members);
    this->run_on_leader(db, [this, db, &task_id, member_out, member_in] {
        ASSERT_EQ(
            check_replace_member_status(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in)),
            ReplaceMemberStatus::COMPLETED);
    });
    LOGINFO("OneMemberRestart test done replica={}", g_helper->replica_num());
}
#endif

TEST_F(ReplDevDynamicTest, ValidateRequest) {
    LOGINFO("ValidateRequest test started replica={}", g_helper->replica_num());
    HS_SETTINGS_FACTORY().modifiable_settings([](auto& s) {
        s.consensus.laggy_threshold = 0;
        LOGINFO("setup consensus.laggy_threshold to {}", 0);
        HS_SETTINGS_FACTORY().save();
    });

    auto db = dbs_.back();
    auto num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();
    auto num_members = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    uint64_t num_io_entries = SISL_OPTIONS["num_io"].as< uint64_t >();

    // Replace the last member in the group with index(num_replicas - 1) with a spare
    // replica with index (num_replica). Member id's are 0,...,num_replicas-1, num_replicas,...,N
    uint32_t member_out = num_replicas - 1;
    uint32_t member_in = num_replicas;

    g_helper->sync_for_test_start(num_members);

    // shut down before replace member
    this->shutdown_replica(1);
    LOGINFO("Shutdown replica 1");

    // wait for shutdown
    std::this_thread::sleep_for(std::chrono::seconds(3));
    g_helper->sync_for_verify_start(num_members);
    if (g_helper->replica_num() == 0) {
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);
    }

    std::string task_id = "task_id";
    if (g_helper->replica_num() == 0) {
        // generate uuid
        replica_id_t fake_member_out = boost::uuids::random_generator()();
        replica_id_t fake_member_in = boost::uuids::random_generator()();
        LOGINFO("test SERVER_NOT_FOUND");
        replace_member(db, task_id, fake_member_out, fake_member_in, 0, ReplServiceError::SERVER_NOT_FOUND);
        LOGINFO("test replace_member already complete");
        replace_member(db, task_id, fake_member_out, g_helper->replica_id(0));
        LOGINFO("test QUORUM_NOT_MET", num_io_entries, g_helper->replica_num());
        replace_member(db, task_id, g_helper->replica_id(member_out), g_helper->replica_id(member_in), 0,
                       ReplServiceError::QUORUM_NOT_MET);
    }

    if (g_helper->replica_num() == 1) {
        LOGINFO("Start replica 1");
        this->start_replica(1);
    }
    g_helper->sync_for_cleanup_start(num_members);
    LOGINFO("ValidateRequest test done replica={}", g_helper->replica_num());
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
    g_helper = std::make_unique< test_common::HSReplTestHelper >("test_raft_repl_dev_dynamic", args, orig_argv);

    // We spawn spare replica's also for dynamic repl dev tests.
    auto total_replicas = SISL_OPTIONS["replicas"].as< uint32_t >() + SISL_OPTIONS["spare_replicas"].as< uint32_t >();
    g_helper->setup(total_replicas);

    auto ret = RUN_ALL_TESTS();
    g_helper->teardown();

    std::string str;
    sisl::ObjCounterRegistry::foreach ([&str](const std::string& name, int64_t created, int64_t alive) {
        fmt::format_to(std::back_inserter(str), "{}: created={} alive={}\n", name, created, alive);
    });
    LOGINFO("Object Life Counter\n:{}", str);

    return ret;
}
