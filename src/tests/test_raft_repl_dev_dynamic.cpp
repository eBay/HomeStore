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

// Dynamic tests spawn spare replica's also which can be used to add and remove from a repl dev.
class ReplDevDynamicTest : public RaftReplDevTestBase {};

TEST_F(ReplDevDynamicTest, ReplaceMember) {
    // Write some IO's, replace a member, validate all members data except which is out.
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
    if (g_helper->replica_num() < num_replicas) {
        // With existing raft repl dev group, write IO's, validate and call replace_member on leader.
        LOGINFO("Writing on leader num_io={} replica={}", num_io_entries, g_helper->replica_num());
        this->write_on_leader(num_io_entries, true /* wait_for_commit */);

        replace_member(db, g_helper->replica_id(member_out), g_helper->replica_id(member_in));
        std::this_thread::sleep_for(std::chrono::seconds(3));
    } else if (g_helper->replica_num() == member_in) {
        LOGINFO("Wait for commits replica={}", g_helper->replica_num());
        wait_for_commits(num_io_entries);
    }

    g_helper->sync_for_verify_start(num_members);
    LOGINFO("sync_for_verify_state replica={} ", g_helper->replica_num());
    if (g_helper->replica_num() != member_out) {
        // Skip the member which is going to be replaced. Validate data on all other replica's.
        LOGINFO("Validate all data written so far by reading them replica={}", g_helper->replica_num());
        this->validate_data();
    } else {
        // The out member will have the repl dev destroyed.
        auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
        do {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
            raft_repl_svc.gc_repl_devs();
            LOGINFO("Waiting for repl dev to get destroyed on out member replica={}", g_helper->replica_num());
        } while (!repl_dev->is_destroyed());
        LOGINFO("Repl dev destroyed on out member replica={}", g_helper->replica_num());
    }

    g_helper->sync_for_cleanup_start(num_members);
    LOGINFO("ReplaceMember test done");
}

// TODO add more tests with leader and member restart, multiple member replace
// leader replace, commit quorum

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
