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
/*
 * Homestore Replication testing binaries shared common definitions, apis and data structures
 */

#pragma once
#include <mutex>
#include <condition_variable>
#include <map>
#include <set>
#include <boost/process.hpp>
#include <boost/asio.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_condition.hpp>
#include <boost/uuid/string_generator.hpp>

#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/settings/settings.hpp>
#include <sisl/grpc/rpc_client.hpp>
#include "test_common/homestore_test_common.hpp"

SISL_OPTION_GROUP(test_repl_common_setup,
                  (replicas, "", "replicas", "Total number of replicas",
                   ::cxxopts::value< uint32_t >()->default_value("3"), "number"),
                  (base_port, "", "base_port", "Port number of first replica",
                   ::cxxopts::value< uint16_t >()->default_value("4000"), "number"),
                  (replica_num, "", "replica_num",
                   "Internal replica num (used to lauch multi process) - don't override",
                   ::cxxopts::value< uint16_t >()->default_value("0"), "number"),
                  (replica_dev_list, "", "replica_dev_list", "Device list for all replicas",
                   ::cxxopts::value< std::vector< std::string > >(), "path [...]"));

std::vector< std::string > test_common::HSTestHelper::s_dev_names;

using namespace homestore;
namespace bip = boost::interprocess;

namespace test_common {

VENUM(ipc_packet_op_t, uint32_t, WAKE_UP = 0, CLEAN_EXIT = 1, UNCLEAN_EXIT = 2, PEER_GOING_DOWN = 3);
ENUM(repl_test_phase_t, uint32_t, REGISTER, MEMBER_START, TEST_RUN, VALIDATE, CLEANUP);

class HSReplTestHelper {
protected:
    struct IPCData {
        bip::interprocess_mutex mtx_;
        bip::interprocess_condition cv_;
        bip::interprocess_mutex exec_mtx_;

        repl_test_phase_t phase_{repl_test_phase_t::REGISTER};
        uint32_t registered_count_{0};
        uint32_t test_start_count_{0};
        uint32_t verify_start_count_{0};
        uint32_t cleanup_start_count_{0};
        uint64_t test_dataset_size_{0};

        void sync_for_member_start(uint32_t num_members = 0) {
            sync_for(registered_count_, repl_test_phase_t::MEMBER_START, num_members);
        }
        void sync_for_test_start(uint32_t num_members = 0) {
            sync_for(test_start_count_, repl_test_phase_t::TEST_RUN, num_members);
        }
        void sync_for_verify_start(uint32_t num_members = 0) {
            sync_for(verify_start_count_, repl_test_phase_t::VALIDATE, num_members);
        }
        void sync_for_cleanup_start(uint32_t num_members = 0) {
            sync_for(cleanup_start_count_, repl_test_phase_t::CLEANUP, num_members);
        }

    private:
        void sync_for(uint32_t& count, repl_test_phase_t new_phase, uint32_t max_count = 0) {
            if (max_count == 0) { max_count = SISL_OPTIONS["replicas"].as< uint32_t >(); }
            std::unique_lock< bip::interprocess_mutex > lg(mtx_);
            ++count;
            if (count == max_count) {
                phase_ = new_phase;
                cv_.notify_all();
            } else {
                cv_.wait(lg, [this, new_phase]() { return (phase_ == new_phase); });
            }

            count = 0;
        }
    };

public:
    class TestReplApplication : public ReplApplication {
    private:
        HSReplTestHelper& helper_;

    public:
        TestReplApplication(HSReplTestHelper& h) : helper_{h} {}
        virtual ~TestReplApplication() = default;

        homestore::repl_impl_type get_impl_type() const override { return homestore::repl_impl_type::server_side; }
        bool need_timeline_consistency() const { return false; }

        std::shared_ptr< homestore::ReplDevListener >
        create_repl_dev_listener(homestore::group_id_t group_id) override {
            return helper_.get_listener(group_id);
        }

        std::pair< std::string, uint16_t > lookup_peer(homestore::replica_id_t replica_id) const override {
            uint16_t port;
            if (auto it = helper_.members_.find(replica_id); it != helper_.members_.end()) {
                port = SISL_OPTIONS["base_port"].as< uint16_t >() + it->second;
            } else {
                RELEASE_ASSERT(false, "Gotten lookup_peer call for a non member");
            }

            return std::make_pair(std::string("127.0.0.1"), port);
        }

        homestore::replica_id_t get_my_repl_id() const override { return helper_.my_replica_id_; }
    };

public:
    friend class TestReplApplication;

    HSReplTestHelper(std::string const& name, std::vector< std::string > const& args, char** argv) :
            name_{name}, args_{args}, argv_{argv} {}

    void setup() {
        replica_num_ = SISL_OPTIONS["replica_num"].as< uint16_t >();
        sisl::logging::SetLogger(name_ + std::string("_replica_") + std::to_string(replica_num_));
        sisl::logging::SetLogPattern("[%D %T%z] [%^%L%$] [%n] [%t] %v");
        auto const num_replicas = SISL_OPTIONS["replicas"].as< uint32_t >();

        boost::uuids::string_generator gen;
        for (uint32_t i{0}; i < num_replicas; ++i) {
            auto replica_id = gen(fmt::format("{:04}", i) + std::string("0123456789abcdef0123456789ab"));
            up_members_.insert(i);
            if (i == replica_num_) { my_replica_id_ = replica_id; }
            members_.insert(std::pair(replica_id, i));
        }

        // example:
        // --num_replicas 3 --replica_dev_list replica_0_dev_1, replica_0_dev_2, replica_0_dev_3, replica_1_dev_1,
        // replica_1_dev_2, replica_1_dev_3, replica_2_dev_1, replica_2_dev_2, replica_2_dev_3    // every replica 2
        // devs;
        // --num_replicas 3 --replica_dev_list replica_0_dev_1, replica_1_dev_1, replica_2_dev_1  // <<< every
        // replica has 1 dev;
        std::vector< std::string > dev_list_all;
        std::vector< std::vector< std::string > > rdev_list(num_replicas);
        if (SISL_OPTIONS.count("replica_dev_list")) {
            dev_list_all = SISL_OPTIONS["replica_dev_list"].as< std::vector< std::string > >();
            RELEASE_ASSERT(dev_list_all.size() % num_replicas == 0,
                           "Number of replica devices should be times of number replicas");
            LOGINFO("Device list from input={}", fmt::join(dev_list_all, ","));
            uint32_t num_devs_per_replica = dev_list_all.size() / num_replicas;
            for (uint32_t i{0}; i < num_replicas; ++i) {
                for (uint32_t j{0}; j < num_devs_per_replica; ++j) {
                    rdev_list[i].push_back(dev_list_all[i * num_devs_per_replica + j]);
                }
            }
        }

        if (replica_num_ == 0) {
            // Erase previous shmem and create a new shmem with IPCData structure
            bip::shared_memory_object::remove("raft_repl_test_shmem");

            // kill the previous processes using the port
            for (uint32_t i = 0; i < num_replicas; ++i)
                check_and_kill(SISL_OPTIONS["base_port"].as< uint16_t >() + i);

            shm_ = std::make_unique< bip::shared_memory_object >(bip::create_only, "raft_repl_test_shmem",
                                                                 bip::read_write);
            shm_->truncate(sizeof(IPCData));
            region_ = std::make_unique< bip::mapped_region >(*shm_, bip::read_write);
            ipc_data_ = new (region_->get_address()) IPCData;

            for (uint32_t i{1}; i < num_replicas; ++i) {
                LOGINFO("Spawning Homestore replica={} instance", i);

                std::string cmd_line;
                fmt::format_to(std::back_inserter(cmd_line), "{} --replica_num {}", args_[0], i);
                for (int j{1}; j < (int)args_.size(); ++j) {
                    fmt::format_to(std::back_inserter(cmd_line), " {}", args_[j]);
                }
                boost::process::child c(boost::process::cmd = cmd_line, proc_grp_);
                c.detach();
            }
        } else {
            shm_ =
                std::make_unique< bip::shared_memory_object >(bip::open_only, "raft_repl_test_shmem", bip::read_write);
            region_ = std::make_unique< bip::mapped_region >(*shm_, bip::read_write);
            ipc_data_ = static_cast< IPCData* >(region_->get_address());
        }

        int tmp_argc = 1;
        folly_ = std::make_unique< folly::Init >(&tmp_argc, &argv_, true);

        LOGINFO("Starting Homestore replica={}", replica_num_);
        test_common::HSTestHelper::start_homestore(
            name_ + std::to_string(replica_num_),
            {{HS_SERVICE::META, {.size_pct = 5.0}},
             {HS_SERVICE::REPLICATION, {.size_pct = 60.0, .repl_app = std::make_unique< TestReplApplication >(*this)}},
             {HS_SERVICE::LOG, {.size_pct = 20.0}}},
            nullptr /*hs_before_svc_start_cb*/, false /*fake_restart*/, true /*init_device*/,
            5u /*shutdown_delay_secs*/, rdev_list[replica_num_]);
    }

    void teardown() {
        LOGINFO("Stopping Homestore replica={}", replica_num_);
        // sisl::GrpcAsyncClientWorker::shutdown_all();
        test_common::HSTestHelper::shutdown_homestore();
        sisl::GrpcAsyncClientWorker::shutdown_all();
    }

    void reset_setup() {
        teardown();
        setup();
    }

    void restart(uint32_t shutdown_delay_secs = 5u) {
        test_common::HSTestHelper::start_homestore(
            name_ + std::to_string(replica_num_),
            {{HS_SERVICE::REPLICATION, {.repl_app = std::make_unique< TestReplApplication >(*this)}},
             {HS_SERVICE::LOG, {}}},
            nullptr, true /* fake_restart */, false /* init_device */, shutdown_delay_secs);
    }

    void restart_one_by_one() {
        exclusive_replica([&]() {
            LOGINFO("Restarting Homestore replica={}", replica_num_);
            test_common::HSTestHelper::start_homestore(
                name_ + std::to_string(replica_num_),
                {{HS_SERVICE::REPLICATION, {.repl_app = std::make_unique< TestReplApplication >(*this)}},
                 {HS_SERVICE::LOG, {}}},
                nullptr, true /* fake_restart */, false /* init_device */, 5u /* shutdown_delay_secs */);
        });
    }

    uint16_t replica_num() const { return replica_num_; }
    homestore::replica_id_t my_replica_id() const { return my_replica_id_; }
    homestore::replica_id_t replica_id(uint16_t member_id) const {
        auto it = std::find_if(members_.begin(), members_.end(),
                               [member_id](auto const& p) { return p.second == member_id; });
        if (it != members_.end()) { return it->first; }
        return boost::uuids::nil_uuid();
    }

    uint16_t member_id(homestore::replica_id_t replica_id) const {
        auto it = members_.find(replica_id);
        if (it != members_.end()) { return it->second; }
        return members_.size();
    }

    Runner& runner() { return io_runner_; }

    void register_listener(std::shared_ptr< ReplDevListener > listener) {
        if (replica_num_ != 0) { pending_listeners_.emplace_back(std::move(listener)); }

        ipc_data_->sync_for_member_start();

        if (replica_num_ == 0) {
            std::set< homestore::replica_id_t > members;
            std::transform(members_.begin(), members_.end(), std::inserter(members, members.end()),
                           [](auto const& p) { return p.first; });
            group_id_t repl_group_id = hs_utils::gen_random_uuid();
            {
                std::unique_lock lg(groups_mtx_);
                repl_groups_.insert({repl_group_id, std::move(listener)});
            }

            auto v = hs()->repl_service().create_repl_dev(repl_group_id, members).get();
            ASSERT_EQ(v.hasValue(), true)
                << "Error in creating repl dev for group_id=" << boost::uuids::to_string(repl_group_id).c_str();
        }
    }

    std::shared_ptr< ReplDevListener > get_listener(homestore::group_id_t group_id) {
        std::unique_lock lg(groups_mtx_);

        auto it = repl_groups_.find(group_id);
        if ((it != repl_groups_.end()) && (it->second != nullptr)) { return it->second; }

        RELEASE_ASSERT(!pending_listeners_.empty(),
                       "Looking for listener for group_id, but register_listener was not called");

        auto listener = std::move(pending_listeners_[0]);
        repl_groups_.insert(std::pair(group_id, listener));
        pending_listeners_.erase(pending_listeners_.begin());
        return listener;
    }

    void unregister_listener(homestore::group_id_t group_id) {
        {
            std::unique_lock lg(groups_mtx_);
            repl_groups_.erase(group_id);
        }
    }

    size_t num_listeners() const {
        std::unique_lock lg(groups_mtx_);
        return repl_groups_.size();
    }

    void sync_for_test_start(uint32_t num_members = 0) { ipc_data_->sync_for_test_start(num_members); }
    void sync_for_verify_start(uint32_t num_members = 0) { ipc_data_->sync_for_verify_start(num_members); }
    void sync_for_cleanup_start(uint32_t num_members = 0) { ipc_data_->sync_for_cleanup_start(num_members); }
    void sync_dataset_size(uint64_t dataset_size) { ipc_data_->test_dataset_size_ = dataset_size; }
    uint64_t dataset_size() const { return ipc_data_->test_dataset_size_; }

    void exclusive_replica(std::function< void() > const& f) {
        std::unique_lock< bip::interprocess_mutex > lg(ipc_data_->exec_mtx_);
        f();
    }

    void check_and_kill(int port) {
        std::string command = "lsof -t -i:" + std::to_string(port);
        if (system(command.c_str())) {
            std::cout << "Port " << port << " is not in use." << std::endl;
        } else {
            std::cout << "Port " << port << " is in use. Trying to kill the process..." << std::endl;
            command += " | xargs kill -9";
            int result = system(command.c_str());
            if (result == 0) {
                std::cout << "Killed the process using port " << port << std::endl;
            } else {
                std::cout << "Failed to kill the process." << std::endl;
            }
        }
    }

private:
    uint16_t replica_num_;
    std::string name_;
    std::vector< std::string > args_;
    char** argv_;

    boost::process::group proc_grp_;
    std::unique_ptr< bip::shared_memory_object > shm_;
    std::unique_ptr< bip::mapped_region > region_;
    std::unique_ptr< folly::Init > folly_;

    std::mutex groups_mtx_;
    std::condition_variable group_created_cv_;
    std::map< homestore::group_id_t, std::shared_ptr< homestore::ReplDevListener > > repl_groups_;
    std::vector< std::shared_ptr< homestore::ReplDevListener > > pending_listeners_; // pending to join raft group
    std::map< homestore::replica_id_t, uint32_t > members_;
    std::set< uint32_t > up_members_;
    homestore::replica_id_t my_replica_id_;

    std::mutex wakeup_mtx_;
    uint32_t wokenup_replicas_{0};
    std::condition_variable wakeup_cv_;

    IPCData* ipc_data_;

    Runner io_runner_;
};
} // namespace test_common
