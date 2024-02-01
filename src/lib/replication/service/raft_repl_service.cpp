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
#include <sisl/logging/logging.h>
#include <iomgr/io_environment.hpp>
#include <chrono>

#include <boost/uuid/string_generator.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/raft_repl_dev.h"

namespace homestore {
ReplServiceError RaftReplService::to_repl_error(nuraft::cmd_result_code code) {
    ReplServiceError ret;
    if (code == nuraft::cmd_result_code::OK) {
        ret = ReplServiceError::OK;
    } else if (code == nuraft::cmd_result_code::CANCELLED) {
        ret = ReplServiceError::CANCELLED;
    } else if (code == nuraft::cmd_result_code::TIMEOUT) {
        ret = ReplServiceError::TIMEOUT;
    } else if (code == nuraft::cmd_result_code::NOT_LEADER) {
        ret = ReplServiceError::NOT_LEADER;
    } else if (code == nuraft::cmd_result_code::BAD_REQUEST) {
        ret = ReplServiceError::BAD_REQUEST;
    } else if (code == nuraft::cmd_result_code::SERVER_ALREADY_EXISTS) {
        ret = ReplServiceError::SERVER_ALREADY_EXISTS;
    } else if (code == nuraft::cmd_result_code::CONFIG_CHANGING) {
        ret = ReplServiceError::CONFIG_CHANGING;
    } else if (code == nuraft::cmd_result_code::SERVER_IS_JOINING) {
        ret = ReplServiceError::SERVER_IS_JOINING;
    } else if (code == nuraft::cmd_result_code::SERVER_NOT_FOUND) {
        ret = ReplServiceError::SERVER_NOT_FOUND;
    } else if (code == nuraft::cmd_result_code::CANNOT_REMOVE_LEADER) {
        ret = ReplServiceError::CANNOT_REMOVE_LEADER;
    } else if (code == nuraft::cmd_result_code::SERVER_IS_LEAVING) {
        ret = ReplServiceError::SERVER_IS_LEAVING;
    } else if (code == nuraft::cmd_result_code::TERM_MISMATCH) {
        ret = ReplServiceError::TERM_MISMATCH;
    } else if (code == nuraft::cmd_result_code::RESULT_NOT_EXIST_YET) {
        ret = ReplServiceError::RESULT_NOT_EXIST_YET;
    } else {
        ret = ReplServiceError::FAILED;
    }
    return ret;
}

RaftReplService::RaftReplService(cshared< ReplApplication >& repl_app) : GenericReplService{repl_app} {
    m_config_sb_bufs.reserve(100);
    meta_service().register_handler(
        get_meta_blk_name() + "_raft_config",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t) {
            m_config_sb_bufs.emplace_back(std::pair(std::move(buf), voidptr_cast(mblk)));
        },
        nullptr, false, std::optional< meta_subtype_vec_t >({get_meta_blk_name()}));
}

void RaftReplService::start() {
    // Step 1: Initialize the Nuraft messaging service, which starts the nuraft service
    auto params = nuraft_mesg::Manager::Params{
        .server_uuid_ = m_my_uuid,
        .mesg_port_ = m_repl_app->lookup_peer(m_my_uuid).second,
        .default_group_type_ = "homestore_replication",
        .ssl_key_ = ioenvironment.get_ssl_key(),
        .ssl_cert_ = ioenvironment.get_ssl_cert(),
        .token_verifier_ = std::dynamic_pointer_cast< sisl::GrpcTokenVerifier >(ioenvironment.get_token_verifier()),
        .token_client_ = std::dynamic_pointer_cast< sisl::GrpcTokenClient >(ioenvironment.get_token_client())};
    m_msg_mgr = nuraft_mesg::init_messaging(params, weak_from_this(), true /* with_data_channel */);

    LOGINFO("Starting RaftReplService with server_uuid={} port={}", boost::uuids::to_string(params.server_uuid_),
            params.mesg_port_);

    // Step 2: Register all RAFT parameters. At the end of this step, raft is ready to be created/join group
    auto r_params = nuraft::raft_params()
                        .with_election_timeout_lower(HS_DYNAMIC_CONFIG(consensus.elect_to_low_ms))
                        .with_election_timeout_upper(HS_DYNAMIC_CONFIG(consensus.elect_to_high_ms))
                        .with_rpc_failure_backoff(HS_DYNAMIC_CONFIG(consensus.rpc_backoff_ms))
                        .with_hb_interval(HS_DYNAMIC_CONFIG(consensus.heartbeat_period_ms))
                        .with_max_append_size(HS_DYNAMIC_CONFIG(consensus.max_append_batch_size))
                        .with_log_sync_batch_size(HS_DYNAMIC_CONFIG(consensus.log_sync_batch_size))
                        .with_log_sync_stopping_gap(HS_DYNAMIC_CONFIG(consensus.min_log_gap_to_join))
                        .with_stale_log_gap(HS_DYNAMIC_CONFIG(consensus.stale_log_gap_hi_threshold))
                        .with_fresh_log_gap(HS_DYNAMIC_CONFIG(consensus.stale_log_gap_lo_threshold))
                        .with_snapshot_enabled(HS_DYNAMIC_CONFIG(consensus.snapshot_freq_distance))
                        //.with_leadership_expiry(-1 /* never expires */) // >>> debug only
                        .with_reserved_log_items(0) // In reality ReplLogStore retains much more than this
                        .with_auto_forwarding(false);
    r_params.return_method_ = nuraft::raft_params::async_handler;
    m_msg_mgr->register_mgr_type(params.default_group_type_, r_params);

    // Step 3: Load all the repl devs from the cached superblks. This step creates the ReplDev instances and adds to
    // list. It is still not joined the Raft group yet
    for (auto const& [buf, mblk] : m_sb_bufs) {
        load_repl_dev(buf, voidptr_cast(mblk));
    }
    m_sb_bufs.clear();

    // Step 4: Load all the raft group configs from the cached superblks. We have 2 superblks for each raft group
    // a) repl_dev configuration (loaded in step 3). This block is updated on every append and persisted on next cp.
    // b) raft group configuration (loaded in this step). This block is updated on every config change and persisted
    // instantly
    //
    // We need to first load the repl_dev with its config and then attach the raft config to that repl dev.
    for (auto const& [buf, mblk] : m_config_sb_bufs) {
        raft_group_config_found(buf, voidptr_cast(mblk));
    }
    m_config_sb_bufs.clear();

    // Step 5: Start the data and logstore service now. This step is essential before we can ask Raft to join groups etc
    hs()->data_service().start();
    hs()->logstore_service().start(hs()->is_first_time_boot());

    // Step 6: Iterate all the repl dev and ask each one of the join the raft group.
    for (auto it = m_rd_map.begin(); it != m_rd_map.end();) {
        auto rdev = std::dynamic_pointer_cast< RaftReplDev >(it->second);
        if (!rdev->join_group()) {
            it = m_rd_map.erase(it);
        } else {
            ++it;
        }
    }

    // Step 7: Register to CPManager to ensure we can flush the superblk.
    hs()->cp_mgr().register_consumer(cp_consumer_t::REPLICATION_SVC, std::make_unique< RaftReplServiceCPHandler >());
}

void RaftReplService::stop() {
    GenericReplService::stop();
    m_msg_mgr.reset();
    hs()->logstore_service().stop();
}

void RaftReplService::raft_group_config_found(sisl::byte_view const& buf, void* meta_cookie) {
    json_superblk group_config;
    auto& js = group_config.load(buf, meta_cookie);

    DEBUG_ASSERT(js.contains("group_id"), "Missing group_id field in raft_config superblk");
    std::string gid_str = js["group_id"];
    RELEASE_ASSERT(!gid_str.empty(), "Invalid raft_group config found");

    boost::uuids::string_generator gen;
    uuid_t group_id = gen(gid_str);

    auto v = get_repl_dev(group_id);
    RELEASE_ASSERT(bool(v), "Can't find the group_id={}, has repl_dev superblk not loaded yet?",
                   boost::uuids::to_string(group_id));

    auto rdev = std::dynamic_pointer_cast< RaftReplDev >(*v);
    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev);
    rdev->attach_listener(std::move(listener));
    rdev->use_config(std::move(group_config));
}

std::string RaftReplService::lookup_peer(nuraft_mesg::peer_id_t const& peer) {
    auto const p = m_repl_app->lookup_peer(peer);
    return p.first + ":" + std::to_string(p.second);
}

shared< nuraft_mesg::mesg_state_mgr > RaftReplService::create_state_mgr(int32_t srv_id,
                                                                        nuraft_mesg::group_id_t const& group_id) {
    LOGINFO("Creating RAFT state manager for server_id={} group_id={}", srv_id, boost::uuids::to_string(group_id));

    auto result = get_repl_dev(group_id);
    if (result) { return std::dynamic_pointer_cast< nuraft_mesg::mesg_state_mgr >(result.value()); }

    // Create a new raft superblk
    superblk< raft_repl_dev_superblk > rd_sb{get_meta_blk_name()};
    rd_sb.create();
    rd_sb->group_id = group_id;
    rd_sb->is_timeline_consistent = m_repl_app->need_timeline_consistency();

    // Create a new instance of Raft ReplDev (which is the state manager this method is looking for)
    auto rdev = std::make_shared< RaftReplDev >(*this, std::move(rd_sb), false /* load_existing */);

    // Create a raft config for this repl_dev and assign it to the repl_dev
    auto raft_config_sb = json_superblk{get_meta_blk_name() + "_raft_config"};
    (*raft_config_sb)["group_id"] = boost::uuids::to_string(group_id);
    raft_config_sb.write();
    rdev->use_config(std::move(raft_config_sb));

    // Attach the listener to the raft
    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev);
    rdev->attach_listener(std::move(listener));

    // Add the repl dev to the map
    add_repl_dev(group_id, rdev);
    return std::dynamic_pointer_cast< nuraft_mesg::mesg_state_mgr >(rdev);
}

AsyncReplResult< shared< ReplDev > > RaftReplService::create_repl_dev(group_id_t group_id,
                                                                      std::set< replica_id_t > const& members) {
    // TODO: All operations are made sync here for convenience to caller. However, we should attempt to make this async
    // and do deferValue to a seperate dedicated hs thread for these kind of operations and wakeup the caller. It
    // probably needs iomanager executor for deferValue.
    if (members.size() > 0) {
        // Create a new RAFT group and add all members. create_group() will call the create_state_mgr which will create
        // the repl_dev instance and add it to the map.
        if (auto const status = m_msg_mgr->create_group(group_id, "homestore_replication").get(); !status) {
            return make_async_error< shared< ReplDev > >(to_repl_error(status.error()));
        }

        auto my_id = m_repl_app->get_my_repl_id();
        for (auto& member : members) {
            if (member == my_id) { continue; } // Skip myself
            do {
                auto const result = m_msg_mgr->add_member(group_id, member).get();
                if (result) {
                    LOGINFO("Groupid={}, new member={} added", boost::uuids::to_string(group_id),
                            boost::uuids::to_string(member));
                    break;
                } else if (result.error() != nuraft::CONFIG_CHANGING) {
                    LOGWARN("Groupid={}, add member={} failed with error={}", boost::uuids::to_string(group_id),
                            boost::uuids::to_string(member), result.error());
                    return make_async_error< shared< ReplDev > >(to_repl_error(result.error()));
                } else {
                    LOGWARN("Config is changing for group_id={} while adding member={}, retry operation in a second",
                            boost::uuids::to_string(group_id), boost::uuids::to_string(member));
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            } while (true);
        }
    }

    auto result = get_repl_dev(group_id);
    return result ? make_async_success< shared< ReplDev > >(result.value())
                  : make_async_error< shared< ReplDev > >(ReplServiceError::SERVER_NOT_FOUND);
}

void RaftReplService::load_repl_dev(sisl::byte_view const& buf, void* meta_cookie) {
    // Load the superblk
    superblk< raft_repl_dev_superblk > rd_sb{get_meta_blk_name()};
    rd_sb.load(buf, meta_cookie);
    HS_DBG_ASSERT_EQ(rd_sb->get_magic(), repl_dev_superblk::REPL_DEV_SB_MAGIC, "Invalid rdev metablk, magic mismatch");
    HS_DBG_ASSERT_EQ(rd_sb->get_raft_sb_version(), raft_repl_dev_superblk::RAFT_REPL_DEV_SB_VERSION,
                     "Invalid version of raft rdev metablk");
    group_id_t group_id = rd_sb->group_id;

    // Validate if the repl_dev for this group is already loaded.
    auto rdev_result = get_repl_dev(group_id);
    if (rdev_result) {
        HS_DBG_ASSERT("Group ID={} already loaded and added to repl_dev list, duplicate load?",
                      boost::uuids::to_string(group_id).c_str());
        return;
    }

    // Create an instance of ReplDev from loaded superblk
    auto rdev = std::make_shared< RaftReplDev >(*this, std::move(rd_sb), true /* load_existing */);

    // Add the RaftReplDev to the list of repl_devs
    add_repl_dev(group_id, rdev);
}

AsyncReplResult<> RaftReplService::replace_member(group_id_t group_id, replica_id_t member_out,
                                                  replica_id_t member_in) const {
    return make_async_error<>(ReplServiceError::NOT_IMPLEMENTED);
}

///////////////////// RaftReplService CP Callbacks /////////////////////////////
std::unique_ptr< CPContext > RaftReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) { return nullptr; }

folly::Future< bool > RaftReplServiceCPHandler::cp_flush(CP* cp) {
    repl_service().iterate_repl_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::static_pointer_cast< RaftReplDev >(repl_dev)->cp_flush(cp); });
    return folly::makeFuture< bool >(true);
}

void RaftReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_repl_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::static_pointer_cast< RaftReplDev >(repl_dev)->cp_cleanup(cp); });
}

int RaftReplServiceCPHandler::cp_progress_percent() { return 100; }
} // namespace homestore
