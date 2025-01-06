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
    m_my_uuid = m_repl_app->get_my_repl_id();
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

    // check if ssl cert files are provided, if yes, monitor the changes
    if (!params.ssl_key_.empty() && !params.ssl_cert_.empty()) {
        ioenvironment.with_file_watcher();
        monitor_cert_changes();
    }

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
                        .with_leadership_expiry(HS_DYNAMIC_CONFIG(consensus.leadership_expiry_ms))
                        .with_reserved_log_items(HS_DYNAMIC_CONFIG(consensus.num_reserved_log_items))
                        .with_auto_forwarding(false);
    // new_joiner_type fully disabled log pack behavior.
    // There is no callback available for handling and localizing the log entries within the pack, which could
    // result in data corruption.
    r_params.use_new_joiner_type_ = true;
    r_params.use_bg_thread_for_snapshot_io_ = HS_DYNAMIC_CONFIG(consensus.use_bg_thread_for_snapshot_io_);
    r_params.return_method_ = nuraft::raft_params::async_handler;
    m_msg_mgr->register_mgr_type(params.default_group_type_, r_params);

    // Step 3: Load all the repl devs from the cached superblks. This step creates the ReplDev instances and adds to
    // list. It is still not joined the Raft group yet
    for (auto const& [buf, mblk] : m_sb_bufs) {
        load_repl_dev(buf, voidptr_cast(mblk));
    }
    m_sb_bufs.clear();

    // Step 4: Load all the raft group configs from the cached superblks. We have 2 superblks for each raft group
    // a) repl_dev configuration (loaded in step 3). This block is updated on every append and persisted on a.
    // b) raft group configuration (loaded in this step). This block is updated on every config change and persisted
    // instantly
    //
    // We need to first load the repl_dev with its config and then attach the raft config to that repl dev.
    for (auto const& [buf, mblk] : m_config_sb_bufs) {
        auto rdev = raft_group_config_found(buf, voidptr_cast(mblk));
        // if repl_dev is in destroy_pending state, it will not be loaded.
        if (rdev) rdev->on_restart();
    }
    m_config_sb_bufs.clear();
    LOGINFO("Repl devs load completed, calling upper layer on_repl_devs_init_completed");
    m_repl_app->on_repl_devs_init_completed();

    // Step 5: Start the data and logstore service now. This step is essential before we can ask Raft to join groups etc

    // It is crucial to start the logstore before the enalbe data channel. This is because during log replay,
    // the commit_blks() function is called, which interacts with the allocator.
    // Starting the data channel before the log replay is complete can lead to a race condition between
    // PUSHDATA operations and log replay.
    // For example, consider LSN 100 in the log store is associated with PBA1. After a restart, the allocator
    // is only aware of allocations up to the last checkpoint and may consider PBA1 as available.
    // If a PUSHDATA request is received during this time, PBA1 could be allocated again to a new request,
    // leading to data corruption by overwriting the data associated with LSN 100.
    // Now the data channel is started in join_group().

    LOGINFO("Starting LogStore service, fist_boot = {}", hs()->is_first_time_boot());
    hs()->logstore_service().start(hs()->is_first_time_boot());
    LOGINFO("Started LogStore service, log replay should already done till this point");
    // all log stores are replayed, time to start data service.
    LOGINFO("Starting DataService");
    hs()->data_service().start();

    // Step 6: Iterate all the repl dev and ask each one of the join the raft group.
    for (auto it = m_rd_map.begin(); it != m_rd_map.end();) {
        auto rdev = std::dynamic_pointer_cast< RaftReplDev >(it->second);
        rdev->wait_for_logstore_ready();
        if (!rdev->join_group()) {
            HS_REL_ASSERT(false, "FAILED TO JOIN GROUP, PANIC HERE");
            it = m_rd_map.erase(it);
        } else {
            ++it;
        }
    }

    // Step 7: Register to CPManager to ensure we can flush the superblk.
    hs()->cp_mgr().register_consumer(cp_consumer_t::REPLICATION_SVC, std::make_unique< RaftReplServiceCPHandler >());

    // Step 8: Start a reaper thread which wakes up time-to-time and fetches pending data or cleans up old requests etc
    start_reaper_thread();

    // Delete any unopened logstores.
    hs()->logstore_service().delete_unopened_logdevs();
}

void RaftReplService::stop() {
    stop_reaper_thread();
    GenericReplService::stop();
    m_msg_mgr.reset();
    hs()->logstore_service().stop();
}

void RaftReplService::monitor_cert_changes() {
    auto fw = ioenvironment.get_file_watcher();
    auto cert_change_cb = [this](const std::string filepath, const bool deleted) {
        LOGINFO("file change event for {}, deleted? {}", filepath, deleted)
        // do not block file_watcher thread
        std::thread restart_svc(&RaftReplService::restart_raft_svc, this, filepath, deleted);
        restart_svc.detach();
    };

    // monitor ssl cert file
    if (!fw->register_listener(ioenvironment.get_ssl_cert(), "hs_ssl_cert_watcher", cert_change_cb)) {
        LOGERROR("Failed to register listner, {} to watch file {}, Not monitoring cert files", "hs_ssl_cert_watcher",
                 ioenvironment.get_ssl_cert());
    }
    // monitor ssl key file
    if (!fw->register_listener(ioenvironment.get_ssl_key(), "hs_ssl_key_watcher", cert_change_cb)) {
        LOGERROR("Failed to register listner, {} to watch file {}, Not monitoring cert files", "hs_ssl_key_watcher",
                 ioenvironment.get_ssl_key());
    }
}

void RaftReplService::restart_raft_svc(const std::string filepath, const bool deleted) {
    if (deleted && !wait_for_cert(filepath)) {
        LOGINFO("file {} deleted, ", filepath)
        // wait for the deleted file to be added again
        throw std::runtime_error(fmt::format("file {} not found! Can not start grpc server", filepath));
    }
    const std::unique_lock lock(raft_restart_mutex);
    m_msg_mgr->restart_server();
    if (deleted) { monitor_cert_changes(); }
}

bool RaftReplService::wait_for_cert(const std::string& filepath) {
    auto attempts = cert_change_timeout / cert_check_sleep;
    for (auto i = attempts; i > 0; --i) {
        if (std::filesystem::exists(filepath)) { return true; }
        std::this_thread::sleep_for(cert_check_sleep);
    }
    return false;
}

RaftReplDev* RaftReplService::raft_group_config_found(sisl::byte_view const& buf, void* meta_cookie) {
    json_superblk group_config;
    auto& js = group_config.load(buf, meta_cookie);

    DEBUG_ASSERT(js.contains("group_id"), "Missing group_id field in raft_config superblk");
    std::string gid_str = js["group_id"];
    RELEASE_ASSERT(!gid_str.empty(), "Invalid raft_group config found");

    boost::uuids::string_generator gen;
    uuid_t group_id = gen(gid_str);

    auto v = get_repl_dev(group_id);
    if (!bool(v)) {
        LOGWARNMOD(
            replication,
            "Unable to find group_id={}, may be repl_dev was destroyed, we will destroy the raft_group_config as well",
            boost::uuids::to_string(group_id));
        group_config.destroy();
        return nullptr;
    }

    auto rdev = std::dynamic_pointer_cast< RaftReplDev >(*v);
    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev);
    rdev->attach_listener(std::move(listener));
    rdev->use_config(std::move(group_config));
    return rdev.get();
}

std::string RaftReplService::lookup_peer(nuraft_mesg::peer_id_t const& peer) {
    auto const p = m_repl_app->lookup_peer(peer);
    if (p.first.empty()) { return {}; }
    return p.first + ":" + std::to_string(p.second);
}

shared< nuraft_mesg::mesg_state_mgr > RaftReplService::create_state_mgr(int32_t srv_id,
                                                                        nuraft_mesg::group_id_t const& group_id) {
    LOGINFOMOD(replication, "Creating RAFT state manager for server_id={} group_id={}", srv_id,
               boost::uuids::to_string(group_id));

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
                    LOGINFOMOD(replication, "Groupid={}, new member={} added", boost::uuids::to_string(group_id),
                               boost::uuids::to_string(member));
                    break;
                } else if (result.error() != nuraft::CONFIG_CHANGING) {
                    LOGWARNMOD(replication, "Groupid={}, add member={} failed with error={}",
                               boost::uuids::to_string(group_id), boost::uuids::to_string(member), result.error());
                    return make_async_error< shared< ReplDev > >(to_repl_error(result.error()));
                } else {
                    LOGWARNMOD(replication,
                               "Config is changing for group_id={} while adding member={}, retry operation in a second",
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

// Remove repl_dev for raft is a 3 step process.
// Step 1: The leader of the repl_dev proposes all members an entry to delete the entire group. As part of commit of
// this entry, all members call leave() method, which does the following:
//      a) Mark in cache that the group is destroyed, so no subsequent write operations are permitted (relevant to
//      leader only)
//      b) Call the upper_layer on_destroy(), so that consumers persistent meta information can be deleted.
//      c) Update the superblk with destroy_pending flag set to 1
//      d) Mark the entry as committed lsn.
//
// If the node crash between step 1a and 1c, given that the entry is not marked committed yet and the fact that actual
// removal of raft groups in lazy fashion, once this member starts back again and rejoins the raft group and the peers
// will send the removal_raft_group entry again and this member will re-commit this entry and proceed step 1a through
// step 3. However, there is a possibility that this node comes backup after the lazy removal time, in which case the
// other members of raft group are long gone and this will be the only member. This case can never be solved and hence
// will let some sort of scrubber to clean that up. Such cases are extremely rare and thus can leave it to scrubber
//
// Step 2: Separate reaper thread which wakes up on pre-determined interval and check if the raft group destroy time is
// up. If so, it will call Nuraft leave_group() call, which call RaftReplDev::permanent_destroy() method.
//
// Step 3: RaftReplDev::permanent_destroy() method will remove the superblk and logstore. This is followed up RAFT
// server shutdown.
//
// If there is a crash after Step 1, but before Step 3, upon crash startup, we see that superblk has destroy_pending
// set. In that case, it will not join the raft group and hence no need to do leave_group() and permanent_destroy().
// It merely needs to cleanup the superblk. Given that logstore is not opened, HomeLogStoreService will automatically
// purge any unopened logstores.
//
folly::SemiFuture< ReplServiceError > RaftReplService::remove_repl_dev(group_id_t group_id) {
    auto rdev_result = get_repl_dev(group_id);
    if (!rdev_result) { return folly::makeSemiFuture< ReplServiceError >(ReplServiceError::SERVER_NOT_FOUND); }

    return std::dynamic_pointer_cast< RaftReplDev >(rdev_result.value())->destroy_group();
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

    if (rd_sb->destroy_pending == 0x1) {
        LOGINFOMOD(replication, "ReplDev group_id={} was destroyed, reclaim the stale resource", group_id);
        // if we do not add the repl_dev to m_rd_map, it will not be permanently destroyed since gc thread finds the
        // pending destroy repl_dev only from m_rd_map. so, we should try to reclaim all the repl_dev stale resources
        // here.

        // 1 since we permanantly destroy the repl_dev here, it will not join_raft group where raft_server will be
        // created. hence , no need to detroy it through nuraft_mesg, where raft_server will be shutdown.
        // 2  m_raft_config_sb will be destroyed in raft_group_config_found() method if repl_dev is is not found, so
        // skip it.

        // 3 logdev will be destroyed in delete_unopened_logdevs() if we don't open it(create repl_dev) here, so skip
        // it.

        // 4 destroy the superblk, and after this,  the repl_dev will not be loaded and found again.
        rd_sb.destroy();

        return;
    }

    // Create an instance of ReplDev from loaded superblk
    auto rdev = std::make_shared< RaftReplDev >(*this, std::move(rd_sb), true /* load_existing */);

    // Add the RaftReplDev to the list of repl_devs
    add_repl_dev(group_id, rdev);
}

AsyncReplResult<> RaftReplService::replace_member(group_id_t group_id, const replica_member_info& member_out,
                                                  const replica_member_info& member_in, uint32_t commit_quorum) const {
    auto rdev_result = get_repl_dev(group_id);
    if (!rdev_result) { return make_async_error<>(ReplServiceError::SERVER_NOT_FOUND); }

    return std::dynamic_pointer_cast< RaftReplDev >(rdev_result.value())
        ->replace_member(member_out, member_in, commit_quorum)
        .via(&folly::InlineExecutor::instance())
        .thenValue([this](auto&& e) mutable {
            if (e.hasError()) { return make_async_error<>(e.error()); }
            return make_async_success<>();
        });
}

////////////////////// Reaper Thread related //////////////////////////////////
void RaftReplService::start_reaper_thread() {
    folly::Promise< folly::Unit > p;
    auto f = p.getFuture();
    iomanager.create_reactor("repl_svc_reaper", iomgr::INTERRUPT_LOOP, 1u, [this, &p](bool is_started) mutable {
        if (is_started) {
            m_reaper_fiber = iomanager.iofiber_self();

            // Schedule the rdev garbage collector timer
            LOGINFOMOD(replication, "Reaper Thread: scheduling GC every {} seconds",
                       HS_DYNAMIC_CONFIG(generic.repl_dev_cleanup_interval_sec));
            m_rdev_gc_timer_hdl = iomanager.schedule_thread_timer(
                HS_DYNAMIC_CONFIG(generic.repl_dev_cleanup_interval_sec) * 1000 * 1000 * 1000, true /* recurring */,
                nullptr, [this](void*) {
                    LOGDEBUGMOD(replication, "Reaper Thread: Doing GC");
                    gc_repl_reqs();
                    gc_repl_devs();
                });

            // Check for queued fetches at the minimum every second
            uint64_t interval_ns =
                std::min(HS_DYNAMIC_CONFIG(consensus.wait_data_write_timer_ms) * 1000 * 1000, 1ul * 1000 * 1000 * 1000);
            m_rdev_fetch_timer_hdl = iomanager.schedule_thread_timer(interval_ns, true /* recurring */, nullptr,
                                                                     [this](void*) { fetch_pending_data(); });

            // Flush durable commit lsns to superblock
            // FIXUP: what is the best value for flush_durable_commit_interval_ms?
            m_flush_durable_commit_timer_hdl = iomanager.schedule_thread_timer(
                HS_DYNAMIC_CONFIG(consensus.flush_durable_commit_interval_ms) * 1000 * 1000, true /* recurring */,
                nullptr, [this](void*) { flush_durable_commit_lsn(); });

            p.setValue();
        } else {
            // Cancel all recurring timers started
            iomanager.cancel_timer(m_rdev_gc_timer_hdl, true /* wait */);
            iomanager.cancel_timer(m_rdev_fetch_timer_hdl, true /* wait */);
            iomanager.cancel_timer(m_flush_durable_commit_timer_hdl, true /* wait */);
        }
    });
    std::move(f).get();
}

void RaftReplService::stop_reaper_thread() {
    iomanager.run_on_wait(m_reaper_fiber, [] { iomanager.stop_io_loop(); });
}

void RaftReplService::add_to_fetch_queue(cshared< RaftReplDev >& rdev, std::vector< repl_req_ptr_t > rreqs) {
    std::unique_lock lg(m_pending_fetch_mtx);
    m_pending_fetch_batches.push(std::make_pair(rdev, std::move(rreqs)));
}

void RaftReplService::fetch_pending_data() {
    std::unique_lock lg(m_pending_fetch_mtx);
    while (!m_pending_fetch_batches.empty()) {
        auto const& [d, rreqs] = m_pending_fetch_batches.front();
        if (get_elapsed_time_ms(rreqs.at(0)->created_time()) < HS_DYNAMIC_CONFIG(consensus.wait_data_write_timer_ms)) {
            break;
        }
        auto const next_batch = std::move(rreqs);
        auto rdev = d;
        m_pending_fetch_batches.pop();
        lg.unlock();

        rdev->check_and_fetch_remote_data(std::move(next_batch));
        lg.lock();
    }
}

void RaftReplService::gc_repl_reqs() {
    std::shared_lock lg(m_rd_map_mtx);
    for (auto it = m_rd_map.begin(); it != m_rd_map.end(); ++it) {
        auto rdev = std::dynamic_pointer_cast< RaftReplDev >(it->second);
        rdev->gc_repl_reqs();
    }
}

void RaftReplService::gc_repl_devs() {
    std::unique_lock lg(m_rd_map_mtx);
    for (auto it = m_rd_map.begin(); it != m_rd_map.end();) {
        auto rdev = std::dynamic_pointer_cast< RaftReplDev >(it->second);
        if (rdev->is_destroy_pending() &&
            (get_elapsed_time_sec(rdev->destroyed_time()) >=
             HS_DYNAMIC_CONFIG(generic.repl_dev_cleanup_interval_sec))) {
            LOGINFOMOD(replication,
                       "ReplDev group_id={} was destroyed, shutting down the raft group in delayed fashion now",
                       rdev->group_id());
            m_msg_mgr->leave_group(rdev->group_id());
            it = m_rd_map.erase(it);
        } else {
            ++it;
        }
    }
}

void RaftReplService::flush_durable_commit_lsn() {
    std::unique_lock lg(m_rd_map_mtx);
    for (auto& rdev_parent : m_rd_map) {
        // FIXUP: is it safe to access rdev_parent here?
        auto rdev = std::dynamic_pointer_cast< RaftReplDev >(rdev_parent.second);
        rdev->flush_durable_commit_lsn();
    }
}

///////////////////// RaftReplService CP Callbacks /////////////////////////////
int ReplSvcCPContext::add_repl_dev_ctx(ReplDev* dev, cshared< ReplDevCPContext > dev_ctx) {
    m_cp_ctx_map.emplace(dev, dev_ctx);
    return 0;
}

cshared< ReplDevCPContext > ReplSvcCPContext::get_repl_dev_ctx(ReplDev* dev) {
    if (m_cp_ctx_map.count(dev) == 0) {
        // it is possible if a repl dev added during the cp flush
        return std::make_shared< ReplDevCPContext >();
    }
    return m_cp_ctx_map[dev];
}

std::unique_ptr< CPContext > RaftReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    // checking if cur_cp == nullptr as on_switchover_cp will be called when registering the cp handler
    if (cur_cp != nullptr) {
        // Add cp info from all devices to current cp.
        // We dont need taking cp_guard as cp_mgr already taken it in do_trigger_cp_flush
        auto cur_cp_ctx = s_cast< ReplSvcCPContext* >(cur_cp->context(cp_consumer_t::REPLICATION_SVC));
        repl_service().iterate_repl_devs([cur_cp, cur_cp_ctx](cshared< ReplDev >& repl_dev) {
            // we need collecting the LSN of each repl dev and put it into current CP.
            // There is no dirty buffers accumulated to new_cp yet, as the cp_mgr ensure replication_svc
            // is the first one being called during cp switchover.
            auto dev_ctx = std::static_pointer_cast< RaftReplDev >(repl_dev)->get_cp_ctx(cur_cp);
            cur_cp_ctx->add_repl_dev_ctx(repl_dev.get(), std::move(dev_ctx));
        });
    }
    // create new ctx
    auto ctx = std::make_unique< ReplSvcCPContext >(new_cp);
    return ctx;
}

folly::Future< bool > RaftReplServiceCPHandler::cp_flush(CP* cp) {
    auto cp_ctx = s_cast< ReplSvcCPContext* >(cp->context(cp_consumer_t::REPLICATION_SVC));
    repl_service().iterate_repl_devs([cp, cp_ctx](cshared< ReplDev >& repl_dev) {
        auto dev_ctx = cp_ctx->get_repl_dev_ctx(repl_dev.get());
        std::static_pointer_cast< RaftReplDev >(repl_dev)->cp_flush(cp, dev_ctx);
    });
    return folly::makeFuture< bool >(true);
}

void RaftReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_repl_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::static_pointer_cast< RaftReplDev >(repl_dev)->cp_cleanup(cp); });
}

int RaftReplServiceCPHandler::cp_progress_percent() { return 100; }
} // namespace homestore
