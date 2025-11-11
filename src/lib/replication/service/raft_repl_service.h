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
#pragma once
#include <map>
#include <queue>
#include <set>
#include <string>
#include <shared_mutex>

#include <folly/Expected.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include <folly/futures/Future.h>
#pragma GCC diagnostic pop
#include <nuraft_mesg/nuraft_mesg.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/logging/logging.h>

#include <homestore/homestore.hpp>
#include <homestore/superblk_handler.hpp>
#include "replication/service/generic_repl_svc.h"

namespace homestore {

constexpr auto cert_change_timeout = std::chrono::seconds(1200);
constexpr auto cert_check_sleep = std::chrono::seconds(1);
constexpr int32_t raft_leader_priority = 100;
constexpr double raft_priority_decay_coefficient = 0.8;
constexpr uint32_t raft_priority_election_round_upper_limit = 5;

struct repl_dev_superblk;
class RaftReplDev;

class RaftReplService : public GenericReplService,
                        public nuraft_mesg::MessagingApplication,
                        public std::enable_shared_from_this< RaftReplService > {
private:
    shared< nuraft_mesg::Manager > m_msg_mgr;
    json_superblk m_config_sb;
    std::vector< std::pair< sisl::byte_view, void* > > m_config_sb_bufs;
    std::mutex m_pending_fetch_mtx;
    std::queue< std::pair< shared< RaftReplDev >, std::vector< repl_req_ptr_t > > > m_pending_fetch_batches;
    iomgr::timer_handle_t m_rdev_fetch_timer_hdl;
    iomgr::timer_handle_t m_rdev_gc_timer_hdl;
    iomgr::timer_handle_t m_flush_durable_commit_timer_hdl;
    iomgr::timer_handle_t m_replace_member_sync_check_timer_hdl;
    iomgr::io_fiber_t m_reaper_fiber;
    std::atomic< int32_t > restart_counter{0};
    std::mutex raft_restart_mutex;

public:
    RaftReplService(cshared< ReplApplication >& repl_app);
    ~RaftReplService() override;

    static ReplServiceError to_repl_error(nuraft::cmd_result_code code);
    int32_t compute_raft_follower_priority();

    ///////////////////// Overrides of nuraft_mesg::MessagingApplication ////////////////////
    std::string lookup_peer(nuraft_mesg::peer_id_t const&) override;
    std::shared_ptr< nuraft_mesg::mesg_state_mgr > create_state_mgr(int32_t srv_id,
                                                                    nuraft_mesg::group_id_t const& group_id) override;
    nuraft_mesg::Manager& msg_manager() { return *m_msg_mgr; }
    void add_to_fetch_queue(cshared< RaftReplDev >& rdev, std::vector< repl_req_ptr_t > rreqs);

protected:
    ///////////////////// Overrides of GenericReplService ////////////////////
    void start() override;
    void stop() override;

    AsyncReplResult< shared< ReplDev > > create_repl_dev(group_id_t group_id,
                                                         std::set< replica_id_t > const& members) override;
    folly::SemiFuture< ReplServiceError > remove_repl_dev(group_id_t group_id) override;
    void load_repl_dev(sisl::byte_view const& buf, void* meta_cookie) override;
    AsyncReplResult<> replace_member(group_id_t group_id, std::string& task_id, const replica_member_info& member_out,
                                     const replica_member_info& member_in, uint32_t commit_quorum = 0,
                                     uint64_t trace_id = 0) const override;

    AsyncReplResult<> flip_learner_flag(group_id_t group_id, const replica_member_info& member, bool target,
                                        uint32_t commit_quorum, bool wait_and_verify = true,
                                        uint64_t trace_id = 0) const override;
    AsyncReplResult<> remove_member(group_id_t group_id, const replica_id_t& member, uint32_t commit_quorum,
                                    bool wait_and_verify = true, uint64_t trace_id = 0) const override;

    AsyncReplResult<> clean_replace_member_task(group_id_t group_id, const std::string& task_id, uint32_t commit_quorum,
                                                uint64_t trace_id = 0) const override;

    ReplResult< std::vector< replace_member_task > > list_replace_member_tasks(uint64_t trace_id = 0) const override;

    ReplaceMemberStatus get_replace_member_status(group_id_t group_id, std::string& task_id,
                                                  const replica_member_info& member_out,
                                                  const replica_member_info& member_in,
                                                  const std::vector< replica_member_info >& others,
                                                  uint64_t trace_id = 0) const override;
    ReplServiceError destroy_repl_dev(group_id_t group_id, uint64_t trace_id = 0) override;

private:
    RaftReplDev* raft_group_config_found(sisl::byte_view const& buf, void* meta_cookie);
    void start_repl_service_timers();
    void stop_repl_service_timers();
    void fetch_pending_data();
    void gc_repl_devs();
    void gc_repl_reqs();
    void flush_durable_commit_lsn();
    void monitor_replace_member_replication_status();
    void monitor_cert_changes();
    void restart_raft_svc(const std::string filepath, const bool deleted);
    bool wait_for_cert(const std::string& filepath);
};

// cp context for repl_dev, repl_dev cp_lsn is critical cursor in the system,
// anything below the cp_lsn we believed is persisted through cp and will not
// go through replay.  The cp_lsn need to be kept into ctx when switchover_cp,
// and the persist of repl_dev_cp need to be done after all other consumers succeed.

struct ReplDevCPContext;

class ReplSvcCPContext : public CPContext {
    std::shared_mutex m_cp_map_mtx;
    std::map< ReplDev*, cshared< ReplDevCPContext > > m_cp_ctx_map;

public:
    ReplSvcCPContext(CP* cp) : CPContext(cp){};
    virtual ~ReplSvcCPContext() = default;
    int add_repl_dev_ctx(ReplDev* dev, cshared< ReplDevCPContext > dev_ctx);
    cshared< ReplDevCPContext > get_repl_dev_ctx(ReplDev* dev);
};

class RaftReplServiceCPHandler : public CPCallbacks {
public:
    RaftReplServiceCPHandler() = default;
    virtual ~RaftReplServiceCPHandler() = default;

public:
    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;
};

} // namespace homestore
