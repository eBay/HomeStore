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
#include <folly/futures/Future.h>
#include <nuraft_mesg/nuraft_mesg.hpp>
#include <sisl/fds/buffer.hpp>
#include <sisl/logging/logging.h>

#include <homestore/homestore.hpp>
#include <homestore/superblk_handler.hpp>
#include "replication/service/generic_repl_svc.h"

namespace homestore {

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
    iomgr::io_fiber_t m_reaper_fiber;

public:
    RaftReplService(cshared< ReplApplication >& repl_app);

    static ReplServiceError to_repl_error(nuraft::cmd_result_code code);

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
    AsyncReplResult<> replace_member(group_id_t group_id, replica_id_t member_out,
                                     replica_id_t member_in) const override;

private:
    void raft_group_config_found(sisl::byte_view const& buf, void* meta_cookie);

    void start_reaper_thread();
    void stop_reaper_thread();
    void fetch_pending_data();
    void gc_repl_devs();
    void gc_repl_reqs();
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
