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
#include <set>
#include <string>
#include <shared_mutex>

#include <sisl/fds/buffer.hpp>
#include <sisl/logging/logging.h>

#include <folly/Expected.h>
#include <folly/futures/Future.h>
#include <homestore/homestore.hpp>
#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include <homestore/checkpoint/cp_mgr.hpp>
#include <homestore/superblk_handler.hpp>

namespace homestore {

static std::string const PUSH_DATA{"push_data"};
static std::string const FETCH_DATA{"fetch_data"};

struct repl_dev_superblk;
class GenericReplService : public ReplicationService {
protected:
    shared< ReplApplication > m_repl_app;
    std::shared_mutex m_rd_map_mtx;
    std::map< group_id_t, shared< ReplDev > > m_rd_map;
    replica_id_t m_my_uuid;
    std::vector< std::pair< sisl::byte_view, void* > > m_sb_bufs;

public:
    static std::shared_ptr< GenericReplService > create(cshared< ReplApplication >& repl_app);

    GenericReplService(cshared< ReplApplication >& repl_app);
    virtual ~GenericReplService();
    virtual void start() = 0;
    meta_sub_type get_meta_blk_name() const override { return "repl_dev"; }

    ReplResult< shared< ReplDev > > get_repl_dev(group_id_t group_id) const override;
    void iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) override;

    hs_stats get_cap_stats() const override;
    replica_id_t get_my_repl_uuid() const { return m_my_uuid; }
    // void resource_audit() override;
    virtual void stop() = 0;

    repl_impl_type get_impl_type() const { return m_repl_app->get_impl_type(); }

protected:
    virtual void add_repl_dev(group_id_t group_id, shared< ReplDev > rdev);
    virtual void load_repl_dev(sisl::byte_view const& buf, void* meta_cookie) = 0;

    // graceful shutdown related
protected:
    std::atomic_bool m_stopping{false};
    mutable std::atomic_uint64_t pending_request_num{0};

    bool is_stopping() const { return m_stopping.load(); }
    void start_stopping() { m_stopping = true; }

    uint64_t get_pending_request_num() const { return pending_request_num.load(); }

    void incr_pending_request_num() const { pending_request_num++; }
    void decr_pending_request_num() const { pending_request_num--; }
};

// TODO: implement graceful shutdown for soloReplService
class SoloReplService : public GenericReplService {
public:
    SoloReplService(cshared< ReplApplication >& repl_app);
    ~SoloReplService() override;
    void start() override;
    void stop() override;

    AsyncReplResult< shared< ReplDev > > create_repl_dev(group_id_t group_id,
                                                         std::set< replica_id_t > const& members) override;
    folly::SemiFuture< ReplServiceError > remove_repl_dev(group_id_t group_id) override;
    void load_repl_dev(sisl::byte_view const& buf, void* meta_cookie) override;
    AsyncReplResult<> replace_member(group_id_t group_id, uuid_t task_id, const replica_member_info& member_out,
                                     const replica_member_info& member_in, uint32_t commit_quorum = 0,
                                     uint64_t trace_id = 0) const override;
    AsyncReplResult<> flip_learner_flag(group_id_t group_id, const replica_member_info& member, bool target,
                                        uint32_t commit_quorum, bool wait_and_verify = true,
                                        uint64_t trace_id = 0) const override;
    ReplaceMemberStatus get_replace_member_status(group_id_t group_id, uuid_t task_id,
                                                  const replica_member_info& member_out,
                                                  const replica_member_info& member_in,
                                                  const std::vector< replica_member_info >& others,
                                                  uint64_t trace_id = 0) const override;
};

class SoloReplServiceCPHandler : public CPCallbacks {
public:
    SoloReplServiceCPHandler() = default;
    virtual ~SoloReplServiceCPHandler() = default;

    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;
};

extern ReplicationService& repl_service();
} // namespace homestore
