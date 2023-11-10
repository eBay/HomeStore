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

struct repl_dev_superblk;
class GenericReplService : public ReplicationService {
protected:
    shared< ReplApplication > m_repl_app;
    std::shared_mutex m_rd_map_mtx;
    std::map< uuid_t, shared< ReplDev > > m_rd_map;

public:
    static std::unique_ptr< GenericReplService > create(cshared< ReplApplication >& repl_app);

    GenericReplService(cshared< ReplApplication >& repl_app);
    virtual void start() = 0;
    virtual void stop();
    meta_sub_type get_meta_blk_name() const override { return "repl_dev"; }

    AsyncReplResult< shared< ReplDev > > create_repl_dev(uuid_t group_id,
                                                         std::set< uuid_t, std::less<> >&& members) override;
    ReplResult< shared< ReplDev > > get_repl_dev(uuid_t group_id) const override;
    void iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) override;
    hs_stats get_cap_stats() const override;

protected:
    virtual AsyncReplResult<> create_replica_set(uuid_t group_id, std::set< uuid_t, std::less<> >&& members) = 0;
    virtual AsyncReplResult<> join_replica_set(uuid_t group_id, cshared< ReplDev >& repl_dev) = 0;
    virtual shared< ReplDev > create_local_repl_dev_instance(superblk< repl_dev_superblk > const& rd_sb,
                                                             bool load_existing) = 0;
    virtual uint32_t rd_super_blk_size() const = 0;

private:
    void rd_super_blk_found(sisl::byte_view const& buf, void* meta_cookie);
};

class SoloReplService : public GenericReplService {
public:
    SoloReplService(cshared< ReplApplication >& repl_app);
    void start() override;

    AsyncReplResult<> replace_member(uuid_t group_id, uuid_t member_out, uuid_t member_in) const override;

private:
    AsyncReplResult<> create_replica_set(uuid_t group_id, std::set< uuid_t, std::less<> >&& members) override;
    AsyncReplResult<> join_replica_set(uuid_t group_id, cshared< ReplDev >& repl_dev) override;
    shared< ReplDev > create_local_repl_dev_instance(superblk< repl_dev_superblk > const& rd_sb,
                                                     bool load_existing) override;
    uint32_t rd_super_blk_size() const override;
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
