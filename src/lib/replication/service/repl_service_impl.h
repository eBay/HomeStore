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
class ReplicationServiceImpl : public ReplicationService {
    struct listener_info {
        folly::Promise< folly::Expected< shared< ReplDev >, ReplServiceError > > dev_promise{};
        std::unique_ptr< ReplDevListener > listener;
    };

    template < class V >
    auto make_async_error(ReplServiceError err) {
        return folly::makeFuture< ReplResult< V > >(folly::makeUnexpected(err));
    }

    template < class V >
    auto make_async_success(V&& v) {
        return folly::makeFuture< ReplResult< V > >(std::move(v));
    }

protected:
    repl_impl_type m_repl_type;
    std::shared_mutex m_rd_map_mtx;
    std::map< uuid_t, shared< ReplDev > > m_rd_map;
    std::map< uuid_t, listener_info > m_pending_open;
    std::atomic< bool > m_rd_map_loaded{false};

public:
    ReplicationServiceImpl(repl_impl_type impl_type);
    void start();
    void stop();
    AsyncReplResult< shared< ReplDev > > create_repl_dev(uuid_t group_id,
                                                         std::set< std::string, std::less<> >&& members,
                                                         std::unique_ptr< ReplDevListener > listener) override;
    AsyncReplResult< shared< ReplDev > > open_repl_dev(uuid_t group_id,
                                                       std::unique_ptr< ReplDevListener > listener) override;
    ReplResult< shared< ReplDev > > get_repl_dev(uuid_t group_id) const override;
    void iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) override;

    folly::Future< ReplServiceError > replace_member(uuid_t group_id, std::string const& member_out,
                                                     std::string const& member_in) const override;

private:
    shared< ReplDev > create_repl_dev_instance(superblk< repl_dev_superblk > const& rd_sb, bool load_existing);
    void rd_super_blk_found(sisl::byte_view const& buf, void* meta_cookie);
};

class ReplServiceCPHandler : public CPCallbacks {
public:
    ReplServiceCPHandler();
    virtual ~ReplServiceCPHandler() = default;

public:
    std::unique_ptr< CPContext > on_switchover_cp(CP* cur_cp, CP* new_cp) override;
    folly::Future< bool > cp_flush(CP* cp) override;
    void cp_cleanup(CP* cp) override;
    int cp_progress_percent() override;
};

extern ReplicationService& repl_service();
} // namespace homestore
