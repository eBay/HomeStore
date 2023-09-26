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
#include <homestore/meta_service.hpp>
#include "common/homestore_assert.hpp"
#include "replication/service/repl_service_impl.h"
#include "replication/repl_dev/solo_repl_dev.h"

namespace homestore {
ReplicationService& repl_service() { return hs()->repl_service(); }

ReplicationServiceImpl::ReplicationServiceImpl(repl_impl_type impl_type) : m_repl_type{impl_type} {
    meta_service().register_handler(
        "repl_dev",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t) { rd_super_blk_found(std::move(buf), voidptr_cast(mblk)); },
        nullptr);
}

void ReplicationServiceImpl::start() {
    // Register to CP to flush the super blk and truncate the logstore
    hs()->cp_mgr().register_consumer(cp_consumer_t::REPLICATION_SVC, std::make_unique< ReplServiceCPHandler >());

    {
        std::shared_lock lg{m_rd_map_mtx};
        for (auto const& [gid, info] : m_pending_open) {
            // info.dev_promise.setValue(folly::makeUnexpected(ReplServiceError::SERVER_NOT_FOUND));
        }
    }
    m_rd_map_loaded = true;
}

void ReplicationServiceImpl::stop() {
    std::unique_lock lg{m_rd_map_mtx};
    m_rd_map.clear();
}

AsyncReplResult< shared< ReplDev > >
ReplicationServiceImpl::create_repl_dev(uuid_t group_id, std::set< std::string, std::less<> >&& members,
                                        std::unique_ptr< ReplDevListener > listener) {
    superblk< repl_dev_superblk > rd_sb{"repl_dev"};
    rd_sb.create(sizeof(repl_dev_superblk));
    rd_sb->gid = group_id;

    shared< ReplDev > repl_dev = create_repl_dev_instance(rd_sb, false /* load_existing */);
    listener->set_repl_dev(repl_dev.get());
    repl_dev->attach_listener(std::move(listener));
    rd_sb.write();
    return make_async_success(std::move(repl_dev));
}

AsyncReplResult< shared< ReplDev > >
ReplicationServiceImpl::open_repl_dev(uuid_t group_id, std::unique_ptr< ReplDevListener > listener) {
    if (m_rd_map_loaded) {
        // We have already loaded all repl_dev and open_repl_dev is called after that, we don't support dynamically
        // opening the repl_dev. Return an error
        LOGERROR("Opening group_id={} after services are started, which is not supported",
                 boost::uuids::to_string(group_id));
        return make_async_error< shared< ReplDev > >(ReplServiceError::BAD_REQUEST);
    }

    std::unique_lock lg(m_rd_map_mtx);
    auto it = m_rd_map.find(group_id);
    if (it != m_rd_map.end()) {
        // We already loaded the ReplDev, just call the group_id and attach the listener
        auto& repl_dev = it->second;
        listener->set_repl_dev(repl_dev.get());
        repl_dev->attach_listener(std::move(listener));
        return make_async_success< shared< ReplDev > >(std::move(repl_dev));
    } else {
        auto [pending_it, inserted] =
            m_pending_open.insert_or_assign(group_id, listener_info{.listener = std::move(listener)});
        DEBUG_ASSERT(inserted, "Duplicate open_replica_dev called for group_id = {}",
                     boost::uuids::to_string(group_id));
        return pending_it->second.dev_promise.getFuture();
    }
}

ReplResult< shared< ReplDev > > ReplicationServiceImpl::get_repl_dev(uuid_t group_id) const {
    std::shared_lock lg(m_rd_map_mtx);
    if (auto it = m_rd_map.find(group_id); it != m_rd_map.end()) { return it->second; }
    return folly::makeUnexpected(ReplServiceError::SERVER_NOT_FOUND);
}

void ReplicationServiceImpl::iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) {
    std::shared_lock lg(m_rd_map_mtx);
    for (const auto& [uuid, rd] : m_rd_map) {
        cb(rd);
    }
}

folly::Future< ReplServiceError > ReplicationServiceImpl::replace_member(uuid_t group_id, std::string const& member_out,
                                                                         std::string const& member_in) const {
    return folly::makeFuture< ReplServiceError >(ReplServiceError::NOT_IMPLEMENTED);
}

shared< ReplDev > ReplicationServiceImpl::create_repl_dev_instance(superblk< repl_dev_superblk > const& rd_sb,
                                                                   bool load_existing) {
    auto it = m_rd_map.end();
    bool happened = false;

    {
        std::unique_lock lg(m_rd_map_mtx);
        std::tie(it, happened) = m_rd_map.emplace(std::make_pair(rd_sb->gid, nullptr));
    }
    DEBUG_ASSERT(m_rd_map.end() != it, "Could not insert into map!");
    if (!happened) { return it->second; }

    shared< ReplDev > repl_dev;
    if (m_repl_type == repl_impl_type::solo) {
        repl_dev = std::make_shared< SoloReplDev >(rd_sb, load_existing);
    } else {
        HS_REL_ASSERT(false, "Repl impl type = {} is not supported yet", enum_name(m_repl_type));
    }
    it->second = repl_dev;

    return repl_dev;
}

void ReplicationServiceImpl::rd_super_blk_found(sisl::byte_view const& buf, void* meta_cookie) {
    superblk< repl_dev_superblk > rd_sb;
    rd_sb.load(buf, meta_cookie);
    HS_DBG_ASSERT_EQ(rd_sb->get_magic(), repl_dev_superblk::REPL_DEV_SB_MAGIC, "Invalid rdev metablk, magic mismatch");
    HS_DBG_ASSERT_EQ(rd_sb->get_version(), repl_dev_superblk::REPL_DEV_SB_VERSION, "Invalid version of rdev metablk");

    shared< ReplDev > repl_dev = create_repl_dev_instance(rd_sb, true /* load_existing */);
    {
        std::unique_lock lg(m_rd_map_mtx);
        auto it = m_pending_open.find(rd_sb->gid);
        if (it != m_pending_open.end()) {
            auto& li_info = it->second;
            // Someone waiting for this repl dev to open, call them to attach the listener and provide the value
            li_info.listener->set_repl_dev(repl_dev.get());
            repl_dev->attach_listener(std::move(li_info.listener));
            li_info.dev_promise.setValue(repl_dev);
            m_pending_open.erase(it);
        }
    }
}

///////////////////// CP Callbacks for Repl Service //////////////
ReplServiceCPHandler::ReplServiceCPHandler() {}

std::unique_ptr< CPContext > ReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) { return nullptr; }

folly::Future< bool > ReplServiceCPHandler::cp_flush(CP* cp) {
    repl_service().iterate_repl_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::dynamic_pointer_cast< SoloReplDev >(repl_dev)->cp_flush(cp); });
    return folly::makeFuture< bool >(true);
}

void ReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_repl_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::dynamic_pointer_cast< SoloReplDev >(repl_dev)->cp_cleanup(cp); });
}

int ReplServiceCPHandler::cp_progress_percent() { return 100; }

} // namespace homestore
