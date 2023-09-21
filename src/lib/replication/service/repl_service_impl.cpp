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
ReplicationServiceImpl& repl_service() { return hs()->repl_service(); }

ReplicationServiceImpl::ReplicationServiceImpl(repl_impl_type impl_type, std::unique_ptr< ReplServiceCallbacks > cbs) :
        m_svc_cbs{std::move(cbs)}, m_repl_type{impl_type} {
    meta_service().register_handler(
        "replication",
        [this](meta_blk* mblk, sisl::byte_view buf, size_t) { rd_super_blk_found(std::move(buf), voidptr_cast(mblk)); },
        nullptr);
}

void ReplicationServiceImpl::start() {
    // Register to CP to flush the super blk and truncate the logstore
    hs()->cp_mgr().register_consumer(cp_consumer_t::REPLICATION_SVC, std::make_unique< ReplServiceCPHandler >());
}

void ReplicationServiceImpl::stop() {
    std::unique_lock lg{m_rd_map_mtx};
    m_rd_map.clear();
}

AsyncReplResult< shared< ReplDev > >
ReplicationServiceImpl::create_replica_dev(uuid_t group_id, std::set< std::string, std::less<> >&& members) {
    superblk< repl_dev_superblk > rd_sb;
    rd_sb.create(sizeof(repl_dev_superblk));
    rd_sb->gid = group_id;

    shared< ReplDev > repl_dev = open_replica_dev(rd_sb, false /* load_existing */);
    return folly::makeSemiFuture< ReplResult< shared< ReplDev > > >(std::move(repl_dev));
}

ReplResult< shared< ReplDev > > ReplicationServiceImpl::get_replica_dev(uuid_t group_id) const {
    std::shared_lock lg(m_rd_map_mtx);
    if (auto it = m_rd_map.find(group_id); it != m_rd_map.end()) { return it->second; }
    return folly::makeUnexpected(ReplServiceError::SERVER_NOT_FOUND);
}

void ReplicationServiceImpl::iterate_replica_devs(std::function< void(cshared< ReplDev >&) > const& cb) {
    std::shared_lock lg(m_rd_map_mtx);
    for (const auto& [uuid, rd] : m_rd_map) {
        cb(rd);
    }
}

folly::SemiFuture< ReplServiceError > ReplicationServiceImpl::replace_member(uuid_t group_id,
                                                                             std::string const& member_out,
                                                                             std::string const& member_in) const {
    return folly::makeSemiFuture< ReplServiceError >(ReplServiceError::NOT_IMPLEMENTED);
}

shared< ReplDev > ReplicationServiceImpl::open_replica_dev(superblk< repl_dev_superblk > const& rd_sb,
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
    repl_dev->attach_listener(m_svc_cbs->on_repl_dev_init(repl_dev));
    it->second = repl_dev;

    return repl_dev;
}

void ReplicationServiceImpl::rd_super_blk_found(sisl::byte_view const& buf, void* meta_cookie) {
    superblk< repl_dev_superblk > rd_sb;
    rd_sb.load(buf, meta_cookie);
    HS_DBG_ASSERT_EQ(rd_sb->get_magic(), repl_dev_superblk::REPL_DEV_SB_MAGIC, "Invalid rdev metablk, magic mismatch");
    HS_DBG_ASSERT_EQ(rd_sb->get_version(), repl_dev_superblk::REPL_DEV_SB_VERSION, "Invalid version of rdev metablk");

    open_replica_dev(rd_sb, true /* load_existing */);
}

///////////////////// CP Callbacks for Repl Service //////////////
ReplServiceCPHandler::ReplServiceCPHandler() {}

std::unique_ptr< CPContext > ReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) { return nullptr; }

folly::Future< bool > ReplServiceCPHandler::cp_flush(CP* cp) {
    repl_service().iterate_replica_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::dynamic_pointer_cast< SoloReplDev >(repl_dev)->cp_flush(cp); });
    return folly::makeFuture< bool >(true);
}

void ReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_replica_devs(
        [cp](cshared< ReplDev >& repl_dev) { std::dynamic_pointer_cast< SoloReplDev >(repl_dev)->cp_cleanup(cp); });
}

int ReplServiceCPHandler::cp_progress_percent() { return 100; }

} // namespace homestore
