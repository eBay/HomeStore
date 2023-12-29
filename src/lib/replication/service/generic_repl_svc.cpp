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
#include <homestore/blkdata_service.hpp>
#include "common/homestore_assert.hpp"
#include "replication/service/generic_repl_svc.h"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/solo_repl_dev.h"

namespace homestore {
ReplicationService& repl_service() { return hs()->repl_service(); }

std::shared_ptr< GenericReplService > GenericReplService::create(cshared< ReplApplication >& repl_app) {
    auto impl_type = repl_app->get_impl_type();
    if (impl_type == repl_impl_type::solo) {
        return std::make_shared< SoloReplService >(repl_app);
    } else if (impl_type == repl_impl_type::server_side) {
        return std::make_shared< RaftReplService >(repl_app);
    } else {
        return nullptr;
    }
}

GenericReplService::GenericReplService(cshared< ReplApplication >& repl_app) :
        m_repl_app{repl_app}, m_my_uuid{repl_app->get_my_repl_id()} {
    meta_service().register_handler(
        get_meta_blk_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t) { load_repl_dev(std::move(buf), voidptr_cast(mblk)); },
        nullptr);
}

void GenericReplService::stop() {
    std::unique_lock lg{m_rd_map_mtx};
    m_rd_map.clear();
}

ReplResult< shared< ReplDev > > GenericReplService::get_repl_dev(group_id_t group_id) const {
    std::shared_lock lg(m_rd_map_mtx);
    if (auto it = m_rd_map.find(group_id); it != m_rd_map.end()) { return it->second; }
    return folly::makeUnexpected(ReplServiceError::SERVER_NOT_FOUND);
}

void GenericReplService::iterate_repl_devs(std::function< void(cshared< ReplDev >&) > const& cb) {
    std::shared_lock lg(m_rd_map_mtx);
    for (const auto& [uuid, rd] : m_rd_map) {
        cb(rd);
    }
}

void GenericReplService::add_repl_dev(group_id_t group_id, shared< ReplDev > rdev) {
    std::unique_lock lg(m_rd_map_mtx);
    [[maybe_unused]] auto [it, happened] = m_rd_map.emplace(std::pair{group_id, rdev});
    HS_DBG_ASSERT(happened, "Unable to put the repl_dev in rd map for group_id={}, duplicated add?", group_id);
}

hs_stats GenericReplService::get_cap_stats() const {
    hs_stats stats;
    stats.total_capacity = data_service().get_total_capacity();
    stats.used_capacity = data_service().get_used_capacity();
    return stats;
}

///////////////////// SoloReplService specializations and CP Callbacks /////////////////////////////
SoloReplService::SoloReplService(cshared< ReplApplication >& repl_app) : GenericReplService{repl_app} {}

void SoloReplService::start() {
    // Register to CP to flush the super blk and truncate the logstore
    hs()->cp_mgr().register_consumer(cp_consumer_t::REPLICATION_SVC, std::make_unique< SoloReplServiceCPHandler >());
}

AsyncReplResult< shared< ReplDev > > SoloReplService::create_repl_dev(group_id_t group_id,
                                                                      std::set< replica_id_t > const& members) {
    superblk< repl_dev_superblk > rd_sb{get_meta_blk_name()};
    rd_sb.create();
    rd_sb->group_id = group_id;
    auto rdev = std::make_shared< SoloReplDev >(std::move(rd_sb), false /* load_existing */);

    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev.get());
    rdev->attach_listener(std::move(listener));

    {
        std::unique_lock lg(m_rd_map_mtx);
        auto [it, happened] = m_rd_map.emplace(group_id, rdev);
        if (!happened) {
            // We should never reach here, as we have failed to emplace in map, but couldn't find entry
            DEBUG_ASSERT(false, "Unable to put the repl_dev in rd map");
            return make_async_error< shared< ReplDev > >(ReplServiceError::SERVER_ALREADY_EXISTS);
        }
    }

    return make_async_success< shared< ReplDev > >(rdev);
}

void SoloReplService::load_repl_dev(sisl::byte_view const& buf, void* meta_cookie) {
    superblk< repl_dev_superblk > rd_sb{get_meta_blk_name()};
    rd_sb.load(buf, meta_cookie);
    HS_DBG_ASSERT_EQ(rd_sb->get_magic(), repl_dev_superblk::REPL_DEV_SB_MAGIC, "Invalid rdev metablk, magic mismatch");
    HS_DBG_ASSERT_EQ(rd_sb->get_version(), repl_dev_superblk::REPL_DEV_SB_VERSION, "Invalid version of rdev metablk");
    group_id_t group_id = rd_sb->group_id;
    auto rdev = std::make_shared< SoloReplDev >(std::move(rd_sb), true /* load_existing */);

    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev.get());
    rdev->attach_listener(std::move(listener));

    {
        std::unique_lock lg(m_rd_map_mtx);
        auto [it, happened] = m_rd_map.emplace(group_id, rdev);
        HS_DBG_ASSERT(happened, "Unable to put the repl_dev in rd map for group_id={}", group_id);
    }
}

AsyncReplResult<> SoloReplService::replace_member(group_id_t group_id, replica_id_t member_out,
                                                  replica_id_t member_in) const {
    return make_async_error<>(ReplServiceError::NOT_IMPLEMENTED);
}

std::unique_ptr< CPContext > SoloReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) { return nullptr; }

folly::Future< bool > SoloReplServiceCPHandler::cp_flush(CP* cp) {
    repl_service().iterate_repl_devs([cp](cshared< ReplDev >& repl_dev) {
        if (repl_dev) { std::dynamic_pointer_cast< SoloReplDev >(repl_dev)->cp_flush(cp); }
    });
    return folly::makeFuture< bool >(true);
}

void SoloReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_repl_devs([cp](cshared< ReplDev >& repl_dev) {
        if (repl_dev) { std::dynamic_pointer_cast< SoloReplDev >(repl_dev)->cp_cleanup(cp); }
    });
}

int SoloReplServiceCPHandler::cp_progress_percent() { return 100; }

} // namespace homestore
