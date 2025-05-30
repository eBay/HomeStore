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
#include <homestore/logstore_service.hpp>
#include <boost/uuid/uuid.hpp>
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

GenericReplService::GenericReplService(cshared< ReplApplication >& repl_app) : m_repl_app{repl_app} {
    m_sb_bufs.reserve(100);
    meta_service().register_handler(
        get_meta_blk_name(),
        [this](meta_blk* mblk, sisl::byte_view buf, size_t) {
            m_sb_bufs.emplace_back(std::pair(std::move(buf), voidptr_cast(mblk)));
        },
        nullptr);
}

GenericReplService::~GenericReplService() {
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
SoloReplService::~SoloReplService(){};

void SoloReplService::start() {
    for (auto const& [buf, mblk] : m_sb_bufs) {
        load_repl_dev(buf, voidptr_cast(mblk));
    }
    m_sb_bufs.clear();

    LOGINFO("Repl devs load completed, calling upper layer on_repl_devs_init_completed");
    m_repl_app->on_repl_devs_init_completed();

    hs()->data_service().start();
    hs()->logstore_service().start(hs()->is_first_time_boot());

    // Register to CP to flush the super blk and truncate the logstore
    hs()->cp_mgr().register_consumer(cp_consumer_t::REPLICATION_SVC, std::make_unique< SoloReplServiceCPHandler >());
}

void SoloReplService::stop() {
    start_stopping();
    while (true) {
        auto pending_request_num = get_pending_request_num();
        if (!pending_request_num) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // stop all repl_devs
    {
        std::unique_lock lg(m_rd_map_mtx);
        for (auto it = m_rd_map.begin(); it != m_rd_map.end(); ++it) {
            auto rdev = std::dynamic_pointer_cast< SoloReplDev >(it->second);
            rdev->stop();
        }
    }
    hs()->logstore_service().stop();
    hs()->data_service().stop();
}

AsyncReplResult< shared< ReplDev > > SoloReplService::create_repl_dev(group_id_t group_id,
                                                                      std::set< replica_id_t > const& members) {
    superblk< repl_dev_superblk > rd_sb{get_meta_blk_name()};
    rd_sb.create();
    rd_sb->group_id = group_id;
    auto rdev = std::make_shared< SoloReplDev >(std::move(rd_sb), false /* load_existing */);

    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev);
    rdev->attach_listener(std::move(listener));
    incr_pending_request_num();

    {
        std::unique_lock lg(m_rd_map_mtx);
        auto [it, happened] = m_rd_map.emplace(group_id, rdev);
        if (!happened) {
            // We should never reach here, as we have failed to emplace in map, but couldn't find entry
            DEBUG_ASSERT(false, "Unable to put the repl_dev in rd map");
            decr_pending_request_num();
            return make_async_error< shared< ReplDev > >(ReplServiceError::SERVER_ALREADY_EXISTS);
        }
    }

    decr_pending_request_num();
    return make_async_success< shared< ReplDev > >(rdev);
}

folly::SemiFuture< ReplServiceError > SoloReplService::remove_repl_dev(group_id_t group_id) {
    // RD_LOGI("Removing repl dev for group_id={}", boost::uuids::to_string(group_id));
    auto rdev = get_repl_dev(group_id);
    if (rdev.hasError()) { return folly::makeSemiFuture(rdev.error()); }

    auto rdev_ptr = rdev.value();

    // 1. Firstly stop the repl dev which waits for any outstanding requests to finish
    rdev_ptr->stop();

    // 2. Destroy the repl dev which will remove the logstore and free the memory;
    dp_cast< SoloReplDev >(rdev_ptr)->destroy();

    // 3. detaches both ways:
    // detach rdev from its listener and listener from rdev;
    rdev_ptr->detach_listener();
    {
        // 4. remove from rd map which finally call SoloReplDev's destructor because this is the last one holding ref to
        // this instance;
        std::unique_lock lg(m_rd_map_mtx);
        m_rd_map.erase(group_id);
    }

    // 5. now destroy the upper layer's listener instance;
    m_repl_app->destroy_repl_dev_listener(group_id);

    return folly::makeSemiFuture(ReplServiceError::OK);
}

void SoloReplService::load_repl_dev(sisl::byte_view const& buf, void* meta_cookie) {
    superblk< repl_dev_superblk > rd_sb{get_meta_blk_name()};
    rd_sb.load(buf, meta_cookie);
    HS_DBG_ASSERT_EQ(rd_sb->get_magic(), repl_dev_superblk::REPL_DEV_SB_MAGIC, "Invalid rdev metablk, magic mismatch");
    HS_DBG_ASSERT_EQ(rd_sb->get_version(), repl_dev_superblk::REPL_DEV_SB_VERSION, "Invalid version of rdev metablk");
    group_id_t group_id = rd_sb->group_id;
    auto rdev = std::make_shared< SoloReplDev >(std::move(rd_sb), true /* load_existing */);

    auto listener = m_repl_app->create_repl_dev_listener(group_id);
    listener->set_repl_dev(rdev);
    rdev->attach_listener(std::move(listener));

    {
        std::unique_lock lg(m_rd_map_mtx);
        auto [_, happened] = m_rd_map.emplace(group_id, rdev);
        (void)happened;
        HS_DBG_ASSERT(happened, "Unable to put the repl_dev in rd map for group_id={}", group_id);
    }
}

AsyncReplResult<> SoloReplService::replace_member(group_id_t group_id, const replica_member_info& member_out,
                                                        const replica_member_info& member_in, uint32_t commit_quorum,
                                                        uint64_t trace_id) const {
    return make_async_error<>(ReplServiceError::NOT_IMPLEMENTED);
}

AsyncReplResult<> SoloReplService::flip_learner_flag(group_id_t group_id, const replica_member_info& member, bool target,
                                    uint32_t commit_quorum, bool wait_and_verify, uint64_t trace_id) const {
    return make_async_error<>(ReplServiceError::NOT_IMPLEMENTED);
}

std::unique_ptr< CPContext > SoloReplServiceCPHandler::on_switchover_cp(CP* cur_cp, CP* new_cp) {
    return std::make_unique< CPContext >(new_cp);
}

folly::Future< bool > SoloReplServiceCPHandler::cp_flush(CP* cp) {
    repl_service().iterate_repl_devs([cp](cshared< ReplDev >& repl_dev) {
        if (repl_dev) { dp_cast< SoloReplDev >(repl_dev)->cp_flush(cp); }
    });
    return folly::makeFuture< bool >(true);
}

void SoloReplServiceCPHandler::cp_cleanup(CP* cp) {
    repl_service().iterate_repl_devs([cp](cshared< ReplDev >& repl_dev) {
        if (repl_dev) { dp_cast< SoloReplDev >(repl_dev)->cp_cleanup(cp); }
    });
}

int SoloReplServiceCPHandler::cp_progress_percent() { return 100; }

} // namespace homestore
