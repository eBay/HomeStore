#include <flatbuffers/idl.h>
#include <flatbuffers/minireflect.h>
#include <folly/executors/InlineExecutor.h>
#include <iomgr/iomgr_flip.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/nil_generator.hpp>

#include <sisl/fds/buffer.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <sisl/grpc/rpc_client.hpp>
#include <sisl/fds/vector_pool.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/superblk_handler.hpp>

#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
// #include "common/homestore_flip.hpp"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/raft_repl_dev.h"
#include "push_data_rpc_generated.h"
#include "fetch_data_rpc_generated.h"

namespace homestore {
std::atomic< uint64_t > RaftReplDev::s_next_group_ordinal{1};

RaftReplDev::RaftReplDev(RaftReplService& svc, superblk< raft_repl_dev_superblk >&& rd_sb, bool load_existing) :
        m_repl_svc{svc},
        m_msg_mgr{svc.msg_manager()},
        m_group_id{rd_sb->group_id},
        m_my_repl_id{svc.get_my_repl_uuid()},
        m_raft_server_id{nuraft_mesg::to_server_id(m_my_repl_id)},
        m_rd_sb{std::move(rd_sb)},
        m_metrics{fmt::format("{}_{}", group_id_str(), m_raft_server_id).c_str()} {
    m_state_machine = std::make_shared< RaftStateMachine >(*this);

    if (load_existing) {
        m_data_journal =
            std::make_shared< ReplLogStore >(*this, *m_state_machine, m_rd_sb->logdev_id, m_rd_sb->logstore_id);
        m_next_dsn = m_rd_sb->last_applied_dsn + 1;
        m_commit_upto_lsn = m_rd_sb->commit_lsn;
        m_last_flushed_commit_lsn = m_commit_upto_lsn;
        m_compact_lsn = m_rd_sb->compact_lsn;

        m_rdev_name = fmt::format("rdev{}", m_rd_sb->group_ordinal);

        // Its ok not to do compare exchange, because loading is always single threaded as of now
        if (m_rd_sb->group_ordinal >= s_next_group_ordinal.load()) {
            s_next_group_ordinal.store(m_rd_sb->group_ordinal + 1);
        }

        if (m_rd_sb->is_timeline_consistent) {
            logstore_service()
                .open_log_store(m_rd_sb->logdev_id, m_rd_sb->free_blks_journal_id, false)
                .thenValue([this](auto log_store) {
                    m_free_blks_journal = std::move(log_store);
                    m_rd_sb->free_blks_journal_id = m_free_blks_journal->get_store_id();
                });
        }
    } else {
        m_data_journal = std::make_shared< ReplLogStore >(*this, *m_state_machine);
        m_rd_sb->logdev_id = m_data_journal->logdev_id();
        m_rd_sb->logstore_id = m_data_journal->logstore_id();
        m_rd_sb->last_applied_dsn = 0;
        m_rd_sb->group_ordinal = s_next_group_ordinal.fetch_add(1);
        m_rdev_name = fmt::format("rdev{}", m_rd_sb->group_ordinal);

        if (m_rd_sb->is_timeline_consistent) {
            m_free_blks_journal = logstore_service().create_new_log_store(m_rd_sb->logdev_id, false /* append_mode */);
            m_rd_sb->free_blks_journal_id = m_free_blks_journal->get_store_id();
        }
        m_rd_sb.write();
    }

    RD_LOG(INFO,
           "Started {} RaftReplDev group_id={}, replica_id={}, raft_server_id={} commited_lsn={} next_dsn={} "
           "log_dev={} log_store={}",
           (load_existing ? "Existing" : "New"), group_id_str(), my_replica_id_str(), m_raft_server_id,
           m_commit_upto_lsn.load(), m_next_dsn.load(), m_rd_sb->logdev_id, m_rd_sb->logstore_id);

#ifdef _PRERELEASE
    m_msg_mgr.bind_data_service_request(PUSH_DATA, m_group_id, [this](intrusive< sisl::GenericRpcData >& rpc_data) {
        if (iomgr_flip::instance()->delay_flip("slow_down_data_channel", [this, rpc_data]() mutable {
                RD_LOGI("Resuming after slow down data channel flip");
                on_push_data_received(rpc_data);
            })) {
            RD_LOGI("Slow down data channel flip is enabled, scheduling to call later");
        } else {
            on_push_data_received(rpc_data);
        }
    });
#else
    m_msg_mgr.bind_data_service_request(PUSH_DATA, m_group_id, bind_this(RaftReplDev::on_push_data_received, 1));
#endif

    m_msg_mgr.bind_data_service_request(FETCH_DATA, m_group_id, bind_this(RaftReplDev::on_fetch_data_received, 1));
}

bool RaftReplDev::join_group() {
    auto raft_result =
        m_msg_mgr.join_group(m_group_id, "homestore_replication",
                             std::dynamic_pointer_cast< nuraft_mesg::mesg_state_mgr >(shared_from_this()));
    if (!raft_result) {
        HS_DBG_ASSERT(false, "Unable to join the group_id={} with error={}", boost::uuids::to_string(m_group_id),
                      raft_result.error());
        return false;
    }
    return true;
}

folly::SemiFuture< ReplServiceError > RaftReplDev::destroy_group() {
    // Set the intent to destroy the group
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::DESTROYING; });

    // Propose to the group to destroy
    auto rreq = repl_req_ptr_t(new repl_req_ctx{});
    rreq->init(journal_type_t::HS_CTRL_DESTROY);

    auto err = m_state_machine->propose_to_raft(std::move(rreq));
    if (err != ReplServiceError::OK) {
        m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::ACTIVE; });
        return folly::makeSemiFuture< ReplServiceError >(std::move(err));
    }

    return m_destroy_promise.getSemiFuture();
}

void RaftReplDev::use_config(json_superblk raft_config_sb) { m_raft_config_sb = std::move(raft_config_sb); }

<<<<<<< HEAD
void RaftReplDev::on_create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    RD_LOG(DEBUG, "create_snapshot last_idx={}/term={}", s.get_last_log_idx(), s.get_last_log_term());
    repl_snapshot snapshot{.last_log_idx_ = s.get_last_log_idx(), .last_log_term_ = s.get_last_log_term()};
    auto result = m_listener->create_snapshot(snapshot).get();
    auto null_except = std::shared_ptr< std::exception >();
    HS_REL_ASSERT(result.hasError() == false, "Not expecting creating snapshot to return false. ");
    m_last_snapshot = nuraft::cs_new< nuraft::snapshot >(s.get_last_log_idx(), s.get_last_log_term(),
                                                         s.get_last_config(), s.size(), s.get_type());
    auto ret_val{true};
    if (when_done) { when_done(ret_val, null_except); }
}

void RaftReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
=======
void RaftReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& data,
>>>>>>> 4a0dc261 (Added remove repl_dev and made repl_req much more contained)
                                    repl_req_ptr_t rreq) {
    if (!rreq) { auto rreq = repl_req_ptr_t(new repl_req_ctx{}); }

    auto const guard = m_stage.access();
    if (auto const stage = *guard.get(); stage != repl_dev_stage_t::ACTIVE) {
        RD_LOGW("Raft channel: Not ready to accept writes, stage={}", enum_name(stage));
        handle_error(rreq,
                     (stage == repl_dev_stage_t::INIT) ? ReplServiceError::SERVER_IS_JOINING
                                                       : ReplServiceError::SERVER_IS_LEAVING);
        return;
    }

    rreq->init(repl_key{.server_id = server_id(), .term = raft_server()->get_term(), .dsn = m_next_dsn.fetch_add(1)},
               true /* is_proposer */, header, key, data.size);

    // Add the request to the repl_dev_rreq map, it will be accessed throughout the life cycle of this request
    auto const [it, happened] = m_repl_key_req_map.emplace(rreq->rkey(), rreq);
    RD_DBG_ASSERT(happened, "Duplicate repl_key={} found in the map", rreq->rkey().to_string());

    // If it is header only entry, directly propose to the raft
    if (rreq->has_linked_data()) {
        push_data_to_all_followers(rreq, data);

        // Step 1: Alloc Blkid
        auto const status = rreq->alloc_local_blks(m_listener, data.size);
        if (status != ReplServiceError::OK) {
            RD_LOGD("Allocating blks failed error={}, failing this req", status);
            handle_error(rreq, status);
            return;
        }

        // Write the data
        data_service().async_write(data, rreq->local_blkid()).thenValue([this, rreq](auto&& err) {
            if (err) {
                HS_DBG_ASSERT(false, "Error in writing data, err_code={}", err.value());
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            } else {
                auto raft_status = m_state_machine->propose_to_raft(rreq);
                if (raft_status != ReplServiceError::OK) { handle_error(rreq, raft_status); }
            }
        });
    } else {
        RD_LOGD("Skipping data channel send since value size is 0");
        rreq->add_state(repl_req_state_t::DATA_WRITTEN);
        auto raft_status = m_state_machine->propose_to_raft(rreq);
        if (raft_status != ReplServiceError::OK) { handle_error(rreq, raft_status); }
    }
}

void RaftReplDev::push_data_to_all_followers(repl_req_ptr_t rreq, sisl::sg_list const& data) {
    auto& builder = rreq->create_fb_builder();

    // Prepare the rpc request packet with all repl_reqs details
    builder.FinishSizePrefixed(
        CreatePushDataRequest(builder, server_id(), rreq->term(), rreq->dsn(),
                              builder.CreateVector(rreq->header().cbytes(), rreq->header().size()),
                              builder.CreateVector(rreq->key().cbytes(), rreq->key().size()), data.size));

    rreq->m_pkts = sisl::io_blob::sg_list_to_ioblob_list(data);
    rreq->m_pkts.insert(rreq->m_pkts.begin(), sisl::io_blob{builder.GetBufferPointer(), builder.GetSize(), false});

    /*RD_LOGI("Data Channel: Pushing data to all followers: rreq=[{}] data=[{}]", rreq->to_string(),
           flatbuffers::FlatBufferToString(builder.GetBufferPointer() + sizeof(flatbuffers::uoffset_t),
                                           PushDataRequestTypeTable()));*/

    RD_LOGD("Data Channel: Pushing data to all followers: rreq=[{}]", rreq->to_compact_string());

    group_msg_service()
        ->data_service_request_unidirectional(nuraft_mesg::role_regex::ALL, PUSH_DATA, rreq->m_pkts)
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, rreq = std::move(rreq)](auto e) {
            if (e.hasError()) {
                RD_LOGE("Data Channel: Error in pushing data to all followers: rreq=[{}] error={}",
                        rreq->to_compact_string(), e.error());
                handle_error(rreq, RaftReplService::to_repl_error(e.error()));
                return;
            }
            // Release the buffer which holds the packets
            RD_LOGD("Data Channel: Data push completed for rreq=[{}]", rreq->to_compact_string());
            rreq->release_fb_builder();
            rreq->m_pkts.clear();
        });
}

void RaftReplDev::on_push_data_received(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto const& incoming_buf = rpc_data->request_blob();
    auto const fb_size =
        flatbuffers::ReadScalar< flatbuffers::uoffset_t >(incoming_buf.cbytes()) + sizeof(flatbuffers::uoffset_t);
    auto push_req = GetSizePrefixedPushDataRequest(incoming_buf.cbytes());
    HS_DBG_ASSERT_EQ(fb_size + push_req->data_size(), incoming_buf.size(), "Size mismatch of data size vs buffer size");

    sisl::blob header = sisl::blob{push_req->user_header()->Data(), push_req->user_header()->size()};
    sisl::blob key = sisl::blob{push_req->user_key()->Data(), push_req->user_key()->size()};
    repl_key rkey{.server_id = push_req->issuer_replica_id(), .term = push_req->raft_term(), .dsn = push_req->dsn()};

#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("drop_push_data_request")) {
        LOGINFO("Data Channel: Flip is enabled, skip on_push_data_received to simulate fetch remote data, "
                "server_id={}, term={}, dsn={}",
                push_req->issuer_replica_id(), push_req->raft_term(), push_req->dsn());
        return;
    }
#endif

    auto rreq = applier_create_req(rkey, header, key, push_req->data_size(), true /* is_data_channel */);
    if (rreq == nullptr) {
        RD_LOG(ERROR,
               "Data Channel: Creating rreq on applier has failed, will ignore the push and let Raft channel send "
               "trigger a fetch explicitly if needed. rkey={}",
               rkey.to_string());
        return;
    }

    if (!rreq->save_pushed_data(rpc_data, incoming_buf.cbytes() + fb_size, push_req->data_size())) {
        RD_LOGD("Data Channel: Data already received for rreq=[{}], ignoring this data", rreq->to_compact_string());
        return;
    }

    // Schedule a write and upon completion, mark the data as written.
    data_service()
        .async_write(r_cast< const char* >(rreq->data()), push_req->data_size(), rreq->local_blkid())
        .thenValue([this, rreq](auto&& err) {
            if (err) {
                COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
                RD_DBG_ASSERT(false, "Error in writing data, error_code={}", err.value());
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            } else {
                rreq->add_state(repl_req_state_t::DATA_WRITTEN);
                rreq->m_data_written_promise.setValue();
                RD_LOGD("Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
            }
        });
}

repl_req_ptr_t RaftReplDev::applier_create_req(repl_key const& rkey, sisl::blob const& user_header,
                                               sisl::blob const& key, uint32_t data_size,
                                               [[maybe_unused]] bool is_data_channel) {
    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT((it != m_repl_key_req_map.end()), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;

    if (!happened) {
        // We already have the entry in the map, check if we are already allocated the blk by previous caller, in
        // that case we need to return the req.
        if (rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) {
            // Do validation if we have the correct mapping
            // RD_REL_ASSERT(blob_equals(user_header, rreq->header), "User header mismatch for repl_key={}",
            //              rkey.to_string());
            // RD_REL_ASSERT(blob_equals(user_key, rreq->key), "User key mismatch for repl_key={}", rkey.to_string());
            RD_LOGD("Repl_key=[{}] already received  ", rkey.to_string());
            return rreq;
        }
    }

    rreq->init(rkey, false /* is_proposer */, user_header, key, data_size);

    // There is no data portion, so there is not need to allocate
    if (!rreq->has_linked_data()) { return rreq; }

    // We need to allocate the block, since entry doesn't exist or if it exist, two threads are trying to do the same
    // thing. So take state mutex and allocate the blk
    std::unique_lock< std::mutex > lg(rreq->m_state_mtx);
    if (rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) { return rreq; }

    auto alloc_status = rreq->alloc_local_blks(m_listener, data_size);
#ifdef _PRERELEASE
    if (is_data_channel) {
        if (iomgr_flip::instance()->test_flip("fake_reject_append_data_channel")) {
            LOGINFO("Data Channel: Reject append_entries flip is triggered for rkey={}", rkey.to_string());
            alloc_status = ReplServiceError::NO_SPACE_LEFT;
        }
    } else {
        if (iomgr_flip::instance()->test_flip("fake_reject_append_raft_channel")) {
            LOGINFO("Raft Channel: Reject append_entries flip is triggered for rkey={}", rkey.to_string());
            alloc_status = ReplServiceError::NO_SPACE_LEFT;
        }
    }
#endif

    if (alloc_status != ReplServiceError::OK) {
        RD_LOGE("For Repl_key=[{}] alloc hints returned error={}, failing this req", rkey.to_string(), alloc_status);
        // Do not call handle_error here, because handle_error is for rreq which needs to be terminated. This one can be
        // retried.
        return nullptr;
    }

    RD_LOGD("in follower_create_req: rreq={}, addr={}", rreq->to_compact_string(),
            reinterpret_cast< uintptr_t >(rreq.get()));
    return rreq;
}

folly::Future< folly::Unit > RaftReplDev::notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs) {
    std::vector< folly::Future< folly::Unit > > futs;
    futs.reserve(rreqs->size());
    std::vector< repl_req_ptr_t > unreceived_data_reqs;

    // Walk through the list of requests and wait for the data to be received and written
    for (auto const& rreq : *rreqs) {
        if ((rreq == nullptr) || (!rreq->has_linked_data())) { continue; }
        auto const status = uint32_cast(rreq->state());
        if (status & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
            RD_LOGD("Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_compact_string());
            continue;
        }

        if (!(status & uint32_cast(repl_req_state_t::DATA_RECEIVED))) {
            // This is a relatively rare scenario which can happen, where the data is not received or localized yet,
            // because it was called as part of pack/unpack i.e bulk data transfer for a new replica. For these
            // cases, the first step of localization doesn't happen (because raft isn't going to give us
            // append_entry handler callback). Hence we do that step of receiving data now. The same scenario can
            // happen in case of leader is not the propose (i.e raft forwarding is enabled)
            unreceived_data_reqs.emplace_back(rreq);
        } else {
            futs.emplace_back(rreq->m_data_written_promise.getFuture());
        }
    }

    if (!unreceived_data_reqs.empty()) {
        // Wait 10 times the actual data fetch timeout during normal scenario. We do that because, unlike in normal
        // scenario where can reject the append and let raft retry the log_entry send (which will cause fetch
        // retry), this flow can't fail or reject. So only option is to wait longer and if it fails, either a) Crash
        // this node and let addition of new raft server fail (or) b) Make this node is unavailable for read and
        // allow it to write (which is an incorrect data) and let remediation flow, replace this node. This atleast
        // allow other repl_dev's in the system accessibly instead of crashing the entire node.
        //
        // TODO: We are doing option a) now, but we should support option b)
        if (!wait_for_data_receive(unreceived_data_reqs, HS_DYNAMIC_CONFIG(consensus.data_receive_timeout_ms) * 10)) {
            HS_REL_ASSERT(false, "Data fetch timeout, should not happen");
        }
        for (auto const& rreq : unreceived_data_reqs) {
            futs.emplace_back(rreq->m_data_written_promise.getFuture());
        }
    }

    // All the entries are done already, no need to wait
    if (futs.size() == 0) { return folly::makeFuture< folly::Unit >(folly::Unit{}); }

    return folly::collectAllUnsafe(futs).thenValue([this, rreqs](auto&& e) {
#ifndef NDEBUG
        for (auto const& rreq : *rreqs) {
            if ((rreq == nullptr) || (!rreq->has_linked_data())) { continue; }
            HS_DBG_ASSERT(rreq->has_state(repl_req_state_t::DATA_WRITTEN),
                          "Data written promise raised without updating DATA_WRITTEN state for rkey={}",
                          rreq->rkey().to_string());
            RD_LOGD("Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_compact_string());
        }
#endif
        RD_LOGT("Data Channel: {} pending reqs's data are written", rreqs->size());
        return folly::makeFuture< folly::Unit >(folly::Unit{});
    });
}

bool RaftReplDev::wait_for_data_receive(std::vector< repl_req_ptr_t > const& rreqs, uint64_t timeout_ms) {
    std::vector< folly::Future< folly::Unit > > futs;
    std::vector< repl_req_ptr_t > only_wait_reqs;
    only_wait_reqs.reserve(rreqs.size());
    futs.reserve(rreqs.size());

    for (auto const& rreq : rreqs) {
        if ((rreq == nullptr) || (!rreq->has_linked_data()) || (rreq->has_state(repl_req_state_t::DATA_RECEIVED))) {
            continue;
        }
        only_wait_reqs.emplace_back(rreq);
        futs.emplace_back(rreq->m_data_received_promise.getFuture());
    }

    // All the data has been received already, no need to wait
    if (futs.size() == 0) { return true; }

    // If we are currently in resync mode, we can fetch the data immediately. Otherwise, stage it and wait for
    // sometime before do an explicit fetch. This is so that, it is possible raft channel has come ahead of data
    // channel and waiting for sometime avoid expensive fetch. On steady state, after a little bit of wait data
    // would be reached automatically.
    RD_LOG(DEBUG,
           "We haven't received data for {} out {} in reqs batch, will fetch and wait for {} ms, in_resync_mode()={} ",
           only_wait_reqs.size(), rreqs.size(), timeout_ms, is_resync_mode());

    // We are yet to support reactive fetch from remote.
    if (is_resync_mode()) {
        check_and_fetch_remote_data(std::move(only_wait_reqs));
    } else {
        m_repl_svc.add_to_fetch_queue(shared_from_this(), std::move(only_wait_reqs));
    }

    // block waiting here until all the futs are ready (data channel filled in and promises are made);
    auto all_futs = folly::collectAllUnsafe(futs).wait(std::chrono::milliseconds(timeout_ms));
    return (all_futs.isReady());
}

void RaftReplDev::check_and_fetch_remote_data(std::vector< repl_req_ptr_t > rreqs) {
    auto total_size_to_fetch = 0ul;
    std::vector< repl_req_ptr_t > next_batch_rreqs;
    auto const max_batch_size = HS_DYNAMIC_CONFIG(consensus.data_fetch_max_size_kb) * 1024ull;
    auto const originator = rreqs.front()->remote_blkid().server_id;

    for (auto const& rreq : rreqs) {
        auto const cur_state = uint32_cast(rreq->state());
        if (cur_state == uint32_cast(repl_req_state_t::ERRORED)) {
            // We already received the data before, just ignore this data
            RD_LOGD("Raft Channel: rreq=[{}] already errored out, ignoring the fetch", rreq->to_compact_string());
            continue;
        } else if (cur_state == uint32_cast(repl_req_state_t::DATA_RECEIVED)) {
            // We already received the data before, just ignore this data
            RD_LOGD("Raft Channel: Data already received for rreq=[{}], ignoring the fetch", rreq->to_compact_string());
            continue;
        }

        RD_REL_ASSERT_EQ(
            rreq->remote_blkid().server_id, originator,
            "Batch of remote pull has different originator, not expected, continuing can cause data corruption");

        auto const size = rreq->remote_blkid().blkid.blk_count() * get_blk_size();
        if ((total_size_to_fetch + size) >= max_batch_size) {
            fetch_data_from_remote(std::move(next_batch_rreqs));
            next_batch_rreqs.clear();
            total_size_to_fetch = 0;
        }

        total_size_to_fetch += size;
        next_batch_rreqs.emplace_back(rreq);
    }
    fetch_data_from_remote(std::move(next_batch_rreqs));
}

void RaftReplDev::fetch_data_from_remote(std::vector< repl_req_ptr_t > rreqs) {
    if (rreqs.size() == 0) { return; }

    std::vector< ::flatbuffers::Offset< RequestEntry > > entries;
    entries.reserve(rreqs.size());

    shared< flatbuffers::FlatBufferBuilder > builder = std::make_shared< flatbuffers::FlatBufferBuilder >();
    RD_LOGD("Data Channel : FetchData from remote: rreq.size={}, my server_id={}", rreqs.size(), server_id());
    auto const& originator = rreqs.front()->remote_blkid().server_id;

    for (auto const& rreq : rreqs) {
        entries.push_back(CreateRequestEntry(*builder, rreq->lsn(), rreq->term(), rreq->dsn(),
                                             builder->CreateVector(rreq->header().cbytes(), rreq->header().size()),
                                             builder->CreateVector(rreq->key().cbytes(), rreq->key().size()),
                                             rreq->remote_blkid().server_id /* blkid_originator */,
                                             builder->CreateVector(rreq->remote_blkid().blkid.serialize().cbytes(),
                                                                   rreq->remote_blkid().blkid.serialized_size())));
        // relax this assert if there is a case in same batch originator can be different (can't think of one now)
        // but if there were to be such case, we need to group rreqs by originator and send them in separate
        // batches;
        RD_DBG_ASSERT_EQ(rreq->remote_blkid().server_id, originator, "Unexpected originator for rreq={}",
                         rreq->to_compact_string());

        RD_LOGT("Fetching data from originator={}, remote: rreq=[{}], remote_blkid={}, my server_id={}", originator,
                rreq->to_compact_string(), rreq->remote_blkid().blkid.to_string(), server_id());
    }

    builder->FinishSizePrefixed(
        CreateFetchData(*builder, CreateFetchDataRequest(*builder, builder->CreateVector(entries))));

    COUNTER_INCREMENT(m_metrics, fetch_rreq_cnt, 1);
    COUNTER_INCREMENT(m_metrics, fetch_total_entries_cnt, rreqs.size());

    // leader can change, on the receiving side, we need to check if the leader is still the one who originated the
    // blkid;
    group_msg_service()
        ->data_service_request_bidirectional(
            originator, FETCH_DATA,
            sisl::io_blob_list_t{
                sisl::io_blob{builder->GetBufferPointer(), builder->GetSize(), false /* is_aligned */}})
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, builder, rreqs = std::move(rreqs)](auto response) {
            if (!response) {
                // if we are here, it means the original who sent the log entries are down.
                // we need to handle error and when the other member becomes leader, it will resend the log entries;
                RD_LOG(ERROR,
                       "Not able to fetching data from originator={}, error={}, probably originator is down. Will "
                       "retry when new leader start appending log entries",
                       rreqs.front()->remote_blkid().server_id, response.error());
                for (auto const& rreq : rreqs) {
                    // TODO: Set the data_received promise with error, so that waiting threads can be unblocked and
                    // reject the request. Without that, it will timeout and then reject it.

                    // We could have get to a scenario, where didn't receive the data at the time of fetch, but we
                    // received after issuing fetch and that leader has already switched. In this case, we don't want to
                    // fail the request.
                    if (!rreq->has_state(repl_req_state_t::DATA_RECEIVED)) {
                        handle_error(rreq, RaftReplService::to_repl_error(response.error()));
                    }
                }
                COUNTER_INCREMENT(m_metrics, fetch_err_cnt, 1);
                return;
            }

            builder->Release();

            iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                                    [this, r = std::move(response.value()), rreqs = std::move(rreqs)]() {
                                        handle_fetch_data_response(std::move(r), std::move(rreqs));
                                    });
        });
}

void RaftReplDev::on_fetch_data_received(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto const& incoming_buf = rpc_data->request_blob();
    auto fetch_req = GetSizePrefixedFetchData(incoming_buf.cbytes());

    RD_LOGD("Data Channel: FetchData received: fetch_req.size={}", fetch_req->request()->entries()->size());

    std::vector< sisl::sg_list > sgs_vec;
    std::vector< folly::Future< bool > > futs;
    sgs_vec.reserve(fetch_req->request()->entries()->size());
    futs.reserve(fetch_req->request()->entries()->size());

    for (auto const& req : *(fetch_req->request()->entries())) {
        auto const& lsn = req->lsn();
        auto const& originator = req->blkid_originator();
        auto const& remote_blkid = req->remote_blkid();

        // release this assert if in the future we want to fetch from non-originator;
        RD_REL_ASSERT_EQ(originator, server_id(),
                         "Not expect to receive fetch data from remote when I am not the originator of this request");

        // fetch data based on the remote_blkid
        if (originator == server_id()) {
            // We are the originator of the blkid, read data locally;
            MultiBlkId local_blkid;

            // convert remote_blkid serialized data to local blkid
            local_blkid.deserialize(sisl::blob{remote_blkid->Data(), remote_blkid->size()}, true /* copy */);

            RD_LOGD("Data Channel: FetchData received: dsn={} lsn={} my_blkid={}", req->dsn(), lsn,
                    local_blkid.to_string());

            // prepare the sgs data buffer to read into;
            auto const total_size = local_blkid.blk_count() * get_blk_size();
            sisl::sg_list sgs;
            sgs.size = total_size;
            sgs.iovs.emplace_back(
                iovec{.iov_base = iomanager.iobuf_alloc(get_blk_size(), total_size), .iov_len = total_size});

            // accumulate the sgs for later use (send back to the requester));
            sgs_vec.push_back(sgs);
            futs.emplace_back(async_read(local_blkid, sgs, total_size));
        }
    }

    folly::collectAllUnsafe(futs).thenValue(
        [this, rpc_data = std::move(rpc_data), sgs_vec = std::move(sgs_vec)](auto&& vf) {
            for (auto const& err_c : vf) {
                if (sisl_unlikely(err_c.value())) {
                    COUNTER_INCREMENT(m_metrics, read_err_cnt, 1);
                    RD_REL_ASSERT(false, "Error in reading data");
                    // TODO: Find a way to return error to the Listener
                    // TODO: actually will never arrive here as iomgr will assert
                    // (should not assert but to raise alert and leave the raft group);
                }
            }

            RD_LOGD("Data Channel: FetchData data read completed for {} buffers", sgs_vec.size());

            // now prepare the io_blob_list to response back to requester;
            nuraft_mesg::io_blob_list_t pkts = sisl::io_blob_list_t{};
            for (auto const& sgs : sgs_vec) {
                auto const ret = sisl::io_blob::sg_list_to_ioblob_list(sgs);
                pkts.insert(pkts.end(), ret.begin(), ret.end());
            }

            rpc_data->set_comp_cb([sgs_vec = std::move(sgs_vec)](boost::intrusive_ptr< sisl::GenericRpcData >&) {
                for (auto const& sgs : sgs_vec) {
                    for (auto const& iov : sgs.iovs) {
                        iomanager.iobuf_free(reinterpret_cast< uint8_t* >(iov.iov_base));
                    }
                }
            });

            rpc_data->send_response(pkts);
        });
}

void RaftReplDev::handle_fetch_data_response(sisl::GenericClientResponse response,
                                             std::vector< repl_req_ptr_t > rreqs) {
    auto raw_data = response.response_blob().cbytes();
    auto total_size = response.response_blob().size();

    COUNTER_INCREMENT(m_metrics, fetch_total_blk_size, total_size);

    RD_DBG_ASSERT_GT(total_size, 0, "Empty response from remote");
    RD_DBG_ASSERT(raw_data, "Empty response from remote");

    RD_LOGD("Data Channel: FetchData completed for {} requests", rreqs.size());

    for (auto const& rreq : rreqs) {
        auto const data_size = rreq->remote_blkid().blkid.blk_count() * get_blk_size();

        if (!rreq->save_fetched_data(response, raw_data, data_size)) {
            RD_DBG_ASSERT(rreq->local_blkid().is_valid(), "Invalid blkid for rreq={}", rreq->to_compact_string());
            auto const local_size = rreq->local_blkid().blk_count() * get_blk_size();
            RD_DBG_ASSERT_EQ(data_size, local_size, "Data size mismatch for rreq={} remote size: {}, local size: {}",
                             rreq->to_compact_string(), data_size, local_size);

            RD_LOGD("Data Channel: Data already received for rreq=[{}], skip and move on to next rreq.",
                    rreq->to_compact_string());
        } else {
            data_service()
                .async_write(r_cast< const char* >(rreq->data()), data_size, rreq->local_blkid())
                .thenValue([this, rreq](auto&& err) {
                    RD_REL_ASSERT(!err,
                                  "Error in writing data"); // TODO: Find a way to return error to the Listener
                    rreq->add_state(repl_req_state_t::DATA_WRITTEN);
                    rreq->m_data_written_promise.setValue();
                    RD_LOGI("Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
                });
            RD_LOGD("Data Channel: Data fetched from remote: rreq=[{}], data_size: {}, total_size: {}, local_blkid: {}",
                    rreq->to_compact_string(), data_size, total_size, rreq->local_blkid().to_string());
        }
        raw_data += data_size;
        total_size -= data_size;
    }

    RD_DBG_ASSERT_EQ(total_size, 0, "Total size mismatch, some data is not consumed");
}

void RaftReplDev::handle_commit(repl_req_ptr_t rreq) {
    if (rreq->local_blkid().is_valid()) { data_service().commit_blk(rreq->local_blkid()); }

    // Remove the request from repl_key map.
    m_repl_key_req_map.erase(rreq->rkey());

    auto prev_lsn = m_commit_upto_lsn.exchange(rreq->lsn());
    RD_DBG_ASSERT_GT(rreq->lsn(), prev_lsn, "Out of order commit of lsns, it is not expected in RaftReplDev");

    auto cur_dsn = m_next_dsn.load(std::memory_order_relaxed);
    while (cur_dsn <= rreq->dsn()) {
        m_next_dsn.compare_exchange_strong(cur_dsn, rreq->dsn() + 1);
    }

    RD_LOGD("Raft channel: Commit rreq=[{}]", rreq->to_compact_string());
    if (rreq->op_code() == journal_type_t::HS_CTRL_DESTROY) {
        leave();
    } else {
        m_listener->on_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq->local_blkid(), rreq);
    }

    if (!rreq->is_proposer()) { rreq->clear(); }
}

void RaftReplDev::handle_error(repl_req_ptr_t const& rreq, ReplServiceError err) {
    if (err == ReplServiceError::OK) { return; }

    if (!rreq->add_state_if_not_already(repl_req_state_t::ERRORED)) {
        RD_LOGE("Raft Channel: Error in processing rreq=[{}] error={}", rreq->to_string(), err);
        return;
    }

    // Remove from the map and thus its no longer accessible from applier_create_req
    m_repl_key_req_map.erase(rreq->rkey());

    if (rreq->op_code() == journal_type_t::HS_DATA_INLINED) {
        // Free the blks which is allocated already
        RD_LOGE("Raft Channel: Error in processing rreq=[{}] error={}", rreq->to_compact_string(), err);
        if (rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) {
            auto blkid = rreq->local_blkid();
            data_service().async_free_blk(blkid).thenValue([blkid](auto&& err) {
                HS_LOG_ASSERT(!err, "freeing blkid={} upon error failed, potential to cause blk leak",
                              blkid.to_string());
            });
        }
    } else if (rreq->op_code() == journal_type_t::HS_CTRL_DESTROY) {
        if (rreq->is_proposer()) { m_destroy_promise.setValue(err); }
    }

    // TODO: Validate if this is a correct assert or not. Is it possible that the log is already flushed and we receive
    // a new request for the same log?
    // HS_DBG_ASSERT(!(rreq->state.load() & uint32_cast(repl_req_state_t::LOG_FLUSHED)),
    //               "Unexpected state, received error after log is flushed for rreq=[{}]", rreq->to_string());

    if (rreq->is_proposer()) {
        // Notify the proposer about the error
        m_listener->on_error(err, rreq->header(), rreq->key(), rreq);
    }
    rreq->clear();
}

static bool blob_equals(sisl::blob const& a, sisl::blob const& b) {
    if (a.size() != b.size()) { return false; }
    return (std::memcmp(a.cbytes(), b.cbytes(), a.size()) == 0);
}

repl_req_ptr_t RaftReplDev::repl_key_to_req(repl_key const& rkey) const {
    auto const it = m_repl_key_req_map.find(rkey);
    if (it == m_repl_key_req_map.cend()) { return nullptr; }
    return it->second;
}

<<<<<<< HEAD
repl_req_ptr_t RaftReplDev::applier_create_req(repl_key const& rkey, sisl::blob const& user_header, uint32_t data_size,
                                               [[maybe_unused]] bool is_data_channel) {
    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT((it != m_repl_key_req_map.end()), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;

    // There is no data portion, so there is not requied to allocate
    if (data_size == 0) {
        rreq->rkey = rkey;
        rreq->value_inlined = true;
        return rreq;
    }

    if (!happened) {
        // We already have the entry in the map, check if we are already allocated the blk by previous caller, in that
        // case we need to return the req.
        if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) {
            // Do validation if we have the correct mapping
            // RD_REL_ASSERT(blob_equals(user_header, rreq->header), "User header mismatch for repl_key={}",
            //              rkey.to_string());
            // RD_REL_ASSERT(blob_equals(user_key, rreq->key), "User key mismatch for repl_key={}", rkey.to_string());
            RD_LOG(DEBUG, "Repl_key=[{}] already received  ", rkey.to_string());
            return rreq;
        }
    }

    // We need to allocate the block, since entry doesn't exist or if it exist, two threads are trying to do the same
    // thing. So take state mutex and allocate the blk
    std::unique_lock< std::mutex > lg(rreq->state_mtx);
    if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) { return rreq; }

    auto hints_result = m_listener->get_blk_alloc_hints(user_header, data_size);
#ifdef _PRERELEASE
    if (is_data_channel) {
        if (iomgr_flip::instance()->test_flip("fake_reject_append_data_channel")) {
            LOGINFO("Data Channel: Reject append_entries flip is triggered for rkey={}", rkey.to_string());
            hints_result = folly::makeUnexpected(ReplServiceError::NO_SPACE_LEFT);
        }
    } else {
        if (iomgr_flip::instance()->test_flip("fake_reject_append_raft_channel")) {
            LOGINFO("Raft Channel: Reject append_entries flip is triggered for rkey={}", rkey.to_string());
            hints_result = folly::makeUnexpected(ReplServiceError::NO_SPACE_LEFT);
        }
    }
#endif

    if (hints_result.hasError()) {
        RD_LOG(ERROR, "For Repl_key=[{}] alloc hints returned error={}, failing this req", rkey.to_string(),
               hints_result.error());
        // Do not call handle_error here, because handle_error is for rreq which needs to be terminated. This one can be
        // retried.
        return nullptr;
    }

    auto const status = data_service().alloc_blks(sisl::round_up(data_size, data_service().get_blk_size()),
                                                  hints_result.value(), rreq->local_blkid);
    if (status != BlkAllocStatus::SUCCESS) {
        RD_LOG(ERROR, "For Repl_key=[{}] allocation failed with status={}, failing this req", status);
        return nullptr;
    }

    rreq->rkey = rkey;
    rreq->value_inlined = false;
    rreq->is_jentry_localize_pending = true; // Journal entry needs to be localized
    rreq->state.fetch_or(uint32_cast(repl_req_state_t::BLK_ALLOCATED));

    RD_LOG(DEBUG, "in applier_create_req: rreq={}", rreq->to_compact_string());

    return rreq;
}

static auto get_max_data_fetch_size() { return HS_DYNAMIC_CONFIG(consensus.data_fetch_max_size_kb) * 1024ull; }

void RaftReplDev::check_and_fetch_remote_data(std::vector< repl_req_ptr_t > rreqs) {
    auto total_size_to_fetch = 0ul;
    std::vector< repl_req_ptr_t > next_batch_rreqs;
    auto const max_batch_size = get_max_data_fetch_size();
    auto const originator = rreqs.front()->remote_blkid.server_id;

    for (auto const& rreq : rreqs) {
        auto const cur_state = rreq->state.load();
        if (cur_state == uint32_cast(repl_req_state_t::ERRORED)) {
            // We already received the data before, just ignore this data
            RD_LOG(DEBUG, "Raft Channel: rreq=[{}] already errored out, ignoring the fetch", rreq->to_compact_string());
            continue;
        } else if (cur_state == uint32_cast(repl_req_state_t::DATA_RECEIVED)) {
            // We already received the data before, just ignore this data
            RD_LOG(DEBUG, "Raft Channel: Data already received for rreq=[{}], ignoring the fetch",
                   rreq->to_compact_string());
            continue;
        }

        RD_REL_ASSERT_EQ(
            rreq->remote_blkid.server_id, originator,
            "Batch of remote pull has different originator, not expected, continuing can cause data corruption");

        auto const size = rreq->remote_blkid.blkid.blk_count() * get_blk_size();
        if ((total_size_to_fetch + size) >= max_batch_size) {
            fetch_data_from_remote(std::move(next_batch_rreqs));
            next_batch_rreqs.clear();
            total_size_to_fetch = 0;
        }

        total_size_to_fetch += size;
        next_batch_rreqs.emplace_back(rreq);
    }
    fetch_data_from_remote(std::move(next_batch_rreqs));
}

void RaftReplDev::fetch_data_from_remote(std::vector< repl_req_ptr_t > rreqs) {
    if (rreqs.size() == 0) { return; }

    std::vector<::flatbuffers::Offset< RequestEntry > > entries;
    entries.reserve(rreqs.size());

    shared< flatbuffers::FlatBufferBuilder > builder = std::make_shared< flatbuffers::FlatBufferBuilder >();
    RD_LOG(DEBUG, "Data Channel : FetchData from remote: rreq.size={}, my server_id={}", rreqs.size(), server_id());
    auto const& originator = rreqs.front()->remote_blkid.server_id;

    for (auto const& rreq : rreqs) {
        entries.push_back(CreateRequestEntry(*builder, rreq->get_lsn(), rreq->term(), rreq->dsn(),
                                             builder->CreateVector(rreq->header.cbytes(), rreq->header.size()),
                                             builder->CreateVector(rreq->key.cbytes(), rreq->key.size()),
                                             rreq->remote_blkid.server_id /* blkid_originator */,
                                             builder->CreateVector(rreq->remote_blkid.blkid.serialize().cbytes(),
                                                                   rreq->remote_blkid.blkid.serialized_size())));
        // relax this assert if there is a case in same batch originator can be different (can't think of one now)
        // but if there were to be such case, we need to group rreqs by originator and send them in separate
        // batches;
        RD_DBG_ASSERT_EQ(rreq->remote_blkid.server_id, originator, "Unexpected originator for rreq={}",
                         rreq->to_compact_string());

        RD_LOG(TRACE, "Fetching data from originator={}, remote: rreq=[{}], remote_blkid={}, my server_id={}",
               originator, rreq->to_compact_string(), rreq->remote_blkid.blkid.to_string(), server_id());
    }

    builder->FinishSizePrefixed(
        CreateFetchData(*builder, CreateFetchDataRequest(*builder, builder->CreateVector(entries))));

    COUNTER_INCREMENT(m_metrics, fetch_rreq_cnt, 1);
    COUNTER_INCREMENT(m_metrics, fetch_total_entries_cnt, rreqs.size());

    // leader can change, on the receiving side, we need to check if the leader is still the one who originated the
    // blkid;
    group_msg_service()
        ->data_service_request_bidirectional(
            originator, FETCH_DATA,
            sisl::io_blob_list_t{
                sisl::io_blob{builder->GetBufferPointer(), builder->GetSize(), false /* is_aligned */}})
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, builder, rreqs = std::move(rreqs)](auto response) {
            if (!response) {
                // if we are here, it means the original who sent the log entries are down.
                // we need to handle error and when the other member becomes leader, it will resend the log entries;
                RD_LOG(ERROR,
                       "Not able to fetching data from originator={}, error={}, probably originator is down. Will "
                       "retry when new leader start appending log entries",
                       rreqs.front()->remote_blkid.server_id, response.error());
                for (auto const& rreq : rreqs) {
                    // TODO: Set the data_received promise with error, so that waiting threads can be unblocked and
                    // reject the request. Without that, it will timeout and then reject it.

                    // We could have get to a scenario, where didn't receive the data at the time of fetch, but we
                    // received after issuing fetch and that leader has already switched. In this case, we don't want to
                    // fail the request.
                    if (!(rreq->state.load() & uint32_cast(repl_req_state_t::DATA_RECEIVED))) {
                        handle_error(rreq, RaftReplService::to_repl_error(response.error()));
                    }
                }
                COUNTER_INCREMENT(m_metrics, fetch_err_cnt, 1);
                return;
            }

            builder->Release();

            iomanager.run_on_forget(iomgr::reactor_regex::random_worker,
                                    [this, r = std::move(response.value()), rreqs = std::move(rreqs)]() {
                                        handle_fetch_data_response(std::move(r), std::move(rreqs));
                                    });
        });
}

void RaftReplDev::handle_fetch_data_response(sisl::GenericClientResponse response,
                                             std::vector< repl_req_ptr_t > rreqs) {
    auto raw_data = response.response_blob().cbytes();
    auto total_size = response.response_blob().size();

    COUNTER_INCREMENT(m_metrics, fetch_total_blk_size, total_size);

    RD_DBG_ASSERT_GT(total_size, 0, "Empty response from remote");
    RD_DBG_ASSERT(raw_data, "Empty response from remote");

    RD_LOG(DEBUG, "Data Channel: FetchData completed for {} requests", rreqs.size());

    for (auto const& rreq : rreqs) {
        auto const data_size = rreq->remote_blkid.blkid.blk_count() * get_blk_size();
        // if data is already received, skip it because someone is already doing the write;
        if (rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_RECEIVED)) &
            uint32_cast(repl_req_state_t::DATA_RECEIVED)) {
            // very unlikely to arrive here, but if data got received during we fetch, let the data channel
            // handle data written;
            raw_data += data_size;
            total_size -= data_size;

            // if blk is already allocated, validate if blk is valid and size matches;
            RD_DBG_ASSERT(rreq->local_blkid.is_valid(), "Invalid blkid for rreq={}", rreq->to_compact_string());
            auto const local_size = rreq->local_blkid.blk_count() * get_blk_size();
            RD_DBG_ASSERT_EQ(data_size, local_size,
                             "Data size mismatch for rreq={} blkid={}, remote size: {}, local size: {}",
                             rreq->to_compact_string(), rreq->local_blkid.to_string(), data_size, local_size);

            RD_LOG(DEBUG, "Data Channel: Data already received for rreq=[{}], skip and move on to next rreq.",
                   rreq->to_compact_string());
            continue;
        } else {
            // Blk must be already allocated, validate if blk is valid and size matches;
            RD_DBG_ASSERT(rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED),
                          "Req in map, but blk is not allocated for rreq={}", rreq->to_compact_string());
            RD_DBG_ASSERT(rreq->local_blkid.is_valid(), "Invalid blkid for rreq={}", rreq->to_compact_string());
            RD_DBG_ASSERT_EQ(data_size, rreq->local_blkid.blk_count() * get_blk_size(),
                             "Data size mismatch for rreq={} blkid={}, remote size: {}, local size: {}",
                             rreq->to_compact_string(), rreq->local_blkid.to_string(), data_size,
                             rreq->local_blkid.blk_count() * get_blk_size());
            rreq->data_received_promise.setValue();
        }

        auto data = raw_data;
        if (((uintptr_t)raw_data % data_service().get_align_size()) != 0) {
            // Unaligned buffer, create a new buffer and copy the entire buf
            rreq->buf_for_unaligned_data = std::move(sisl::io_blob_safe(data_size, data_service().get_align_size()));
            std::memcpy(rreq->buf_for_unaligned_data.bytes(), data, data_size);
            data = rreq->buf_for_unaligned_data.cbytes();
            RD_DBG_ASSERT(((uintptr_t)data % data_service().get_align_size()) == 0,
                          "Data is still not aligned after copy");
        }

        // Schedule a write and upon completion, mark the data as written.
        data_service()
            .async_write(r_cast< const char* >(data), data_size, rreq->local_blkid)
            .thenValue([this, rreq, response](auto&& err) {
                if (err) {
                    COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
                    RD_DBG_ASSERT(false, "Error in writing data, error_code={}", err.value());
                    handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
                } else {
                    rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
                    rreq->data_written_promise.setValue();
                    RD_LOG(TRACE, "Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
                }
            });

        // move the raw_data pointer to next rreq's data;
        raw_data += data_size;
        total_size -= data_size;

        RD_LOG(DEBUG, "Data Channel: Data fetched from remote: rreq=[{}], data_size: {}, total_size: {}",
               rreq->to_compact_string(), data_size, total_size);
    }

    RD_DBG_ASSERT_EQ(total_size, 0, "Total size mismatch, some data is not consumed");
}

bool RaftReplDev::wait_for_data_receive(std::vector< repl_req_ptr_t > const& rreqs, uint64_t timeout_ms) {
    std::vector< folly::Future< folly::Unit > > futs;
    std::vector< repl_req_ptr_t > only_wait_reqs;
    only_wait_reqs.reserve(rreqs.size());
    futs.reserve(rreqs.size());

    for (auto const& rreq : rreqs) {
        if ((rreq == nullptr) || (rreq->value_inlined) ||
            (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_RECEIVED))) {
            continue;
        }
        only_wait_reqs.emplace_back(rreq);
        futs.emplace_back(rreq->data_received_promise.getFuture());
    }

    // All the data has been received already, no need to wait
    if (futs.size() == 0) { return true; }

    // If we are currently in resync mode, we can fetch the data immediately. Otherwise, stage it and wait for
    // sometime before do an explicit fetch. This is so that, it is possible raft channel has come ahead of data
    // channel and waiting for sometime avoid expensive fetch. On steady state, after a little bit of wait data
    // would be reached automatically.
    RD_LOG(DEBUG,
           "We haven't received data for {} out {} in reqs batch, will fetch and wait for {} ms, in_resync_mode()={} ",
           only_wait_reqs.size(), rreqs.size(), timeout_ms, is_resync_mode());

    if (is_resync_mode()) {
        check_and_fetch_remote_data(std::move(only_wait_reqs));
    } else {
        m_repl_svc.add_to_fetch_queue(shared_from_this(), std::move(only_wait_reqs));
    }

    // block waiting here until all the futs are ready (data channel filled in and promises are made);
    auto all_futs = folly::collectAllUnsafe(futs).wait(std::chrono::milliseconds(timeout_ms));
    return (all_futs.isReady());
}

folly::Future< folly::Unit > RaftReplDev::notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs) {
    std::vector< folly::Future< folly::Unit > > futs;
    futs.reserve(rreqs->size());
    std::vector< repl_req_ptr_t > unreceived_data_reqs;

    // Walk through the list of requests and wait for the data to be received and written
    for (auto const& rreq : *rreqs) {
        if ((rreq == nullptr) || (rreq->value_inlined)) { continue; }
        auto const status = rreq->state.load();
        if (status & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
            RD_LOG(DEBUG, "Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_compact_string());
            continue;
        }

        if (!(status & uint32_cast(repl_req_state_t::DATA_RECEIVED))) {
            // This is a relatively rare scenario which can happen, where the data is not received or localized yet,
            // because it was called as part of pack/unpack i.e bulk data transfer for a new replica. For these
            // cases, the first step of localization doesn't happen (because raft isn't going to give us
            // append_entry handler callback). Hence we do that step of receiving data now. The same scenario can
            // happen in case of leader is not the propose (i.e raft forwarding is enabled)
            unreceived_data_reqs.emplace_back(rreq);
        } else {
            futs.emplace_back(rreq->data_written_promise.getFuture());
        }
    }

    if (!unreceived_data_reqs.empty()) {
        // Wait 10 times the actual data fetch timeout during normal scenario. We do that because, unlike in normal
        // scenario where can reject the append and let raft retry the log_entry send (which will cause fetch
        // retry), this flow can't fail or reject. So only option is to wait longer and if it fails, either a) Crash
        // this node and let addition of new raft server fail (or) b) Make this node is unavailable for read and
        // allow it to write (which is an incorrect data) and let remediation flow, replace this node. This atleast
        // allow other repl_dev's in the system accessibly instead of crashing the entire node.
        //
        // TODO: We are doing option a) now, but we should support option b)
        if (!wait_for_data_receive(unreceived_data_reqs, HS_DYNAMIC_CONFIG(consensus.data_receive_timeout_ms) * 10)) {
            HS_REL_ASSERT(false, "Data fetch timeout, should not happen");
        }
        for (auto const& rreq : unreceived_data_reqs) {
            futs.emplace_back(rreq->data_written_promise.getFuture());
        }
    }

    // All the entries are done already, no need to wait
    if (futs.size() == 0) { return folly::makeFuture< folly::Unit >(folly::Unit{}); }

    return folly::collectAllUnsafe(futs).thenValue([this, rreqs](auto&& e) {
#ifndef NDEBUG
        for (auto const& rreq : *rreqs) {
            if ((rreq == nullptr) || (rreq->value_inlined)) { continue; }
            HS_DBG_ASSERT(rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN),
                          "Data written promise raised without updating DATA_WRITTEN state for rkey={}",
                          rreq->rkey.to_string());
            RD_LOG(DEBUG, "Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_compact_string());
        }
#endif
        RD_LOG(TRACE, "Data Channel: {} pending reqs's data are written", rreqs->size());
        return folly::makeFuture< folly::Unit >(folly::Unit{});
    });
}

=======
>>>>>>> 4a0dc261 (Added remove repl_dev and made repl_req much more contained)
folly::Future< std::error_code > RaftReplDev::async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                         bool part_of_batch) {
    return data_service().async_read(bid, sgs, size, part_of_batch);
}

void RaftReplDev::async_free_blks(int64_t, MultiBlkId const& bid) {
    // TODO: For timeline consistency required, we should retain the blkid that is changed and write that to another
    // journal.
    data_service().async_free_blk(bid);
}

AsyncReplResult<> RaftReplDev::become_leader() {
    return m_msg_mgr.become_leader(m_group_id).via(&folly::InlineExecutor::instance()).thenValue([this](auto&& e) {
        if (e.hasError()) {
            RD_LOGE("Error in becoming leader: {}", e.error());
            return make_async_error<>(RaftReplService::to_repl_error(e.error()));
        }
        return make_async_success<>();
    });
}

bool RaftReplDev::is_leader() const { return m_repl_svc_ctx->is_raft_leader(); }

replica_id_t RaftReplDev::get_leader_id() const {
    static replica_id_t empty_uuid = boost::uuids::nil_uuid();
    auto leader = m_repl_svc_ctx->raft_leader_id();
    return leader.empty() ? empty_uuid : boost::lexical_cast< replica_id_t >(leader);
}

std::vector< peer_info > RaftReplDev::get_replication_status() const {
    std::vector< peer_info > pi;
    auto rep_status = m_repl_svc_ctx->get_raft_status();
    for (auto const& pinfo : rep_status) {
        pi.emplace_back(peer_info{.id_ = boost::lexical_cast< replica_id_t >(pinfo.id_),
                                  .replication_idx_ = pinfo.last_log_idx_,
                                  .last_succ_resp_us_ = pinfo.last_succ_resp_us_});
    }
    return pi;
}

uint32_t RaftReplDev::get_blk_size() const { return data_service().get_blk_size(); }

nuraft_mesg::repl_service_ctx* RaftReplDev::group_msg_service() { return m_repl_svc_ctx.get(); }
nuraft::raft_server* RaftReplDev::raft_server() { return m_repl_svc_ctx->_server; }

///////////////////////////////////  Config Serialize/Deserialize Section ////////////////////////////////////
static nlohmann::json serialize_server_config(std::list< nuraft::ptr< nuraft::srv_config > > const& server_list) {
    auto servers = nlohmann::json::array();
    for (auto const& server_conf : server_list) {
        if (!server_conf) { continue; }
        servers.push_back(nlohmann::json{{"id", server_conf->get_id()},
                                         {"dc_id", server_conf->get_dc_id()},
                                         {"endpoint", server_conf->get_endpoint()},
                                         {"aux", server_conf->get_aux()},
                                         {"learner", server_conf->is_learner()},
                                         {"priority", server_conf->get_priority()}});
    }
    return servers;
}

static nlohmann::json serialize_cluster_config(const nuraft::cluster_config& config) {
    return nlohmann::json{{"log_idx", config.get_log_idx()},
                          {"prev_log_idx", config.get_prev_log_idx()},
                          {"eventual_consistency", config.is_async_replication()},
                          {"user_ctx", config.get_user_ctx()},
                          {"servers", serialize_server_config(config.get_servers())}};
}

static nuraft::ptr< nuraft::srv_config > deserialize_server_config(nlohmann::json const& server) {
    DEBUG_ASSERT(server.contains("id"), "Missing field")
    auto const id = static_cast< int32_t >(server["id"]);
    DEBUG_ASSERT(server.contains("dc_id"), "Missing field")
    auto const dc_id = static_cast< int32_t >(server["dc_id"]);
    DEBUG_ASSERT(server.contains("endpoint"), "Missing field")
    auto const endpoint = server["endpoint"];
    DEBUG_ASSERT(server.contains("aux"), "Missing field")
    auto const aux = server["aux"];
    DEBUG_ASSERT(server.contains("learner"), "Missing field")
    auto const learner = server["learner"];
    DEBUG_ASSERT(server.contains("priority"), "Missing field")
    auto const prior = static_cast< int32_t >(server["priority"]);
    return nuraft::cs_new< nuraft::srv_config >(id, dc_id, endpoint, aux, learner, prior);
}

static void deserialize_server_list(nlohmann::json const& servers,
                                    std::list< nuraft::ptr< nuraft::srv_config > >& server_list) {
    for (auto const& server_conf : servers) {
        server_list.push_back(deserialize_server_config(server_conf));
    }
}

nuraft::ptr< nuraft::cluster_config > deserialize_cluster_config(nlohmann::json const& cluster_config) {
    DEBUG_ASSERT(cluster_config.contains("log_idx"), "Missing field")
    auto const& log_idx = cluster_config["log_idx"];
    DEBUG_ASSERT(cluster_config.contains("prev_log_idx"), "Missing field")
    auto const& prev_log_idx = cluster_config["prev_log_idx"];
    DEBUG_ASSERT(cluster_config.contains("eventual_consistency"), "Missing field")
    auto const& eventual = cluster_config["eventual_consistency"];

    auto raft_config = nuraft::cs_new< nuraft::cluster_config >(log_idx, prev_log_idx, eventual);
    DEBUG_ASSERT(cluster_config.contains("user_ctx"), "Missing field")
    raft_config->set_user_ctx(cluster_config["user_ctx"]);
    DEBUG_ASSERT(cluster_config.contains("servers"), "Missing field")
    deserialize_server_list(cluster_config["servers"], raft_config->get_servers());
    return raft_config;
}

nuraft::ptr< nuraft::cluster_config > RaftReplDev::load_config() {
    std::unique_lock lg{m_config_mtx};
    auto& js = *m_raft_config_sb;

    if (!js.contains("config")) {
        auto cluster_conf = nuraft::cs_new< nuraft::cluster_config >();
        cluster_conf->get_servers().push_back(
            nuraft::cs_new< nuraft::srv_config >(m_raft_server_id, my_replica_id_str()));
        js["config"] = serialize_cluster_config(*cluster_conf);
    }
    return deserialize_cluster_config(js["config"]);
}

void RaftReplDev::save_config(const nuraft::cluster_config& config) {
    std::unique_lock lg{m_config_mtx};
    (*m_raft_config_sb)["config"] = serialize_cluster_config(config);
    m_raft_config_sb.write();
}

void RaftReplDev::save_state(const nuraft::srv_state& state) {
    std::unique_lock lg{m_config_mtx};
    (*m_raft_config_sb)["state"] = nlohmann::json{{"term", state.get_term()}, {"voted_for", state.get_voted_for()}};
    m_raft_config_sb.write();
}

nuraft::ptr< nuraft::srv_state > RaftReplDev::read_state() {
    std::unique_lock lg{m_config_mtx};
    auto& js = *m_raft_config_sb;
    auto state = nuraft::cs_new< nuraft::srv_state >();
    if (js["state"].empty()) {
        js["state"] = nlohmann::json{{"term", state->get_term()}, {"voted_for", state->get_voted_for()}};
    } else {
        try {
            state->set_term(uint64_cast(js["state"]["term"]));
            state->set_voted_for(static_cast< int >(js["state"]["voted_for"]));
        } catch (std::out_of_range const&) {
            LOGWARN("State data was not in the expected format [group_id={}]!", m_group_id)
        }
    }
    return state;
}

nuraft::ptr< nuraft::log_store > RaftReplDev::load_log_store() { return m_data_journal; }

int32_t RaftReplDev::server_id() { return m_raft_server_id; }

bool RaftReplDev::is_destroy_pending() const { return (m_rd_sb->destroy_pending == 0x1); }

///////////////////////////////////  nuraft_mesg::mesg_state_mgr overrides ////////////////////////////////////
void RaftReplDev::become_ready() {
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::ACTIVE; });
}

uint32_t RaftReplDev::get_logstore_id() const { return m_data_journal->logstore_id(); }

std::shared_ptr< nuraft::state_machine > RaftReplDev::get_state_machine() { return m_state_machine; }

void RaftReplDev::permanent_destroy() {}

void RaftReplDev::leave() {
    // Persist that destroy pending in superblk, so that in case of crash before cleanup of resources, it can be done
    // post restart.
    m_rd_sb->destroy_pending = 0x1;
    m_rd_sb.write();

    // We update that this repl_dev in destroyed state, actual clean up of resources happen in reaper thread later
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::DESTROYED; });
    m_destroyed_time = Clock::now();

    // We let the listener know right away, so that they can cleanup persistent structures soonest. This will
    // reduce the time window of leaked resources if any
    m_listener->on_destroy();
    m_destroy_promise.setValue(ReplServiceError::OK); // In case proposer is waiting for the destroy to complete
}

std::pair< bool, nuraft::cb_func::ReturnCode > RaftReplDev::handle_raft_event(nuraft::cb_func::Type type,
                                                                              nuraft::cb_func::Param* param) {
    auto ret = nuraft::cb_func::ReturnCode::Ok;

    if (type == nuraft::cb_func::Type::GotAppendEntryReqFromLeader) {
        auto raft_req = r_cast< nuraft::req_msg* >(param->ctx);
        auto const& entries = raft_req->log_entries();

        if (!entries.empty()) {
            RD_LOGT("Raft channel: Received {} append entries on follower from leader, localizing them",
                    entries.size());

            auto reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
            for (auto& entry : entries) {
                if (entry->get_val_type() != nuraft::log_val_type::app_log) { continue; }
                auto req = m_state_machine->localize_journal_entry_prepare(*entry);
                if (req == nullptr) {
                    sisl::VectorPool< repl_req_ptr_t >::free(reqs);
                    return {true, nuraft::cb_func::ReturnCode::ReturnNull};
                }
                reqs->emplace_back(std::move(req));
            }

            // Wait till we receive the data from its originator for all the requests
            if (!wait_for_data_receive(*reqs, HS_DYNAMIC_CONFIG(consensus.data_receive_timeout_ms))) {
                for (auto const& rreq : *reqs) {
                    handle_error(rreq, ReplServiceError::TIMEOUT);
                }
                ret = nuraft::cb_func::ReturnCode::ReturnNull;
            }
            sisl::VectorPool< repl_req_ptr_t >::free(reqs);
        }
        return {true, ret};
    } else {
        return {false, ret};
    }
}

///////////////////////////////////  Private metohds ////////////////////////////////////
void RaftReplDev::cp_flush(CP*) {
    auto const lsn = m_commit_upto_lsn.load();
    auto const clsn = m_compact_lsn.load();

    if (lsn == m_last_flushed_commit_lsn) {
        // Not dirtied since last flush ignore
        return;
    }
    m_rd_sb->compact_lsn = clsn;
    m_rd_sb->commit_lsn = lsn;
    m_rd_sb->checkpoint_lsn = lsn;
    m_rd_sb->last_applied_dsn = m_next_dsn.load();
    m_rd_sb.write();
    m_last_flushed_commit_lsn = lsn;
}

void RaftReplDev::cp_cleanup(CP*) {}
} // namespace homestore
