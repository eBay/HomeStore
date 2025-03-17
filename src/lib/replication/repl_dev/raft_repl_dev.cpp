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
#include "device/device.h"
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
        m_data_journal = std::make_shared< ReplLogStore >(
            *this, *m_state_machine, m_rd_sb->logdev_id, m_rd_sb->logstore_id,
            [this](logstore_seq_num_t lsn, log_buffer buf, void* key) { on_log_found(lsn, buf, key); },
            [this](std::shared_ptr< HomeLogStore > hs, logstore_seq_num_t lsn) {
                m_log_store_replay_done = true;
                set_log_store_last_durable_lsn(hs->tail_lsn());
            });
        m_next_dsn = m_rd_sb->last_applied_dsn + 1;
        m_commit_upto_lsn = m_rd_sb->durable_commit_lsn;
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
        m_rd_sb->destroy_pending = 0x0;
        m_rd_sb->group_ordinal = s_next_group_ordinal.fetch_add(1);
        m_rdev_name = fmt::format("rdev{}", m_rd_sb->group_ordinal);

        if (m_rd_sb->is_timeline_consistent) {
            m_free_blks_journal = logstore_service().create_new_log_store(m_rd_sb->logdev_id, false /* append_mode */);
            m_rd_sb->free_blks_journal_id = m_free_blks_journal->get_store_id();
        }
        m_rd_sb.write();
        bind_data_service();
    }

    RD_LOG(INFO,
           "Started {} RaftReplDev group_id={}, replica_id={}, raft_server_id={} commited_lsn={}, "
           "compact_lsn={}, checkpoint_lsn:{}, next_dsn={} "
           "log_dev={} log_store={}",
           (load_existing ? "Existing" : "New"), group_id_str(), my_replica_id_str(), m_raft_server_id,
           m_commit_upto_lsn.load(), m_compact_lsn.load(), m_rd_sb->checkpoint_lsn, m_next_dsn.load(),
           m_rd_sb->logdev_id, m_rd_sb->logstore_id);
}

bool RaftReplDev::bind_data_service() {
    RD_LOG(INFO, "Starting data channel, group_id={}, replica_id={}", group_id_str(), my_replica_id_str());
    bool success = false;
#ifdef _PRERELEASE
    success =
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
    success =
        m_msg_mgr.bind_data_service_request(PUSH_DATA, m_group_id, bind_this(RaftReplDev::on_push_data_received, 1));
#endif
    if (!success) {
        RD_LOGE("Failed to bind data service request for PUSH_DATA");
        return false;
    }
    success =
        m_msg_mgr.bind_data_service_request(FETCH_DATA, m_group_id, bind_this(RaftReplDev::on_fetch_data_received, 1));
    if (!success) {
        RD_LOGE("Failed to bind data service request for FETCH_DATA");
        return false;
    }
    return true;
}

bool RaftReplDev::join_group() {
    bind_data_service();
    auto raft_result =
        m_msg_mgr.join_group(m_group_id, "homestore_replication",
                             std::dynamic_pointer_cast< nuraft_mesg::mesg_state_mgr >(shared_from_this()));
    if (!raft_result) {
        HS_DBG_ASSERT(false, "Unable to join the group_id={} with error={}", group_id_str(), raft_result.error());
        return false;
    }
    return true;
}

AsyncReplResult<> RaftReplDev::replace_member(const replica_member_info& member_out,
                                              const replica_member_info& member_in, uint32_t commit_quorum) {

    if (is_stopping()) {
        LOGINFO("repl dev is being shutdown!");
        return make_async_error<>(ReplServiceError::STOPPING);
    }
    incr_pending_request_num();

    LOGINFO("Replace member group_id={} member_out={} member_in={}", group_id_str(),
            boost::uuids::to_string(member_out.id), boost::uuids::to_string(member_in.id));

    if (commit_quorum >= 1) {
        // Two members are down and leader cant form the quorum. Reduce the quorum size.
        reset_quorum_size(commit_quorum);
    }

    // Step 1: Check if leader itself is requested to move out.
    if (m_my_repl_id == member_out.id && m_my_repl_id == get_leader_id()) {
        // If leader is the member requested to move out, then give up leadership and return error.
        // Client will retry replace_member request to the new leader.
        raft_server()->yield_leadership(true /* immediate */, -1 /* successor */);
        RD_LOGI("Replace member leader is the member_out so yield leadership");
        reset_quorum_size(0);
        decr_pending_request_num();
        return make_async_error<>(ReplServiceError::NOT_LEADER);
    }

    // Step 2. Add the new member.
    return m_msg_mgr.add_member(m_group_id, member_in.id)
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, member_in, member_out, commit_quorum](auto&& e) -> AsyncReplResult<> {
            // TODO Currently we ignore the cancelled, fix nuraft_mesg to not timeout
            // when adding member. Member is added to cluster config until member syncs fully
            // with atleast stop gap. This will take a lot of time for block or
            // object storage.
            if (e.hasError()) {
                // Ignore the server already exists as server already added to the cluster.
                // The pg member change requests from control path are idemepotent and request
                // can be resend and one of the add or remove can failed and has to retried.
                if (e.error() == nuraft::cmd_result_code::CANCELLED ||
                    e.error() == nuraft::cmd_result_code::SERVER_ALREADY_EXISTS) {
                    RD_LOGW("Ignoring error returned from nuraft add_member {}", e.error());
                } else {
                    RD_LOGE("Replace member error in add member : {}", e.error());
                    reset_quorum_size(0);
                    decr_pending_request_num();
                    return make_async_error<>(RaftReplService::to_repl_error(e.error()));
                }
            }

            RD_LOGI("Replace member added member={} to group_id={}", boost::uuids::to_string(member_in.id),
                    group_id_str());

            // Step 3. Append log entry to mark the old member is out and new member is added.
            auto rreq = repl_req_ptr_t(new repl_req_ctx{});
            replace_members_ctx members;
            members.replica_out = member_out;
            members.replica_in = member_in;

            sisl::blob header(r_cast< uint8_t* >(&members), sizeof(replace_members_ctx));
            rreq->init(
                repl_key{.server_id = server_id(), .term = raft_server()->get_term(), .dsn = m_next_dsn.fetch_add(1)},
                journal_type_t::HS_CTRL_REPLACE, true, header, sisl::blob{}, 0, m_listener);

            auto err = m_state_machine->propose_to_raft(std::move(rreq));
            if (err != ReplServiceError::OK) {
                LOGERROR("Replace member propose to raft failed {}", err);
                reset_quorum_size(0);
                decr_pending_request_num();
                return make_async_error<>(std::move(err));
            }

            RD_LOGI("Replace member proposed to raft group_id={}", group_id_str());

            // Step 4. Remove the old member. Even if the old member is temporarily
            // down and recovers, nuraft mesg see member remove from cluster log
            // entry and call exit_group() and leave().
            return m_msg_mgr.rem_member(m_group_id, member_out.id)
                .via(&folly::InlineExecutor::instance())
                .thenValue([this, member_out, commit_quorum](auto&& e) -> AsyncReplResult<> {
                    if (e.hasError()) {
                        // Ignore the server not found as server removed from the cluster
                        // as requests are idempotent and can be resend.
                        if (e.error() == nuraft::cmd_result_code::SERVER_NOT_FOUND) {
                            RD_LOGW("Remove member not found in group error, ignoring");
                        } else {
                            // Its ok to retry this request as the request
                            // of replace member is idempotent.
                            RD_LOGE("Replace member failed to remove member : {}", e.error());
                            reset_quorum_size(0);
                            decr_pending_request_num();
                            return make_async_error<>(ReplServiceError::RETRY_REQUEST);
                        }
                    } else {
                        RD_LOGI("Replace member removed member={} from group_id={}",
                                boost::uuids::to_string(member_out.id), group_id_str());
                    }

                    // Revert the quorum size back to 0.
                    reset_quorum_size(0);
                    decr_pending_request_num();
                    return make_async_success<>();
                });
        });
}

void RaftReplDev::reset_quorum_size(uint32_t commit_quorum) {
    RD_LOGI("Reset raft quorum size={}", commit_quorum);
    nuraft::raft_params params = raft_server()->get_current_params();
    params.with_custom_commit_quorum_size(commit_quorum);
    params.with_custom_election_quorum_size(commit_quorum);
    raft_server()->update_params(params);
}

folly::SemiFuture< ReplServiceError > RaftReplDev::destroy_group() {
    // Set the intent to destroy the group
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::DESTROYING; });

    // Propose to the group to destroy
    auto rreq = repl_req_ptr_t(new repl_req_ctx{});

    // if we have a rreq {originator=1, term=1, dsn=0, lsn=7} in follower and a baseline resync is triggerd before the
    // rreq is committed in the follower, then the on_commit of the rreq will not be called and as a result this rreq
    // will become a garbage rreq in this follower. now if we trigger a destroy_group, a new rreq {originator=1, term=1,
    // dsn=0} will created in the follower since the default dsn of a repl_key is 0.after the log of this rreq is
    // appended to log store and get a new lsn, if we link the new lsn to the old rreq (rreq is identified by
    // {originator, term, dsn}) which has alread have a lsn, then a assert will be throw out. pls refer to
    // repl_req_ctx::set_lsn

    // here, we set the dsn to a new one , which is definitely unique in the follower, so that the new rreq will not
    // have a conflict with the old rreq.
    rreq->init(repl_key{.server_id = server_id(), .term = raft_server()->get_term(), .dsn = m_next_dsn.fetch_add(1)},
               journal_type_t::HS_CTRL_DESTROY, true, sisl::blob{}, sisl::blob{}, 0, m_listener);

    auto err = m_state_machine->propose_to_raft(std::move(rreq));
    if (err != ReplServiceError::OK) {
        m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::ACTIVE; });
        return folly::makeSemiFuture< ReplServiceError >(std::move(err));
        LOGERROR("RaftReplDev::destroy_group failed {}", err);
    }

    LOGINFO("Raft repl dev destroy_group={}", group_id_str());
    return m_destroy_promise.getSemiFuture();
}

void RaftReplDev::use_config(json_superblk raft_config_sb) { m_raft_config_sb = std::move(raft_config_sb); }

void RaftReplDev::on_create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    RD_LOG(DEBUG, "create_snapshot last_idx={}/term={}", s.get_last_log_idx(), s.get_last_log_term());
    auto snp_ctx = std::make_shared< nuraft_snapshot_context >(s);
    auto result = m_listener->create_snapshot(snp_ctx).get();
    auto null_except = std::shared_ptr< std::exception >();
    HS_REL_ASSERT(result.hasError() == false, "Not expecting creating snapshot to return false. ");

    auto ret_val{true};
    if (when_done) { when_done(ret_val, null_except); }
}

// 1 before repl_dev.stop() is called, the upper layer should make sure that there is no pending request. so graceful
// shutdown can consider when stopping repl_dev, there is no pending request.
// 2 before the log is appended to log store, repl_dev will guarantee the corresponding data is persisted on disk. so
// even if we do not care about this when stop, it will be ok, since log will replayed after restart.

// we do not have shutdown for async_alloc_write according to the two points above.
void RaftReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& data,
                                    repl_req_ptr_t rreq) {
    if (!rreq) { auto rreq = repl_req_ptr_t(new repl_req_ctx{}); }

    {
        auto const guard = m_stage.access();
        if (auto const stage = *guard.get(); stage != repl_dev_stage_t::ACTIVE) {
            RD_LOGW("Raft channel: Not ready to accept writes, stage={}", enum_name(stage));
            handle_error(rreq,
                         (stage == repl_dev_stage_t::INIT) ? ReplServiceError::SERVER_IS_JOINING
                                                           : ReplServiceError::SERVER_IS_LEAVING);
            return;
        }
    }

    auto status = rreq->init(
        repl_key{.server_id = server_id(), .term = raft_server()->get_term(), .dsn = m_next_dsn.fetch_add(1)},
        data.size ? journal_type_t::HS_DATA_LINKED : journal_type_t::HS_DATA_INLINED, true /* is_proposer */, header,
        key, data.size, m_listener);

    // Add the request to the repl_dev_rreq map, it will be accessed throughout the life cycle of this request
    auto const [it, happened] = m_repl_key_req_map.emplace(rreq->rkey(), rreq);
    RD_DBG_ASSERT(happened, "Duplicate repl_key={} found in the map", rreq->rkey().to_string());

    if (status != ReplServiceError::OK) {
        RD_LOGD("Initializing rreq failed error={}, failing this req", status);
        handle_error(rreq, status);
        return;
    }

    // If it is header only entry, directly propose to the raft
    if (rreq->has_linked_data()) {
        if (rreq->is_proposer() && rreq->has_state(repl_req_state_t::DATA_COMMITTED)) {
            RD_LOGD("data blks has already been allocated and committed, failing this req");
            handle_error(rreq, ReplServiceError::DATA_DUPLICATED);
            return;
        }

#ifdef _PRERELEASE
        if (iomgr_flip::instance()->test_flip("disable_leader_push_data")) {
            RD_LOGD("Simulating push data failure, so that all the follower will have to fetch data");
        } else
            push_data_to_all_followers(rreq, data);
#else
        push_data_to_all_followers(rreq, data);
#endif

        COUNTER_INCREMENT(m_metrics, total_write_cnt, 1);
        COUNTER_INCREMENT(m_metrics, outstanding_data_write_cnt, 1);

        auto const data_write_start_time = Clock::now();
        // Write the data
        data_service()
            .async_write(data, rreq->local_blkid())
            .thenValue([this, rreq, data_write_start_time](auto&& err) {
                // update outstanding no matter error or not;
                COUNTER_DECREMENT(m_metrics, outstanding_data_write_cnt, 1);

                if (err) {
                    HS_DBG_ASSERT(false, "Error in writing data, err_code={}", err.value());
                    handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
                } else {
                    // update metrics for originated rreq;
                    const auto write_num_pieces = rreq->local_blkid().num_pieces();
                    HISTOGRAM_OBSERVE(m_metrics, rreq_pieces_per_write, write_num_pieces);
                    HISTOGRAM_OBSERVE(m_metrics, rreq_data_write_latency_us,
                                      get_elapsed_time_us(data_write_start_time));
                    HISTOGRAM_OBSERVE(m_metrics, rreq_total_data_write_latency_us,
                                      get_elapsed_time_us(rreq->created_time()));

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
    builder.FinishSizePrefixed(CreatePushDataRequest(
        builder, server_id(), rreq->term(), rreq->dsn(),
        builder.CreateVector(rreq->header().cbytes(), rreq->header().size()),
        builder.CreateVector(rreq->key().cbytes(), rreq->key().size()), data.size, get_time_since_epoch_ms()));

    rreq->m_pkts = sisl::io_blob::sg_list_to_ioblob_list(data);
    rreq->m_pkts.insert(rreq->m_pkts.begin(), sisl::io_blob{builder.GetBufferPointer(), builder.GetSize(), false});

    /*RD_LOGI("Data Channel: Pushing data to all followers: rreq=[{}] data=[{}]", rreq->to_string(),
           flatbuffers::FlatBufferToString(builder.GetBufferPointer() + sizeof(flatbuffers::uoffset_t),
                                           PushDataRequestTypeTable()));*/

    auto peers = get_active_peers();
    auto calls = std::vector< nuraft_mesg::NullAsyncResult >();
    for (auto peer : peers) {
        RD_LOGD("Data Channel: Pushing data to follower {}, rreq=[{}]", peer, rreq->to_string());
        calls.push_back(group_msg_service()
                            ->data_service_request_unidirectional(peer, PUSH_DATA, rreq->m_pkts)
                            .via(&folly::InlineExecutor::instance()));
    }
    folly::collectAllUnsafe(calls).thenValue([this, rreq](auto&& v_res) {
        for (auto const& res : v_res) {
            if (sisl_likely(res.value())) {
                auto r = res.value();
                if (r.hasError()) {
                    // Just logging PushData error, no action is needed as follower can try by fetchData.
                    RD_LOGW("Data Channel: Error in pushing data to all followers: rreq=[{}] error={}",
                            rreq->to_string(), r.error());
                }
            }
        }
        RD_LOGD("Data Channel: Data push completed for rreq=[{}]", rreq->to_string());
        // Release the buffer which holds the packets
        rreq->release_fb_builder();
        rreq->m_pkts.clear();
    });
}

void RaftReplDev::on_push_data_received(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto const push_data_rcv_time = Clock::now();
    auto const& incoming_buf = rpc_data->request_blob();
    if (!incoming_buf.cbytes()) {
        RD_LOGW("Data Channel: PushData received with empty buffer, ignoring this call");
        rpc_data->send_response();
        return;
    }

    auto const fb_size =
        flatbuffers::ReadScalar< flatbuffers::uoffset_t >(incoming_buf.cbytes()) + sizeof(flatbuffers::uoffset_t);
    auto push_req = GetSizePrefixedPushDataRequest(incoming_buf.cbytes());
    if (fb_size + push_req->data_size() != incoming_buf.size()) {
        RD_LOGW("Data Channel: PushData received with size mismatch, header size {}, data size {}, received size {}",
                fb_size, push_req->data_size(), incoming_buf.size());
        rpc_data->send_response();
        return;
    }
    sisl::blob header = sisl::blob{push_req->user_header()->Data(), push_req->user_header()->size()};
    sisl::blob key = sisl::blob{push_req->user_key()->Data(), push_req->user_key()->size()};
    repl_key rkey{.server_id = push_req->issuer_replica_id(), .term = push_req->raft_term(), .dsn = push_req->dsn()};
    auto const req_orig_time_ms = push_req->time_ms();

    RD_LOGD("Data Channel: PushData received: time diff={} ms.", get_elapsed_time_ms(req_orig_time_ms));

#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("drop_push_data_request")) {
        LOGINFO("Data Channel: Flip is enabled, skip on_push_data_received to simulate fetch remote data, "
                "server_id={}, term={}, dsn={}",
                push_req->issuer_replica_id(), push_req->raft_term(), push_req->dsn());
        rpc_data->send_response();
        return;
    }
#endif

    auto rreq = applier_create_req(rkey, journal_type_t::HS_DATA_LINKED, header, key, push_req->data_size(),
                                   true /* is_data_channel */);
    if (rreq == nullptr) {
        RD_LOG(ERROR,
               "Data Channel: Creating rreq on applier has failed, will ignore the push and let Raft channel send "
               "trigger a fetch explicitly if needed. rkey={}",
               rkey.to_string());
        rpc_data->send_response();
        return;
    }

    if (!rreq->save_pushed_data(rpc_data, incoming_buf.cbytes() + fb_size, push_req->data_size())) {
        RD_LOGD("Data Channel: Data already received for rreq=[{}], ignoring this data", rreq->to_string());
        rpc_data->send_response();
        return;
    }

    COUNTER_INCREMENT(m_metrics, total_write_cnt, 1);
    COUNTER_INCREMENT(m_metrics, outstanding_data_write_cnt, 1);

    // Schedule a write and upon completion, mark the data as written.
    data_service()
        .async_write(r_cast< const char* >(rreq->data()), push_req->data_size(), rreq->local_blkid())
        .thenValue([this, rreq, push_data_rcv_time](auto&& err) {
            // update outstanding no matter error or not;
            COUNTER_DECREMENT(m_metrics, outstanding_data_write_cnt, 1);

            if (err) {
                COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
                RD_DBG_ASSERT(false, "Error in writing data, error_code={}", err.value());
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            } else {
                rreq->release_data();
                rreq->add_state(repl_req_state_t::DATA_WRITTEN);
                rreq->m_data_written_promise.setValue();
                const auto data_log_diff_us =
                    push_data_rcv_time.time_since_epoch().count() > rreq->created_time().time_since_epoch().count()
                    ? get_elapsed_time_us(rreq->created_time(), push_data_rcv_time)
                    : get_elapsed_time_us(push_data_rcv_time, rreq->created_time());

                auto const data_write_latency = get_elapsed_time_us(push_data_rcv_time);
                auto const total_data_write_latency = get_elapsed_time_us(rreq->created_time());
                auto const write_num_pieces = rreq->local_blkid().num_pieces();

                HISTOGRAM_OBSERVE(m_metrics, rreq_pieces_per_write, write_num_pieces);
                HISTOGRAM_OBSERVE(m_metrics, rreq_push_data_latency_us, data_write_latency);
                HISTOGRAM_OBSERVE(m_metrics, rreq_total_data_write_latency_us, total_data_write_latency);

                RD_LOGD("Data Channel: Data write completed for rreq=[{}], time_diff_data_log_us={}, "
                        "data_write_latency_us={}, total_data_write_latency_us(rreq creation to write complete)={}, "
                        "local_blkid.num_pieces={}",
                        rreq->to_string(), data_log_diff_us, data_write_latency, total_data_write_latency,
                        write_num_pieces);
            }
        });
}

repl_req_ptr_t RaftReplDev::applier_create_req(repl_key const& rkey, journal_type_t code, sisl::blob const& user_header,
                                               sisl::blob const& key, uint32_t data_size,
                                               [[maybe_unused]] bool is_data_channel) {
    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT((it != m_repl_key_req_map.end()), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;

    if (!happened) {
        // We already have the entry in the map, reset its start time to prevent it from being incorrectly gc during
        // use.
        rreq->set_created_time();
        // Check if we are already allocated the blk by previous caller, in that case we need to return the req.
        if (rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) {
            // Do validation if we have the correct mapping
            // RD_REL_ASSERT(blob_equals(user_header, rreq->header), "User header mismatch for repl_key={}",
            //              rkey.to_string());
            // RD_REL_ASSERT(blob_equals(user_key, rreq->key), "User key mismatch for repl_key={}", rkey.to_string());
            RD_LOGD("Repl_key=[{}] already received  ", rkey.to_string());
            return rreq;
        }
    }

    // rreq->init will allocate the block if it has linked data.
    auto status = rreq->init(rkey, code, false /* is_proposer */, user_header, key, data_size, m_listener);
    if (!rreq->has_linked_data()) { return rreq; }
#ifdef _PRERELEASE
    if (is_data_channel) {
        if (iomgr_flip::instance()->test_flip("fake_reject_append_data_channel")) {
            LOGINFO("Data Channel: Reject append_entries flip is triggered for rkey={}", rkey.to_string());
            status = ReplServiceError::NO_SPACE_LEFT;
        }
    } else {
        if (iomgr_flip::instance()->test_flip("fake_reject_append_raft_channel")) {
            LOGINFO("Raft Channel: Reject append_entries flip is triggered for rkey={}", rkey.to_string());
            status = ReplServiceError::NO_SPACE_LEFT;
        }
    }
#endif
    if (status != ReplServiceError::OK) {
        RD_LOGD("For Repl_key=[{}] alloc hints returned error={}, failing this req", rkey.to_string(), status);
        // Do not call handle_error here, because handle_error is for rreq which needs to be terminated. This one can be
        // retried.
        return nullptr;
    }

    RD_LOGD("in follower_create_req: rreq={}, addr={}", rreq->to_string(), reinterpret_cast< uintptr_t >(rreq.get()));
    return rreq;
}

folly::Future< folly::Unit > RaftReplDev::notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs) {
    std::vector< folly::Future< folly::Unit > > futs;
    futs.reserve(rreqs->size());
    std::vector< repl_req_ptr_t > unreceived_data_reqs;

    // Walk through the list of requests and wait for the data to be received and written
    for (auto const& rreq : *rreqs) {
        if (!rreq->has_linked_data()) { continue; }
        auto const status = uint32_cast(rreq->state());
        if (status & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
            RD_LOGD("Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_string());
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
            RD_LOGD("Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_string());
        }
#endif
        RD_LOGT("Data Channel: {} pending reqs's data are written", rreqs->size());
        return folly::makeFuture< folly::Unit >(folly::Unit{});
    });
}

bool RaftReplDev::wait_for_data_receive(std::vector< repl_req_ptr_t > const& rreqs, uint64_t timeout_ms,
                                        std::vector< repl_req_ptr_t >* timeout_rreqs) {
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
        check_and_fetch_remote_data(only_wait_reqs);
    } else {
        m_repl_svc.add_to_fetch_queue(shared_from_this(), only_wait_reqs);
    }

    // block waiting here until all the futs are ready (data channel filled in and promises are made);
    auto all_futs_ready = folly::collectAllUnsafe(futs).wait(std::chrono::milliseconds(timeout_ms)).isReady();
    if (!all_futs_ready && timeout_rreqs != nullptr) {
        timeout_rreqs->clear();
        for (size_t i{0}; i < futs.size(); ++i) {
            if (!futs[i].isReady()) { timeout_rreqs->emplace_back(only_wait_reqs[i]); }
        }
        all_futs_ready = timeout_rreqs->empty();
    }
    return all_futs_ready;
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
            RD_LOGD("Raft Channel: rreq=[{}] already errored out, ignoring the fetch", rreq->to_string());
            continue;
        } else if (cur_state == uint32_cast(repl_req_state_t::DATA_RECEIVED)) {
            // We already received the data before, just ignore this data
            RD_LOGD("Raft Channel: Data already received for rreq=[{}], ignoring the fetch", rreq->to_string());
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
                         rreq->to_string());

        RD_LOGT("Fetching data from originator={}, remote: rreq=[{}], remote_blkid={}, my server_id={}", originator,
                rreq->to_string(), rreq->remote_blkid().blkid.to_string(), server_id());
    }

    builder->FinishSizePrefixed(
        CreateFetchData(*builder, CreateFetchDataRequest(*builder, builder->CreateVector(entries))));

    COUNTER_INCREMENT(m_metrics, fetch_rreq_cnt, 1);
    COUNTER_INCREMENT(m_metrics, fetch_total_entries_cnt, rreqs.size());
    COUNTER_INCREMENT(m_metrics, outstanding_data_fetch_cnt, 1);

    // leader can change, on the receiving side, we need to check if the leader is still the one who originated the
    // blkid;
    auto const fetch_start_time = Clock::now();
    group_msg_service()
        ->data_service_request_bidirectional(
            originator, FETCH_DATA,
            sisl::io_blob_list_t{
                sisl::io_blob{builder->GetBufferPointer(), builder->GetSize(), false /* is_aligned */}})
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, builder, rreqs = std::move(rreqs), fetch_start_time](auto response) {
            COUNTER_DECREMENT(m_metrics, outstanding_data_fetch_cnt, 1);
            auto const fetch_latency_us = get_elapsed_time_us(fetch_start_time);
            HISTOGRAM_OBSERVE(m_metrics, rreq_data_fetch_latency_us, fetch_latency_us);

            RD_LOGD("Data Channel: FetchData from remote completed, time taken={} us", fetch_latency_us);

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
    if (!incoming_buf.cbytes()) {
        RD_LOGW("Data Channel: PushData received with empty buffer, ignoring this call");
        rpc_data->send_response();
        return;
    }
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
        MultiBlkId local_blkid;
        local_blkid.deserialize(sisl::blob{remote_blkid->Data(), remote_blkid->size()}, true /* copy */);
        // prepare the sgs data buffer to read into;
        auto const total_size = local_blkid.blk_count() * get_blk_size();
        sisl::sg_list sgs;
        sgs.size = total_size;
        sgs.iovs.emplace_back(
            iovec{.iov_base = iomanager.iobuf_alloc(get_blk_size(), total_size), .iov_len = total_size});

        // accumulate the sgs for later use (send back to the requester));
        sgs_vec.push_back(sgs);

        if (originator != server_id()) {
            RD_LOGD("non-originator FetchData received:  dsn={} lsn={} originator={}, my_server_id={}", req->dsn(), lsn,
                    originator, server_id());
        } else {
            RD_LOGD("Data Channel: FetchData received:  dsn={} lsn={}", req->dsn(), lsn);
        }

        auto const& header = req->user_header();
        sisl::blob user_header = sisl::blob{header->Data(), header->size()};
        RD_LOGD("Data Channel: FetchData handled, my_blkid={}", local_blkid.to_string());
        futs.emplace_back(std::move(m_listener->on_fetch_data(lsn, user_header, local_blkid, sgs)));
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
    auto resp_blob = response.response_blob();
    auto raw_data = resp_blob.cbytes();
    auto total_size = resp_blob.size();

    COUNTER_INCREMENT(m_metrics, fetch_total_blk_size, total_size);

    RD_DBG_ASSERT_GT(total_size, 0, "Empty response from remote");
    RD_DBG_ASSERT(raw_data, "Empty response from remote");

    RD_LOGD("Data Channel: FetchData completed for {} requests", rreqs.size());

    for (auto const& rreq : rreqs) {
        auto const data_size = rreq->remote_blkid().blkid.blk_count() * get_blk_size();

        if (!rreq->save_fetched_data(response, raw_data, data_size)) {
            RD_DBG_ASSERT(rreq->local_blkid().is_valid(), "Invalid blkid for rreq={}", rreq->to_string());
            auto const local_size = rreq->local_blkid().blk_count() * get_blk_size();
            RD_DBG_ASSERT_EQ(data_size, local_size, "Data size mismatch for rreq={} remote size: {}, local size: {}",
                             rreq->to_string(), data_size, local_size);

            RD_LOGD("Data Channel: Data already received for rreq=[{}], skip and move on to next rreq.",
                    rreq->to_string());
        } else {
            auto const data_write_start_time = Clock::now();
            COUNTER_INCREMENT(m_metrics, total_write_cnt, 1);
            COUNTER_INCREMENT(m_metrics, outstanding_data_write_cnt, 1);
            data_service()
                .async_write(r_cast< const char* >(rreq->data()), data_size, rreq->local_blkid())
                .thenValue([this, rreq, data_write_start_time](auto&& err) {
                    // update outstanding no matter error or not;
                    COUNTER_DECREMENT(m_metrics, outstanding_data_write_cnt, 1);
                    auto const data_write_latency = get_elapsed_time_us(data_write_start_time);
                    auto const total_data_write_latency = get_elapsed_time_us(rreq->created_time());
                    auto const write_num_pieces = rreq->local_blkid().num_pieces();

                    HISTOGRAM_OBSERVE(m_metrics, rreq_pieces_per_write, write_num_pieces);
                    HISTOGRAM_OBSERVE(m_metrics, rreq_data_write_latency_us, data_write_latency);
                    HISTOGRAM_OBSERVE(m_metrics, rreq_total_data_write_latency_us, total_data_write_latency);

                    RD_REL_ASSERT(!err,
                                  "Error in writing data"); // TODO: Find a way to return error to the Listener
                    rreq->release_data();
                    rreq->add_state(repl_req_state_t::DATA_WRITTEN);
                    rreq->m_data_written_promise.setValue();

                    RD_LOGD("Data Channel: Data Write completed rreq=[{}], data_write_latency_us={}, "
                            "total_write_latency_us={}, write_num_pieces={}",
                            rreq->to_string(), data_write_latency, total_data_write_latency, write_num_pieces);
                });

            RD_LOGD("Data Channel: Data fetched from remote: rreq=[{}], data_size: {}, total_size: {}, local_blkid: {}",
                    rreq->to_string(), data_size, total_size, rreq->local_blkid().to_string());
        }
        raw_data += data_size;
        total_size -= data_size;
    }

    RD_DBG_ASSERT_EQ(total_size, 0, "Total size mismatch, some data is not consumed");
}

void RaftReplDev::commit_blk(repl_req_ptr_t rreq) {
    if (rreq->local_blkid().is_valid()) {
        if (data_service().commit_blk(rreq->local_blkid()) != BlkAllocStatus::SUCCESS) {
            if (hs()->device_mgr()->is_boot_in_degraded_mode() && m_log_store_replay_done)
                return;
            else
                RD_DBG_ASSERT(false, "fail to commit blk when applying log in non-degraded mode.")
        }
    }
}

void RaftReplDev::handle_rollback(repl_req_ptr_t rreq) {
    // 1. call the listener to rollback
    m_listener->on_rollback(rreq->lsn(), rreq->header(), rreq->key(), rreq);

    // 2. remove the request from maps
    m_state_machine->unlink_lsn_to_req(rreq->lsn(), rreq);
    m_repl_key_req_map.erase(rreq->rkey());

    // 3. free the allocated blocks
    if (rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) {
        auto blkid = rreq->local_blkid();
        data_service().async_free_blk(blkid).thenValue([this, blkid](auto&& err) {
            HS_LOG_ASSERT(!err, "freeing blkid={} upon error failed, potential to cause blk leak", blkid.to_string());
            RD_LOGD("Rollback rreq: Releasing blkid={} freed successfully", blkid.to_string());
        });
    }
}

void RaftReplDev::handle_commit(repl_req_ptr_t rreq, bool recovery) {
    if (!rreq->has_state(repl_req_state_t::DATA_COMMITTED)) { commit_blk(rreq); }

    // Remove the request from repl_key map.
    m_repl_key_req_map.erase(rreq->rkey());
    // Remove the request from lsn map.
    m_state_machine->unlink_lsn_to_req(rreq->lsn(), rreq);

    auto cur_dsn = m_next_dsn.load(std::memory_order_relaxed);
    while (cur_dsn <= rreq->dsn()) {
        m_next_dsn.compare_exchange_strong(cur_dsn, rreq->dsn() + 1);
    }

    RD_LOGD("Raft channel: Commit rreq=[{}]", rreq->to_string());
    if (rreq->op_code() == journal_type_t::HS_CTRL_DESTROY) {
        leave();
    } else if (rreq->op_code() == journal_type_t::HS_CTRL_REPLACE) {
        replace_member(rreq);
    } else {
        m_listener->on_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq->local_blkid(), rreq);
    }

    if (!recovery) {
        auto prev_lsn = m_commit_upto_lsn.exchange(rreq->lsn());
        RD_DBG_ASSERT_GT(rreq->lsn(), prev_lsn,
                         "Out of order commit of lsns, it is not expected in RaftReplDev. cur_lsns={}, prev_lsns={}",
                         rreq->lsn(), prev_lsn);
    }
    if (!rreq->is_proposer()) { rreq->clear(); }
}

void RaftReplDev::handle_config_commit(const repl_lsn_t lsn, raft_cluster_config_ptr_t& new_conf) {
    // when reaching here, the new config has already been applied to the cluster.
    // since we didn't create repl req for config change, we just need to update m_commit_upto_lsn here.

    // keep this variable in case it is needed later
    (void)new_conf;
    auto prev_lsn = m_commit_upto_lsn.load(std::memory_order_relaxed);
    if (prev_lsn >= lsn || !m_commit_upto_lsn.compare_exchange_strong(prev_lsn, lsn)) {
        RD_LOGE("Raft Channel: unexpected log {} commited before config {} committed", prev_lsn, lsn);
    }
}

void RaftReplDev::handle_error(repl_req_ptr_t const& rreq, ReplServiceError err) {
    if (err == ReplServiceError::OK) { return; }
    RD_LOGE("Raft Channel: Error in processing rreq=[{}] error={}", rreq->to_string(), err);

    if (!rreq->add_state_if_not_already(repl_req_state_t::ERRORED)) {
        RD_LOGE("Raft Channel: Error has been added for rreq=[{}] error={}", rreq->to_string(), err);
        return;
    }

    // Remove from the map and thus its no longer accessible from applier_create_req
    m_repl_key_req_map.erase(rreq->rkey());

    // Ensure non-volatile lsn not exist because handle_error should not be called after append entries.
    auto exist_rreq = m_state_machine->lsn_to_req(rreq->lsn());
    if (exist_rreq != nullptr && !exist_rreq->is_volatile()) {
        HS_REL_ASSERT(false, "Unexpected: LSN={} is already ready to commit, exist_rreq=[{}]", rreq->lsn(),
                      exist_rreq->to_string());
    }
    if (err == ReplServiceError::DATA_DUPLICATED) {
        RD_LOGE("Raft Channel: Error in processing rreq=[{}] error={}", rreq->to_string(), err);
        m_listener->on_error(err, rreq->header(), rreq->key(), rreq);
        rreq->clear();
        return;
    }
    if (rreq->op_code() == journal_type_t::HS_DATA_LINKED) {
        // Free the blks which is allocated already
        if (rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) {
            auto blkid = rreq->local_blkid();
            data_service().async_free_blk(blkid).thenValue([blkid](auto&& err) {
                HS_LOG_ASSERT(!err, "freeing blkid={} upon error failed, potential to cause blk leak",
                              blkid.to_string());
            });
        }
    } else if (rreq->op_code() == journal_type_t::HS_CTRL_DESTROY ||
               rreq->op_code() == journal_type_t::HS_CTRL_REPLACE) {
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

void RaftReplDev::replace_member(repl_req_ptr_t rreq) {
    auto members = r_cast< const replace_members_ctx* >(rreq->header().cbytes());

    RD_LOGI("Raft repl replace_member commit member_out={} member_in={}",
            boost::uuids::to_string(members->replica_out.id), boost::uuids::to_string(members->replica_in.id));

    m_listener->on_replace_member(members->replica_out, members->replica_in);
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

// async_read and async_free_blks graceful shutdown will be handled by data_service.

folly::Future< std::error_code > RaftReplDev::async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                         bool part_of_batch) {
    if (is_stopping()) {
        LOGINFO("repl dev is being shutdown!");
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::operation_canceled));
    }
    return data_service().async_read(bid, sgs, size, part_of_batch);
}

folly::Future< std::error_code > RaftReplDev::async_free_blks(int64_t, MultiBlkId const& bid) {
    // TODO: For timeline consistency required, we should retain the blkid that is changed and write that to another
    // journal.
    if (is_stopping()) {
        LOGINFO("repl dev is being shutdown!");
        return folly::makeFuture< std::error_code >(std::make_error_code(std::errc::operation_canceled));
    }
    return data_service().async_free_blk(bid);
}

AsyncReplResult<> RaftReplDev::become_leader() {
    if (is_stopping()) {
        LOGINFO("repl dev is being shutdown!");
        return make_async_error<>(ReplServiceError::STOPPING);
    }
    incr_pending_request_num();

    return m_msg_mgr.become_leader(m_group_id).via(&folly::InlineExecutor::instance()).thenValue([this](auto&& e) {
        if (e.hasError()) {
            RD_LOGE("Error in becoming leader: {}", e.error());
            decr_pending_request_num();
            return make_async_error<>(RaftReplService::to_repl_error(e.error()));
        }
        decr_pending_request_num();
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

std::set< replica_id_t > RaftReplDev::get_active_peers() const {
    auto repl_status = get_replication_status();
    std::set< replica_id_t > res;
    auto my_committed_idx = m_commit_upto_lsn.load();
    uint64_t least_active_repl_idx = my_committed_idx > HS_DYNAMIC_CONFIG(consensus.laggy_threshold)
        ? my_committed_idx - HS_DYNAMIC_CONFIG(consensus.laggy_threshold)
        : 0;
    // peer's last log idx should also >= leader's start_index-1(ensure existence), otherwise leader can't append log
    // entries to it and baseline resync will be triggerred. Try to avoid conflict between baseline resync and normal
    // replication.
    least_active_repl_idx = std::max(least_active_repl_idx, m_data_journal->start_index() - 1);
    for (auto p : repl_status) {
        if (p.id_ == m_my_repl_id) { continue; }
        if (p.replication_idx_ >= least_active_repl_idx) {
            res.insert(p.id_);
        } else {
            RD_LOGW("Excluding peer {} from active_peers, lag {}, my lsn {}, peer lsn {}, least_active_repl_idx {}",
                    p.id_, my_committed_idx - p.replication_idx_, my_committed_idx, p.replication_idx_,
                    least_active_repl_idx);
        }
    }
    return res;
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
    RD_LOGI("Saved config {}", (*m_raft_config_sb)["config"].dump());
}

void RaftReplDev::save_state(const nuraft::srv_state& state) {
    std::unique_lock lg{m_config_mtx};
    (*m_raft_config_sb)["state"] = nlohmann::json{{"term", state.get_term()},
                                                  {"voted_for", state.get_voted_for()},
                                                  {"election_timer_allowed", state.is_election_timer_allowed()},
                                                  {"catching_up", state.is_catching_up()}};
    m_raft_config_sb.write();
    RD_LOGI("Saved state {}", (*m_raft_config_sb)["state"].dump());
}

nuraft::ptr< nuraft::srv_state > RaftReplDev::read_state() {
    std::unique_lock lg{m_config_mtx};
    auto& js = *m_raft_config_sb;
    auto state = nuraft::cs_new< nuraft::srv_state >();
    if (js["state"].empty()) {
        js["state"] = nlohmann::json{{"term", state->get_term()},
                                     {"voted_for", state->get_voted_for()},
                                     {"election_timer_allowed", state->is_election_timer_allowed()},
                                     {"catching_up", state->is_catching_up()}};
    } else {
        try {
            state->set_term(uint64_cast(js["state"]["term"]));
            state->set_voted_for(static_cast< int >(js["state"]["voted_for"]));
            state->allow_election_timer(static_cast< bool >(js["state"]["election_timer_allowed"]));
            state->set_catching_up(static_cast< bool >(js["state"]["catching_up"]));
        } catch (std::out_of_range const&) {
            LOGWARN("State data was not in the expected format [group_id={}]!", m_group_id)
        }
    }
    return state;
}

nuraft::ptr< nuraft::log_store > RaftReplDev::load_log_store() { return m_data_journal; }

int32_t RaftReplDev::server_id() { return m_raft_server_id; }

bool RaftReplDev::is_destroy_pending() const { return (*m_stage.access().get() == repl_dev_stage_t::DESTROYED); }
bool RaftReplDev::is_destroyed() const { return (*m_stage.access().get() == repl_dev_stage_t::PERMANENT_DESTROYED); }

///////////////////////////////////  nuraft_mesg::mesg_state_mgr overrides ////////////////////////////////////
void RaftReplDev::become_ready() {
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::ACTIVE; });
}

uint32_t RaftReplDev::get_logstore_id() const { return m_data_journal->logstore_id(); }

std::shared_ptr< nuraft::state_machine > RaftReplDev::get_state_machine() { return m_state_machine; }

void RaftReplDev::permanent_destroy() {
    RD_LOGI("Permanent destroy for raft repl dev group_id={}", group_id_str());
    // let the listener know at first, so that they can cleanup persistent structures before raft repl dev is destroyed
    m_listener->on_destroy(group_id());
    m_raft_config_sb.destroy();
    m_data_journal->remove_store();
    logstore_service().destroy_log_dev(m_data_journal->logdev_id());
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::PERMANENT_DESTROYED; });
    // we should destroy repl_dev superblk only after all the resources are cleaned up, so that is crash recovery
    // occurs, we have a chance to find the stale repl_dev and reclaim all the stale resources.
    m_rd_sb.destroy();
}

void RaftReplDev::leave() {
    // this will be called in 3 cases :
    //  1. commit log entry of journal_type_t::HS_CTRL_DESTROY
    //  2. it is removed from the cluster and the new config(excluding this node) is being committed on this node
    //  3. it is removed from the cluster , but the node is down and new config log(excluding this node) is not
    //  replicated to this removed node. when the node restart, leader will not send any append entry to this node,
    //  since it is not a member of the raft group. it will become a condidate and send request-vote request to other
    //  members of this raft group. a member will send RemovedFromCluster to the node if this member finds the node
    //  is no longer a member of the raft group.

    // leave() will never be called concurrently, since config change and journal_type_t::HS_CTRL_DESTROY are all log
    // entry, which will be committed sequentially.
    if (is_destroy_pending()) return;

    // We update that this repl_dev in destroyed state, actual clean up of resources happen in reaper thread later
    m_stage.update([](auto* stage) { *stage = repl_dev_stage_t::DESTROYED; });
    m_destroyed_time = Clock::now();

    // Persist that destroy pending in superblk, so that in case of crash before cleanup of resources, it can be done
    // post restart.
    m_rd_sb->destroy_pending = 0x1;
    m_rd_sb.write();

    RD_LOGI("RaftReplDev leave group_id={}", group_id_str());
    m_destroy_promise.setValue(ReplServiceError::OK); // In case proposer is waiting for the destroy to complete
}

nuraft::cb_func::ReturnCode RaftReplDev::raft_event(nuraft::cb_func::Type type, nuraft::cb_func::Param* param) {
    auto ret = nuraft::cb_func::ReturnCode::Ok;

    switch (type) {
    case nuraft::cb_func::Type::GotAppendEntryReqFromLeader: {
        auto raft_req = r_cast< nuraft::req_msg* >(param->ctx);
        auto const& entries = raft_req->log_entries();

        auto start_lsn = raft_req->get_last_log_idx() + 1;
        RD_LOGD("Raft channel: Received {} append entries on follower from leader, term {}, lsn {} ~ {} , my commited "
                "lsn {} , leader commmited lsn {}",
                entries.size(), raft_req->get_last_log_term(), start_lsn, start_lsn + entries.size() - 1,
                m_commit_upto_lsn.load(), raft_req->get_commit_idx());

        if (!entries.empty()) {
            RD_LOGT("Raft channel: Received {} append entries on follower from leader, localizing them",
                    entries.size());

            auto reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
            auto last_commit_lsn = uint64_cast(get_last_commit_lsn());
            for (unsigned long i = 0; i < entries.size(); i++) {
                auto& entry = entries[i];
                auto lsn = start_lsn + i;
                auto term = entry->get_term();
                if (entry->get_val_type() != nuraft::log_val_type::app_log) { continue; }
                if (entry->get_buf_ptr()->size() == 0) { continue; }
                // skipping localize for already committed log(dup), they anyway will be discard
                // by nuraft before append_log.
                if (lsn <= last_commit_lsn) {
                    RD_LOGT("Raft channel: term {}, lsn {}, skipping dup, last_commit_lsn {}", term, lsn,
                            last_commit_lsn);
                    continue;
                }
                // Those LSNs already in logstore but not yet committed, will be dedup here,
                // applier_create_req will return same req as previous one
                auto req = m_state_machine->localize_journal_entry_prepare(*entry);
                if (req == nullptr) {
                    sisl::VectorPool< repl_req_ptr_t >::free(reqs);
                    // The hint set here will be used by the next after next appendEntry, the next one
                    // always go with -1 from NuRraft code.
                    //
                    // We are rejecting this log entry, meaning we can accept previous log entries.
                    // If there is nothing we can accept(i==0), that maens we are waiting for commit
                    // of previous lsn, set it to 1 in this case.
                    m_state_machine->reset_next_batch_size_hint(std::max(1ul, i));
                    return nuraft::cb_func::ReturnCode::ReturnNull;
                }
                reqs->emplace_back(std::move(req));
            }

            // Wait till we receive the data from its originator for all the requests
            std::vector< repl_req_ptr_t > timeout_rreqs;
            if (!wait_for_data_receive(*reqs, HS_DYNAMIC_CONFIG(consensus.data_receive_timeout_ms), &timeout_rreqs)) {
                for (auto const& rreq : timeout_rreqs) {
                    handle_error(rreq, ReplServiceError::TIMEOUT);
                }
                ret = nuraft::cb_func::ReturnCode::ReturnNull;
            }
            sisl::VectorPool< repl_req_ptr_t >::free(reqs);
        }
        if (ret == nuraft::cb_func::ReturnCode::Ok) { m_state_machine->inc_next_batch_size_hint(); }
        return ret;
    }
    case nuraft::cb_func::Type::JoinedCluster:
        RD_LOGD("Raft channel: Received JoinedCluster, implies become_follower");
        become_follower_cb();
        return nuraft::cb_func::ReturnCode::Ok;
    case nuraft::cb_func::Type::BecomeFollower: {
        RD_LOGD("Raft channel: Received BecomeFollower");
        become_follower_cb();
        return nuraft::cb_func::ReturnCode::Ok;
    }
    case nuraft::cb_func::Type::BecomeLeader: {
        RD_LOGD("Raft channel: Received BecomeLeader");
        become_leader_cb();
        return nuraft::cb_func::ReturnCode::Ok;
    }

    // RemovedFromCluster will be handled in nuraft_mesg::generic_raft_event_handler where leave() is called

    // TODO: Add more type handler if necessary
    default:
        break;
    }
    return nuraft::cb_func::ReturnCode::Ok;
}

void RaftReplDev::flush_durable_commit_lsn() {
    if (is_destroyed()) {
        RD_LOGI("Raft repl dev is destroyed, ignore flush durable commmit lsn");
        return;
    }

    auto const lsn = m_commit_upto_lsn.load();
    std::unique_lock lg{m_sb_mtx};
    m_rd_sb->durable_commit_lsn = lsn;
    m_rd_sb.write();
}

///////////////////////////////////  Private metohds ////////////////////////////////////
void RaftReplDev::cp_flush(CP* cp, cshared< ReplDevCPContext > ctx) {
    if (is_destroyed()) {
        RD_LOGI("Raft repl dev is destroyed, ignore cp flush");
        return;
    }

    auto const lsn = ctx->cp_lsn;
    auto const clsn = ctx->compacted_to_lsn;
    auto const dsn = ctx->last_applied_dsn;

    if (lsn == m_last_flushed_commit_lsn) {
        // Not dirtied since last flush ignore
        return;
    }

    std::unique_lock lg{m_sb_mtx};
    m_rd_sb->compact_lsn = clsn;
    // dc_lsn is also flushed in flush_durable_commit_lsn()
    // we need to take a max to avoid rolling back.
    m_rd_sb->durable_commit_lsn = std::max(lsn, m_rd_sb->durable_commit_lsn);
    m_rd_sb->checkpoint_lsn = lsn;
    m_rd_sb->last_applied_dsn = dsn;
    m_rd_sb.write();
    m_last_flushed_commit_lsn = lsn;
    RD_LOGD("cp flush in raft repl dev, lsn={}, clsn={}, next_dsn={}, cp string:{}", lsn, clsn, m_next_dsn.load(),
            cp->to_string());
}

cshared< ReplDevCPContext > RaftReplDev::get_cp_ctx(CP* cp) {
    auto const cp_lsn = m_commit_upto_lsn.load();
    auto const clsn = m_compact_lsn.load();
    auto const dsn = m_next_dsn.load();

    RD_LOGD("getting cp_ctx for raft repl dev {}, cp_lsn={}, clsn={}, next_dsn={}, cp string:{}", (void*)this, cp_lsn,
            clsn, dsn, cp->to_string());
    auto dev_ctx = std::make_shared< ReplDevCPContext >();
    dev_ctx->cp_lsn = cp_lsn;
    dev_ctx->compacted_to_lsn = clsn;
    dev_ctx->last_applied_dsn = dsn;
    return dev_ctx;
}

void RaftReplDev::cp_cleanup(CP*) {}

void RaftReplDev::gc_repl_reqs() {
    auto cur_dsn = m_next_dsn.load();
    if (cur_dsn != 0) cur_dsn = cur_dsn - 1;
    // On follower, DSN below cur_dsn should very likely be commited.
    // It is not guaranteed because DSN and LSN are generated separately,
    // DSN in async_alloc_write before pushing data, LSN later when
    // proposing to raft. Two simultaneous write requests on leader can have
    // <LSN=100, DSN=102> and <LSN=101, DSN =101> during the window.
    std::vector< repl_req_ptr_t > expired_rreqs;

    auto req_map_size = m_repl_key_req_map.size();
    RD_LOGI("m_repl_key_req_map size is {};", req_map_size);
    for (auto [key, rreq] : m_repl_key_req_map) {
        // FIXME: Skipping proposer for now, the DSN in proposer increased in proposing stage, not when commit().
        // Need other mechanism.
        if (rreq->is_proposer()) {
            // don't clean up proposer's request
            continue;
        }
        if (rreq->dsn() < cur_dsn && rreq->is_expired()) {
            // The DSN can be out of order, wait till rreq expired.
            RD_LOGD("legacy req with commited DSN, rreq=[{}] , dsn = {}, next_dsn = {}, gap= {}, elapsed_time_sec {}",
                    rreq->to_string(), rreq->dsn(), cur_dsn, cur_dsn - rreq->dsn(),
                    get_elapsed_time_sec(rreq->created_time()));
            expired_rreqs.push_back(rreq);
        }
    }
    int sm_req_cnt = 0;
    // FIXME: we ensured data written before appending log to log store, in which we add rreq to state_machine
    // and during pre-commit/commit we retrieve rreq from state_machine. Removing requests outside of state
    // machine is risky.
    // Below logs are logging only, can be removed once we get more confidence.
    m_state_machine->iterate_repl_reqs([this, cur_dsn, &sm_req_cnt](auto key, auto rreq) {
        sm_req_cnt++;
        if (rreq->is_proposer()) {
            // don't clean up proposer's request
            return;
        }
        if (rreq->is_expired()) {
            RD_LOGD("StateMachine: rreq=[{}] is expired, elapsed_time_sec{};", rreq->to_string(),
                    get_elapsed_time_sec(rreq->created_time()));
        }
    });
    RD_LOGI("state_machine req map size is {};", sm_req_cnt);

    for (auto removing_rreq : expired_rreqs) {
        // once log flushed, the commit progress controlled by raft
        if (removing_rreq->has_state(repl_req_state_t::LOG_FLUSHED)) {
            RD_LOGI("Skipping GC rreq [{}] because it is in state machine", removing_rreq->to_string());
            continue;
        }
        // do garbage collection
        // 1. free the allocated blocks
        RD_LOGI("Removing rreq [{}]", removing_rreq->to_string());
        if (removing_rreq->has_state(repl_req_state_t::BLK_ALLOCATED)) {
            auto blkid = removing_rreq->local_blkid();
            data_service().async_free_blk(blkid).thenValue([this, blkid](auto&& err) {
                HS_LOG_ASSERT(!err, "freeing blkid={} upon error failed, potential to cause blk leak",
                              blkid.to_string());
                RD_LOGD("GC rreq: Releasing blkid={} freed successfully", blkid.to_string());
            });
        }
        // 2. remove from the m_repl_key_req_map
        if (m_repl_key_req_map.find(removing_rreq->rkey()) != m_repl_key_req_map.end()) {
            m_repl_key_req_map.erase(removing_rreq->rkey());
        }
    }
}

void RaftReplDev::set_log_store_last_durable_lsn(store_lsn_t lsn) { m_data_journal->set_last_durable_lsn(lsn); }

void RaftReplDev::on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx) {
    auto repl_lsn = to_repl_lsn(lsn);
    // apply the log entry if the lsn is between checkpoint lsn and durable commit lsn
    if (repl_lsn <= m_rd_sb->checkpoint_lsn) { return; }

    // 1. Get the log entry and prepare rreq
    auto const lentry = to_nuraft_log_entry(buf);

    // TODO: Handle the case where the log entry is not app_log, example config logs
    if (lentry->get_val_type() != nuraft::log_val_type::app_log) { return; }

    repl_journal_entry* jentry = r_cast< repl_journal_entry* >(lentry->get_buf().data_begin());
    RELEASE_ASSERT_EQ(jentry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                      "Mismatched version of journal entry received from RAFT peer");

    RD_LOGT("Raft Channel: Applying Raft log_entry upon recovery: server_id={}, term={}, lsn={}, journal_entry=[{}] ",
            jentry->server_id, lentry->get_term(), repl_lsn, jentry->to_string());

    auto entry_to_hdr = [](repl_journal_entry* jentry) {
        return sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry), jentry->user_header_size};
    };

    auto entry_to_key = [](repl_journal_entry* jentry) {
        return sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry) + jentry->user_header_size,
                          jentry->key_size};
    };

    auto entry_to_val = [](repl_journal_entry* jentry) {
        return sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry) + jentry->user_header_size +
                              jentry->key_size,
                          jentry->value_size};
    };

    repl_key const rkey{.server_id = jentry->server_id, .term = lentry->get_term(), .dsn = jentry->dsn};

    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT((it != m_repl_key_req_map.end()), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;
    RD_DBG_ASSERT(happened, "rreq already exists for rkey={}", rkey.to_string());
    uint32_t data_size{0u};

    // If the data is linked and value_size is non-zero, it means blks have been allocated for data.
    // Since the log is flushed after data is written, the data has already been received.
    if ((jentry->code == journal_type_t::HS_DATA_LINKED) && (jentry->value_size > 0)) {
        MultiBlkId entry_blkid;
        entry_blkid.deserialize(entry_to_val(jentry), true /* copy */);
        data_size = entry_blkid.blk_count() * get_blk_size();
        rreq->set_local_blkid(entry_blkid);
        rreq->add_state(repl_req_state_t::BLK_ALLOCATED);
        rreq->add_state(repl_req_state_t::DATA_RECEIVED);
    }

    rreq->set_lsn(repl_lsn);
    // keep lentry in scope for the lyfe cycle of the rreq
    rreq->set_lentry(lentry);
    auto status = rreq->init(rkey, jentry->code, false /* is_proposer */, entry_to_hdr(jentry), entry_to_key(jentry),
                             data_size, m_listener);
    if (status != ReplServiceError::OK) {
        RD_LOGE("Initializing rreq failed, rreq=[{}], error={}", rreq->to_string(), status);
    }

    // we load the log from log device, implies log flushed.  We only flush log after data is written to data device.
    rreq->add_state(repl_req_state_t::DATA_WRITTEN);
    rreq->add_state(repl_req_state_t::LOG_RECEIVED);
    rreq->add_state(repl_req_state_t::LOG_FLUSHED);
    RD_LOGD("Replay log on restart, rreq=[{}]", rreq->to_string());

    // 2. Pre-commit the log entry as in nuraft pre-commit was called once log appended to logstore.
    m_listener->on_pre_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq);

    // LSN above dc_lsn we forgot their states,  they can either
    // a. be committed before, but DC_LSN not yet flushed
    // b. not yet committed,  might be committed or rollback
    if (repl_lsn > m_rd_sb->durable_commit_lsn) {
        // In memory state of these blks is lost. Commit them now to avoid usage of same blk twice.
        commit_blk(rreq);
        // add rreq to state machine, state-machine will decide to commit or rollback this rreq.
        m_state_machine->link_lsn_to_req(rreq, int64_cast(repl_lsn));
        return;
    }

    // 3. Commit the log entry
    handle_commit(rreq, true /* recovery */);
}

void RaftReplDev::create_snp_resync_data(raft_buf_ptr_t& data_out) {
    snp_repl_dev_data msg;
    auto msg_size = sizeof(snp_repl_dev_data);
    msg.dsn = m_next_dsn;
    auto crc = crc32_ieee(init_crc32, reinterpret_cast< const unsigned char* >(&msg), msg_size);
    RD_LOGD("create snapshot resync msg, dsn={}, crc={}", msg.dsn, crc);
    msg.crc = crc;
    data_out = nuraft::buffer::alloc(msg_size);
    std::memcpy(data_out->data_begin(), &msg, msg_size);
}

bool RaftReplDev::save_snp_resync_data(nuraft::buffer& data) {
    auto msg = r_cast< snp_repl_dev_data* >(data.data_begin());
    if (msg->magic_num != HOMESTORE_RESYNC_DATA_MAGIC ||
        msg->protocol_version != HOMESTORE_RESYNC_DATA_PROTOCOL_VERSION_V1) {
        RD_LOGE("Snapshot resync data validation failed, magic={}, version={}", msg->magic_num, msg->protocol_version);
        return false;
    }
    auto received_crc = msg->crc;
    RD_LOGD("received snapshot resync msg, dsn={}, crc={}, received crc={}", msg->dsn, msg->crc, received_crc);
    // Clear the crc field before verification, because the crc value computed by leader doesn't contain it.
    msg->crc = 0;
    auto computed_crc =
        crc32_ieee(init_crc32, reinterpret_cast< const unsigned char* >(msg), sizeof(snp_repl_dev_data));
    if (received_crc != computed_crc) {
        RD_LOGE("Snapshot resync data crc mismatch, received_crc={}, computed_crc={}", received_crc, computed_crc);
        return false;
    }
    if (msg->dsn > m_next_dsn) {
        m_next_dsn = msg->dsn;
        RD_LOGD("Update next_dsn from {} to {}", m_next_dsn.load(), msg->dsn);
        return true;
    }
    return true;
}

void RaftReplDev::on_restart() { m_listener->on_restart(); }

bool RaftReplDev::is_resync_mode() {
    int64_t const leader_commited_lsn = raft_server()->get_leader_committed_log_idx();
    int64_t const my_log_idx = raft_server()->get_last_log_idx();
    auto diff = leader_commited_lsn - my_log_idx;
    bool resync_mode = (diff > HS_DYNAMIC_CONFIG(consensus.resync_log_idx_threshold));
    if (resync_mode) {
        RD_LOGD("Raft Channel: Resync mode, leader_commited_lsn={}, my_log_idx={}, diff={}", leader_commited_lsn,
                my_log_idx, diff);
    }
    return resync_mode;
}

} // namespace homestore
