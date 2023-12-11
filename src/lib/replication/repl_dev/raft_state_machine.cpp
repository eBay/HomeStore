#include <iomgr/iomgr_timer.hpp>
#include <sisl/logging/logging.h>
#include <sisl/fds/utils.hpp>
#include <sisl/fds/vector_pool.hpp>

#include "repl_dev/raft_state_machine.h"
#include "repl_dev/raft_repl_dev.h"

SISL_LOGGING_DECL(replication)

namespace homestore {

RaftStateMachine::RaftStateMachine(RaftReplDev& rd) : m_rd{rd} {
    m_success_ptr = nuraft::buffer::alloc(sizeof(int));
    m_success_ptr->put(0);
}

raft_buf_ptr_t RaftStateMachine::pre_commit_ext(nuraft::state_machine::ext_op_params const& params) {
    // Leader precommit is processed in next callback, since lsn would not have been known to repl layer till we get
    // the next callback.
    if (!m_rd.is_leader()) {
        int64_t lsn = s_cast< int64_t >(params.log_idx);
        raft_buf_ptr_t data = params.data;

        repl_req_ptr_t rreq = lsn_to_req(lsn);
        RD_LOG(INFO, "Raft channel: Precommit rreq=[{}]", rreq->to_compact_string());
        m_rd.m_listener->on_pre_commit(rreq->lsn, rreq->header, rreq->key, rreq);
    }
    return m_success_ptr;
}

void RaftStateMachine::after_precommit_in_leader(nuraft::raft_server::req_ext_cb_params const& params) {
    repl_req_ptr_t rreq = repl_req_ptr_t(r_cast< repl_req_ctx* >(params.context));
    link_lsn_to_req(rreq, int64_cast(params.log_idx));

    RD_LOG(INFO, "Raft Channel: Proposed rreq=[{}]", rreq->to_compact_string());
    m_rd.m_listener->on_pre_commit(rreq->lsn, rreq->header, rreq->key, rreq);
}

raft_buf_ptr_t RaftStateMachine::commit_ext(nuraft::state_machine::ext_op_params const& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);
    raft_buf_ptr_t data = params.data;

    repl_req_ptr_t rreq = lsn_to_req(lsn);
    if (rreq == nullptr) { return m_success_ptr; }

    RD_LOG(INFO, "Raft channel: Received Commit message rreq=[{}]", rreq->to_compact_string());
    if (m_rd.is_leader()) {
        // This is the time to ensure flushing of journal happens in leader
        if (m_rd.m_data_journal->last_durable_index() < uint64_cast(lsn)) { m_rd.m_data_journal->flush(); }
        rreq->state.fetch_or(uint32_cast(repl_req_state_t::LOG_FLUSHED));
    }
    if (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
        m_lsn_req_map.erase(rreq->lsn);
        m_rd.report_committed(rreq);
    }
    return m_success_ptr;
}

uint64_t RaftStateMachine::last_commit_index() { return uint64_cast(m_rd.get_last_commit_lsn()); }

void RaftStateMachine::propose_to_raft(repl_req_ptr_t rreq) {
    uint32_t val_size = rreq->value.size ? rreq->local_blkid.serialized_size() : 0;
    uint32_t entry_size = sizeof(repl_journal_entry) + rreq->header.size() + rreq->key.size() + val_size;
    rreq->alloc_journal_entry(entry_size, true /* raft_buf */);
    rreq->journal_entry->code = (rreq->value.size) ? journal_type_t::HS_LARGE_DATA : journal_type_t::HS_HEADER_ONLY;
    rreq->journal_entry->server_id = m_rd.server_id();
    rreq->journal_entry->dsn = rreq->dsn();
    rreq->journal_entry->user_header_size = rreq->header.size();
    rreq->journal_entry->key_size = rreq->key.size();
    rreq->journal_entry->value_size = val_size;

    rreq->is_proposer = true;
    uint8_t* raw_ptr = uintptr_cast(rreq->journal_entry) + sizeof(repl_journal_entry);
    if (rreq->header.size()) {
        std::memcpy(raw_ptr, rreq->header.cbytes(), rreq->header.size());
        raw_ptr += rreq->header.size();
    }

    if (rreq->key.size()) {
        std::memcpy(raw_ptr, rreq->key.cbytes(), rreq->key.size());
        raw_ptr += rreq->key.size();
    }

    if (rreq->value.size) {
        auto const b = rreq->local_blkid.serialize();
        std::memcpy(raw_ptr, b.cbytes(), b.size());
        raw_ptr += b.size();
    }

    auto* vec = sisl::VectorPool< raft_buf_ptr_t >::alloc();
    vec->push_back(rreq->raft_journal_buf());

    nuraft::raft_server::req_ext_params param;
    param.after_precommit_ = bind_this(RaftStateMachine::after_precommit_in_leader, 1);
    param.expected_term_ = 0;
    param.context_ = voidptr_cast(rreq.get());

    RD_LOG(TRACE, "Raft Channel: journal_entry=[{}] ", rreq->journal_entry->to_string());

    m_rd.raft_server()->append_entries_ext(*vec, param);
    sisl::VectorPool< raft_buf_ptr_t >::free(vec);
}

repl_req_ptr_t RaftStateMachine::transform_journal_entry(nuraft::ptr< nuraft::log_entry >& lentry) {
    // Leader has nothing to transform or process
    if (m_rd.is_leader()) { return nullptr; }

    // We don't want to transform anything that is not an app log
    if (lentry->get_val_type() != nuraft::log_val_type::app_log) { return nullptr; }

    repl_journal_entry* jentry = r_cast< repl_journal_entry* >(lentry->get_buf().data_begin());
    RELEASE_ASSERT_EQ(jentry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                      "Mismatched version of journal entry received from RAFT peer");

    RD_LOG(TRACE, "Received Raft log_entry=[term={}], journal_entry=[{}] ", lentry->get_term(), jentry->to_string());

    // For inline data we don't need to transform anything
    if (jentry->code != journal_type_t::HS_LARGE_DATA) { return nullptr; }

    sisl::blob const header = sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry), jentry->user_header_size};
    sisl::blob const key = sisl::blob{header.cbytes() + header.size(), jentry->key_size};
    DEBUG_ASSERT_GT(jentry->value_size, 0, "Entry marked as large data, but value size is notified as 0");

    // From the repl_key, get the repl_req. In cases where log stream got here first, this method will create a new
    // repl_req and return that back. Fill up all of the required journal entry inside the repl_req
    auto rreq = m_rd.follower_create_req(
        repl_key{.server_id = jentry->server_id, .term = lentry->get_term(), .dsn = jentry->dsn}, header, key,
        jentry->value_size);
    rreq->journal_buf = lentry->serialize();

    MultiBlkId entry_blkid;
    entry_blkid.deserialize(sisl::blob{key.cbytes() + key.size(), jentry->value_size}, true /* copy */);
    rreq->remote_blkid = RemoteBlkId{jentry->server_id, entry_blkid};

    auto const local_size = rreq->local_blkid.serialized_size();
    auto const remote_size = entry_blkid.serialized_size();
    uint8_t* blkid_location;
    if (local_size > remote_size) {
        // We need to copy the entire log_entry to accomodate local blkid
        auto new_buf = nuraft::buffer::expand(*rreq->raft_journal_buf(),
                                              rreq->raft_journal_buf()->size() + local_size - remote_size);
        blkid_location = uintptr_cast(new_buf->data_begin()) + rreq->raft_journal_buf()->size() - jentry->value_size;
        rreq->journal_buf = std::move(new_buf);
    } else {
        // Can do in-place replace of remote blkid with local blkid.
        blkid_location = uintptr_cast(rreq->raft_journal_buf()->data_begin()) + rreq->raft_journal_buf()->size() -
            jentry->value_size;
    }
    std::memcpy(blkid_location, rreq->local_blkid.serialize().cbytes(), local_size);
    rreq->journal_entry = r_cast< repl_journal_entry* >(rreq->raft_journal_buf()->data_begin());

    return rreq;
}

void RaftStateMachine::link_lsn_to_req(repl_req_ptr_t rreq, int64_t lsn) {
    rreq->lsn = lsn;
    rreq->state.fetch_or(uint32_cast(repl_req_state_t::LOG_RECEIVED));
    [[maybe_unused]] auto r = m_lsn_req_map.insert(lsn, std::move(rreq));
    RD_DBG_ASSERT_EQ(r.second, true, "lsn={} already in precommit list", lsn);
}

repl_req_ptr_t RaftStateMachine::lsn_to_req(int64_t lsn) {
    // Pull the req from the lsn
    auto const it = m_lsn_req_map.find(lsn);
    // RD_DBG_ASSERT(it != m_lsn_req_map.cend(), "lsn req map missing lsn={}", lsn);
    if (it == m_lsn_req_map.cend()) { return nullptr; }

    repl_req_ptr_t rreq = it->second;
    RD_DBG_ASSERT_EQ(lsn, rreq->lsn, "lsn req map mismatch");
    return rreq;
}

nuraft_mesg::repl_service_ctx* RaftStateMachine::group_msg_service() { return m_rd.group_msg_service(); }

void RaftStateMachine::create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    RD_LOG(DEBUG, "create_snapshot {}/{}", s.get_last_log_idx(), s.get_last_log_term());
    auto null_except = std::shared_ptr< std::exception >();
    auto ret_val{false};
    if (when_done) when_done(ret_val, null_except);
}

std::string RaftStateMachine::rdev_name() const { return m_rd.rdev_name(); }

#if 0
void RaftStateMachine::stop_write_wait_timer() {
    if (m_wait_blkid_write_timer_hdl != iomgr::null_timer_handle) {
        iomanager.cancel_timer(m_wait_blkid_write_timer_hdl);
        m_wait_blkid_write_timer_hdl = iomgr::null_timer_handle;
    }
}

void RaftStateMachine::check_and_fetch_remote_data(std::vector< repl_req_ptr_t >&& rreqs, AsyncNotifier p) {
    for (auto const& rreq : rreqs) {
        if (!(rreq->state.load() & uint32_cast(repl_req_state_t::DATA_RECEIVED))) {
            // found some blkid not completed yet, save to the remote list;
            remote_fetch_blkids->emplace_back(fb);
        }
    }

    if (remote_fetch_blkids->size()) {
        // we've got some blkids not completed yet, let's fetch from remote;
        fetch_blkid_data_from_leader(std::move(remote_fetch_blkids));
    }
}

//
// if return false /* no need to wait */, no cb will be triggered;
// if return true /* need to wait */ , cb will be triggered after all local blkids completed writting;
//
bool RaftStateMachine::async_fetch_write_blkids(std::vector< RemoteBlkId > const& remote_blkids,
                                                batch_completion_cb_t cb) {
    std::vector< RemoteBlkId > wait_to_fill_remote_blkids;

    remote_blkids.erase(std::remove_if(remote_blkids.begin(), remote_blkids.end(),
                                       [this](RemoteBlkId const& rblkid) {
                                           auto it = m_blkid_map.find(rblkid);
                                           if (it == m_blkid_map.end()) {
                                               auto const [local_blkid, state] = try_map_blkid(rblkid);
                                               it = m_blkid_map.find(rblkid);

                                               // add this fq_blkid to wait list;
                                               wait_to_fill_remote_blkids.emplace_back(rblkid);

                                               // fall through;
                                           }

                                           // now "it" points to either newly created map entry or already existed
                                           // entry;
                                           if (it->second->m_state != blkid_state_t::completed) {
                                               // same waiter can wait on multiple fq_blkids;
                                               RD_DBG_ASSERT(!it->second->m_waiter,
                                                             "not expecting to apply waiter on already waited entry.");
                                               it->second->m_waiter = std::make_shared< blkid_waiter >(std::move(cb));
                                           }
                                       }),
                        remote_blkids.end());

    for (const auto& rblkid : remote_blkids) {
        auto it = m_blkid_map.find(rblkid);
        if (it == m_blkid_map.end()) {
            auto const [local_blkid, state] = try_map_blkid(rblkid);
            it = m_blkid_map.find(rblkid);

            // add this fq_blkid to wait list;
            wait_to_fill_remote_blkids.emplace_back(rblkid);

            // fall through;
        }

        // now "it" points to either newly created map entry or already existed entry;
        if (it->second->m_state != blkid_state_t::completed) {
            // same waiter can wait on multiple fq_blkids;
            RD_DBG_ASSERT(!it->second->m_waiter, "not expecting to apply waiter on already waited entry.");
            it->second->m_waiter = std::make_shared< blkid_waiter >(std::move(cb));
        }
    }

    const auto wait_size = wait_to_fill_remote_blkids.size();
#if __cplusplus > 201703L
    [[unlikely]] if (m_resync_mode) {
#else
    if (sisl_unlikely(m_resync_mode)) {
#endif
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_blkids(std::move(wait_to_fill_fq_blkids));
    } else if (wait_size) {
        // some blkids are not in completed state, let's schedule a timer to check it again;
        // either we wait for data channel to fill in the data or we wait for certain time and trigger a fetch from
        // remote;
        m_wait_blkid_write_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(repl->wait_blkid_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, &wait_to_fill_fq_blkids]([[maybe_unused]] void* cookie) {
                // check input fq_blkids to see if they completed write, if there is
                // still any fq_blkid not completed yet, trigger a remote fetch
                check_and_fetch_remote_blkids(std::move(wait_to_fill_fq_blkids));
            });
    }

    // if size is not zero, it means caller needs to wait;
    return wait_size != 0;
}

void RaftStateMachine::check_and_fetch_remote_blkids(std::vector< RemoteBlkId > const& fq_blkid_list) {
    auto remote_fetch_blkids = std::make_unique< std::vector< RemoteBlkId > >();
    for (const auto& fb : fq_blkid_list) {
        auto it = m_blkid_map.find(fb);
        if (it->second->m_state != blkid_state_t::completed) {
            // found some blkid not completed yet, save to the remote list;
            remote_fetch_blkids->emplace_back(fb);
        }
    }

    if (remote_fetch_blkids->size()) {
        // we've got some blkids not completed yet, let's fetch from remote;
        fetch_blkid_data_from_leader(std::move(remote_fetch_blkids));
    }
}

//
// for the same fq_blkid, if caller calls it concurrently with different state, result is undetermined;
//
blkid_state_t RaftStateMachine::update_map_blkid(RemoteBlkId const& remote_blkid, blkid_state_t const& state) {
    RD_DBG_ASSERT(state != blkid_state_t::unknown && state != blkid_state_t::allocated,
                  "invalid state, not expecting update to state: {}", state);
    auto it = m_blkid_map.find(remote_blkid);
    const auto old_state = it->second->m_state;
    it->second->m_state = state;

    if ((state == blkid_state_t::completed) && (it->second->m_waiter != nullptr)) {
        // waiter on this fq_blkid can be released.
        // if this is the last fq_blkid that this waiter is waiting on, cb will be triggered automatically;
        RD_DBG_ASSERT_EQ(old_state, blkid_state_t::written, "invalid state, not expecting state to be: {}", state);
        it->second->m_waiter.reset();
    }

    return old_state;
}

std::size_t RaftStateMachine::remove_map_blkid(RemoteBlkId const& fq_blkid) { return m_blkid_map.erase(fq_blkid); }

void RaftStateMachine::fetch_blkid_data_from_leader(std::unique_ptr< std::vector< RemoteBlkId > > fq_blkid_list) {
    blkid_list_t remote_blkids;
    for (auto const& fq_blkid : *fq_blkid_list) {
        remote_blkids.push_back(fq_blkid.blkid);
    }
    m_rd->fetch_blkid_data_from_leader(remote_blkids);
}

void RaftStateMachine::create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    RD_LOG(DEBUG, "create_snapshot {}/{}", s.get_last_log_idx(), s.get_last_log_term());
    auto null_except = std::shared_ptr< std::exception >();
    auto ret_val{false};
    if (when_done) when_done(ret_val, null_except);
}

blkid_state_t RaftStateMachine::get_blkid_state(RemoteBlkId const& fq_blkid) const {
    const auto key_string = fq_blkid.to_key_string();
    const auto it = m_blkid_map.find(key_string);
    return (it != m_blkid_map.end()) ? it->second->m_state : blkid_state_t::unknown;
}

void RaftStateMachine::on_data_received(sisl::io_blob const& incoming_buf,
                                        boost::intrusive_ptr< sisl::GenericRpcData >& rpc_data) {
    // deserialize incoming buf and get fq blkid list and the data to be written
    auto it = m_rpc_generator->deserialize(incoming_buf);

    sisl::sg_iterator sg_itr(value.iovs);
    auto futs = sisl::VectorPool< AsyncNotify >::alloc();

    while (it.has_more()) {
        auto const [remote_blkid, usr_hdr_blob, value_blob] = it.next();

        auto entry = mapper_get_entry(remote_blkid, usr_hdr_blob);
        auto const& local_info = entry->second;
        if (local_info->is_write_pending()) {
            futs->emplace_back(data_service()
                                   .async_write(r_cast< const char* >(value_blob.bytes), value_blob.size, blkid)
                                   .thenValue([local_info = std::move(local_info)](auto&&) {
                                       if (local_info->set_write_completed()) { local_info->comp_promise.setValue(); }
                                       return folly::makeFuture< folly::Unit >();
                                   }));
        }
    }

#if 0
    // blkids which are in allocated state after try_map_blkid are pushed in the final lists to be written.
    // All other states are ignored.
    for (auto const& remote_blkid : remote_blkids) {
        auto const [blkid, blkid_state] = try_map_blkid(remote_blkid);
        uint64_t remote_size = (remote_blk.get_nblks() * data_service().get_blk_size());

        switch (blkid_state) {
        case blkid_state_t::allocated:
            futs->emplace_back(data_service().async_write(sg_itr.next_iovs(remote_size), blkid));
            break;

        case blkid_state_t::written: // fall-through
        case blkid_state_t::completed:
            sg_itr.move_offset(remote_size);
            break;

        case blkid_state_t::unknown:
        default:
            break;
        }
    }
#endif

    if (futs->size()) {
        folly::collectAllUnsafe(*futs).thenValue([this, futs, rpc_data = std::move(rpc_data)]() {
            if (rpc_data) { msg_service().send_data_service_response({}, rpc_data); }
            sisl::VectorPool< AsyncNotify >::free(futs);
        });
    } else {
        if (rpc_data) { msg_service().send_data_service_response({}, rpc_data); }
        sisl::VectorPool< AsyncNotify >::free(futs);
    }
}

class FetchDataClientContext {
public:
    RaftStateMachine* sm_ptr;
    std::map< RemoteBlkId, sisl::blob > m_req_blkid_hdrs;

    ReplDevImpl* repl_dev() { return sm_ptr->m_rd; }

    FetchDataClientContext(RaftStateMachine* sm) : sm_ptr(sm) {}
    void add_requested_ids(RemoteBlkId const& blkid, sisl::blob const& usr_hdr) {
        m_req_blkid_hdrs.insert(std::pair(blkid, usr_hdr));
    }

    sisl::blob get_user_header(RemoteBlkId const& blkid) const {
        auto it = m_req_blkid_hdrs.find(blkid);
        RELEASE_ASSERT_EQ("Received blkid {} wasn't presented in requested map", blkid);
    }
};

void ReplicaSetImpl::fetch_data_from_leader(std::unique_ptr< FetchDataClientContext > ctx) {
    msg_service().data_service_request(
        FETCH_DATA, m_rpc_generator->serialize(),
        data_rpc::serialize(data_channel_rpc_hdr{m_group_id, 0 /*replace with replica id*/}, remote_pbas,
                            m_state_store.get(), {}),
        [this](sisl::io_blob const& incoming_buf) {
            auto null_rpc_data = boost::intrusive_ptr< sisl::GenericRpcData >(nullptr);
            m_state_machine->on_data_received(incoming_buf, null_rpc_data);
        });
}

void RaftStateMachine::on_fetch_data_received(sisl::io_blob const& incoming_buf,
                                              std::unique_ptr< FetchDataClientContext > ctx) {
    // deserialize incoming buf and get fq blkid list and the data to be written
    auto it = m_rpc_generator->deserialize(incoming_buf);

    auto futs = sisl::VectorPool< AsyncNotify >::alloc();

    while (it.has_more()) {
        auto [remote_blkid, usr_hdr_blob, value_blob] = it.next();
        usr_hdr_blob = ctx->get_user_header(remote_blkid);

        auto entry = mapper_get_entry(remote_blkid, usr_hdr_blob);
        auto const& local_info = entry->second;
        if (local_info->is_write_pending()) {
            futs->emplace_back(data_service()
                                   .async_write(r_cast< const char* >(value_blob.bytes), value_blob.size, blkid)
                                   .thenValue([local_info = std::move(local_info)](auto&&) {
                                       if (local_info->set_write_completed()) { local_info->comp_promise.setValue(); }
                                       return folly::makeFuture< folly::Unit >();
                                   }));
        } else {
            RD_LOG(DEBUG,
                   "Fetched data for remote_blkid={} but it is already being received as part of send data and it is "
                   "being processed, ignoring this fetch",
                   remote_blkid);
        }
    }

    if (futs->size()) {
        folly::collectAllUnsafe(*futs).thenValue([this, futs, rpc_data = std::move(rpc_data)]() {
            if (rpc_data) { msg_service().send_data_service_response({}, rpc_data); }
            sisl::VectorPool< AsyncNotify >::free(futs);
        });
    } else {
        if (rpc_data) { msg_service().send_data_service_response({}, rpc_data); }
        sisl::VectorPool< AsyncNotify >::free(futs);
    }
}

class FetchDataServerContext : public sisl::GenericRpcContextBase {
public:
    RaftStateMachine* sm_ptr;
    blkid_list_t const blkids;
    sisl::sg_list sgs;
    sisl::io_blob hdr_blob;

    ReplDevImpl* repl_dev() { return sm_ptr->m_rd; }

    FetchDataServerContext(RaftStateMachine* sm, blkid_list_t&& b, sisl::sg_list&& sl) :
            sm_ptr(sm), blkids(std::move(b)), sgs{std::move(sl)} {}
};

void RaftStateMachine::on_fetch_data_request(sisl::io_blob const& incoming_buf,
                                             intrusive< sisl::GenericRpcData >& rpc_data) {
    // set the completion callback
    rpc_data->set_comp_cb(
        [this](boost::intrusive_ptr< sisl::GenericRpcData >& rpc_data) { on_fetch_data_send_completed(rpc_data); });

    // get the blkids for which we need to send the data
    auto dit = m_rpc_generator->deserialize(incoming_buf);

    assert(rpc_data != nullptr);

    auto futs = sisl::VectorPool< folly::Future< bool > >::alloc();
    sisl::sg_list sgs{.size = 0, .iovs = {}};

    for (const auto& lblkid : blkids) {
        uint64_t size = (lblkid.get_nblks() * data_service().get_blk_size());
        uint8_t* buf = iomanager.iobuf_alloc(512, size);
        sgs.size += size;
        sgs.iovs.emplace_back(iovec{.iov_base = buf, .iov_len = size});
        futs->emplace_back(data_service().async_read(lblkid, buf, size));
    }

    if (futs->size()) {
        rpc_data->set_context(std::make_unique< FetchDataServerContext >(this, std::move(blkids), std::move(sgs)));
        folly::collectAllUnsafe(*futs).thenValue([rpc_data = std::move(rpc_data), futs](auto&&) {
            auto fctx = d_cast< FetchDataServerContext* >(rpc_data->get_context());
            auto response_blobs =
                data_rpc::serialize(data_channel_rpc_hdr{m_group_id, m_server_id}, fctx->blkids, fctx->sgs);
            fctx->hdr_blob = response_blobs[0];
            fctx->repl_dev()->send_data_service_response(response_blobs, rpc_data);
            sisl::VectorPool< folly::Future< bool > >::free(futs);
        });
    } else {
        sisl::VectorPool< folly::Future< bool > >::free(futs);
    }
}

void RaftStateMachine::on_fetch_data_send_completed(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto fctx = dynamic_cast< FetchDataServerContext* >(rpc_data->get_context());
    assert(fctx != nullptr);
    for (auto& iov : fctx->sgs.iovs) {
        iomanager.iobuf_free(uintptr_cast(iov.iov_base));
        iov.iov_base = nullptr;
        iov.iov_len = 0;
    }
    sgs.size = 0;

    delete[] fctx->hdr_blob.bytes;
}
#endif
} // namespace homestore
