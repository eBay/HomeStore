#include <sisl/logging/logging.h>
#include <sisl/fds/utils.hpp>
#include <sisl/fds/obj_allocator.hpp>
#include <sisl/fds/vector_pool.hpp>
#include <sisl/grpc/generic_service.hpp>
#include "state_machine/repl_set_impl.h"
#include <iomgr/iomgr_timer.hpp>
#include "state_machine.h"
#include "storage/storage_engine.h"
#include "log_store/journal_entry.h"
#include "service/repl_config.h"
#include "rpc_data_channel_include.h"

SISL_LOGGING_DECL(home_replication)

namespace homestore {

ReplicaStateMachine::ReplicaStateMachine(ReplDevImpl* rd) : m_rd{rd}, m_group_id{rd->m_group_id} {
    m_success_ptr = nuraft::buffer::alloc(sizeof(int));
    m_success_ptr->put(0);
}

void ReplicaStateMachine::stop_write_wait_timer() {
    if (m_wait_blkid_write_timer_hdl != iomgr::null_timer_handle) {
        iomanager.cancel_timer(m_wait_blkid_write_timer_hdl);
        m_wait_blkid_write_timer_hdl = iomgr::null_timer_handle;
    }
}

void ReplicaStateMachine::propose(const sisl::blob& header, const sisl::blob& key, const sisl::sg_list& value,
                                  blk_alloc_hints&& hints, void* user_ctx) {
    // Step 1: Alloc blkid in case of valid values
    BlkId blkid;
    if (value.size) {
        auto status = data_service().alloc_blk(value.size, hints, blkid);
        assert(status == BlkAllocStatus::SUCCESS); // TODO: Return ReplError
    }

    // Step 3: Create the request structure containing all details essential for callback
    repl_req* req = new repl_req();
    req->header = header;
    req->key = key;
    req->value = value;
    req->local_blkid = blkid;
    req->user_ctx = user_ctx;

    // Step 2: Send the data to all replicas
    send_in_data_channel(blkid, header, value);

    // Step 4: Write the data to underlying store
    data_service().async_write(value, hints, blkid).thenValue([this, req](bool) {
        ++req->num_blkids_written;
        check_and_commit(req);
    });

    // Step 5: Allocate and populate the journal entry
    auto const entry_size = sizeof(repl_journal_entry) + (blkids.size() * sizeof(BlkId)) + header.size + key.size;
    raft_buf_ptr_t buf = nuraft::buffer::alloc(entry_size);

    auto* entry = r_cast< repl_journal_entry* >(buf->data_begin());
    entry->code = journal_type_t::DATA;
    entry->user_header_size = header.size;
    entry->key_size = key.size;

    // Step 6: Copy the header and key into the journal entry
    uint8_t* raw_ptr = uintptr_cast(entry) + sizeof(repl_journal_entry);
    std::memcpy(raw_ptr, header.bytes, header.size);
    raw_ptr += header.size;
    std::memcpy(raw_ptr, key.bytes, key.size);
    raw_ptr += key.size;

    // Step 7: Copy blkid into the buffer
    *(r_cast< BlkId* >(raw_ptr)) = blkid;
    raw_ptr += sizeof(BlkId);

    // Step 8: Append the entry to the raft group
    auto* vec = sisl::VectorPool< raft_buf_ptr_t >::alloc();
    vec->push_back(buf);

    nuraft::raft_server::req_ext_params param;
    param.after_precommit_ = bind_this(ReplicaStateMachine::after_precommit_in_leader, 1);
    param.expected_term_ = 0;
    param.context_ = voidptr_cast(req);

    // m_raft_server->append_entries_ext(*vec, param);
    sisl::VectorPool< raft_buf_ptr_t >::free(vec);
}

raft_buf_ptr_t ReplicaStateMachine::pre_commit_ext(nuraft::state_machine::ext_op_params const& params) {
    // Leader precommit is processed in next callback, since lsn would not have been known to repl layer till we get
    // the next callback.
    if (!m_rd->is_leader()) {
        int64_t lsn = s_cast< int64_t >(params.log_idx);
        raft_buf_ptr_t data = params.data;

        RS_LOG(DEBUG, "pre_commit: {}, size: {}", lsn, data->size());
        repl_req* req = lsn_to_req(lsn);

        m_rd->m_listener->on_pre_commit(req->lsn, req->header, req->key, req->user_ctx);
    }
    return m_success_ptr;
}

void ReplicaStateMachine::after_precommit_in_leader(nuraft::raft_server::req_ext_cb_params const& params) {
    repl_req* req = r_cast< repl_req* >(params.context);
    link_lsn_to_req(req, int64_cast(params.log_idx));

    m_rd->m_listener->on_pre_commit(req->lsn, req->header, req->key, req->user_ctx);
}

raft_buf_ptr_t ReplicaStateMachine::commit_ext(nuraft::state_machine::ext_op_params const& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);
    raft_buf_ptr_t data = params.data;

    RS_LOG(DEBUG, "apply_commit: {}, size: {}", lsn, data->size());

    repl_req* req = lsn_to_req(lsn);
    if (m_rd->is_leader()) {
        // This is the time to ensure flushing of journal happens in leader
        if (m_rd->m_data_journal->last_durable_index() < uint64_cast(lsn)) { m_rd->m_data_journal->flush(); }
        req->is_raft_written.store(true);
    }
    check_and_commit(req);
    return m_success_ptr;
}

void ReplicaStateMachine::check_and_commit(repl_req* req) {
    if ((req->num_blkids_written.load() == req->local_blkids.size()) && req->is_raft_written.load()) {
        m_rd->m_listener->on_commit(req->lsn, req->header, req->key, req->local_blkids, req->user_ctx);
        m_rd->commit_lsn(req->lsn);
        m_lsn_req_map.erase(req->lsn);
        delete req;
    }
}

uint64_t ReplicaStateMachine::last_commit_index() { return uint64_cast(m_rd->get_last_commit_lsn()); }

repl_req* ReplicaStateMachine::transform_journal_entry(raft_buf_ptr_t const& raft_buf) {
    // Leader has nothing to transform or process
    if (m_rd->is_leader()) { return nullptr; }

    repl_journal_entry* entry = r_cast< repl_journal_entry* >(raft_buf->data_begin());
    repl_req* req = new repl_req();
    req->header =
        sisl::blob{uintptr_cast(raft_buf->data_begin()) + sizeof(repl_journal_entry), entry->user_header_size};
    req->key = sisl::blob{req->header.bytes + req->header.size, req->key.size};
    uint8_t* raw_cur_blkid = uintptr_cast(req->key.bytes + req->key.size);

    // Transform log_entry and also populate the blkids in a list
    auto const remote_blkid = RemoteBlkId{entry->replica_id, *r_cast< BlkId* >(raw_cur_blkid)};
    auto const [local_blkid, state] = try_map_blkid(remote_blkid);
    *r_cast< BlkId* >(raw_cur_blkid) = local_blkid;

    // TODO: Should we leave this on senders id in journal or better to write local id?
    entry->replica_id = m_server_id;

    req->remote_blkid = remote_blkid;
    req->local_blkid = local_blkid;
    req->journal_entry = raft_buf;

    return req;
}

void ReplicaStateMachine::link_lsn_to_req(repl_req* req, int64_t lsn) {
    req->lsn = lsn;
    [[maybe_unused]] auto r = m_lsn_req_map.insert(lsn, req);
    RS_DBG_ASSERT_EQ(r.second, true, "lsn={} already in precommit list", lsn);
}

repl_req* ReplicaStateMachine::lsn_to_req(int64_t lsn) {
    // Pull the req from the lsn
    auto const it = m_lsn_req_map.find(lsn);
    RS_DBG_ASSERT(it != m_lsn_req_map.cend(), "lsn req map missing lsn={}", lsn);

    repl_req* req = it->second;
    RS_DBG_ASSERT_EQ(lsn, req->lsn, "lsn req map mismatch");
    return req;
}

BlkId do_alloc_blk(uint32_t num_blks, blk_alloc_hints const& hints) {
    BlkId blkid;
    auto const status = data_service().alloc_blks(num_blks->data_service().get_blk_size(), hints, blkid);
    RELEASE_ASSERT_EQ(status, BlkAllocStatus::SUCCESS, "alloc_blks returned null, no space left!");
    return blkid;
}

shared< local_blkid_info > ReplicaStateMachine::mapper_get_create_entry(RemoteBlkId const& remote_blkid,
                                                                        sisl::blob const& user_header) {
    auto const [it, happened] =
        m_blkid_map.try_emplace(remote_blkid,
                                std::make_shared< local_blkid_info >(do_alloc_blk(
                                    remote_blkid.get_num_blks(), m_rd->m_listener->get_blk_alloc_hints(user_header))));
    return it->second;
}

shared< local_blkid_info > ReplicaStateMachine::mapper_find_entry(RemoteBlkId const& remote_blkid) const {
    const auto it = m_blkid_map.find(remote_blkid);
    return if (it == m_blkid_map.cend()) ? nullptr : it->second;
}

AsyncNotify ReplicaStateMachine::mapper_fetch_write_pop(std::vector< shared< local_blkid_info > >&& infos) {
    // Pop any entries that are already completed - from the entries list as well as from map
    infos.erase(std::remove_if(infos.begin(), infos.end(), [this](cshared< local_blkid_info >& local_info) {
        if (local_info->is_completed()) {
            m_blkid_map.erase(local_info->m_rblkid); // Remove=Pop from map as well, since it is completed
            return true;                             // Remove from the fetchable list
        }
    }));

    // All the entries are done already, no need to wait
    if (infos.size() == 0) { return folly::makeFuture< folly::Unit >(); }

    AsyncNotifier p;
    auto ret = p.getFuture();

    if (sisl_unlikely(m_resync_mode)) {
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_blkids(std::move(infos), std::move(p));
    } else {
        // some blkids are not in completed state, let's schedule a timer to check it again;
        // we wait for data channel to fill in the data. Still if its not done we trigger a fetch from remote;
        m_wait_blkid_write_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(repl->wait_blkid_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, infos = std::move(infos), p = std::move(p)](auto) {
                check_and_fetch_remote_blkids(std::move(infos), std::move(p));
            });
    }
    return ret;
}

void ReplicaStateMachine::check_and_fetch_remote_blkids(std::vector< shared< local_blkid_info > >&& infos) {
    for (const auto& local_info : infos) {
        if (local_info->is_waiting_for_data()) {
            // found some blkid not completed yet, save to the remote list;
            remote_fetch_blkids->emplace_back(fb);
        }
    }

    if (remote_fetch_blkids->size()) {
        // we've got some blkids not completed yet, let's fetch from remote;
        fetch_blkid_data_from_leader(std::move(remote_fetch_blkids));
    }
}

std::pair< BlkId, blkid_state_t > ReplicaStateMachine::try_map_blkid(RemoteBlkId const& remote_blkid) {
    const auto it = m_blkid_map.find(remote_blkid);
    shared< local_blkid_info > local_blkid_ptr;
    if (it != m_blkid_map.end()) {
        local_blkid_ptr = it->second;
    } else {
        BlkId local_blkid;
        auto const status = data_service().alloc_blks(size, blk_alloc_hints{}, local_blkid);
        RS_REL_ASSERT_EQ(status, BlkAllocStatus::SUCCESS, "alloc_blks returned null, no space left!");

        local_blkid_ptr =
            std::make_shared< local_blkid_info >(local_blkid, blkid_state_t::allocated, nullptr /*waiter*/);

        // insert to concurrent hash map
        m_blkid_map.emplace(remote_blkid, local_blkid);
    }

    return std::make_pair(local_blkids_ptr->m_blkid, local_blkids_ptr->m_state);
}

//
// if return false /* no need to wait */, no cb will be triggered;
// if return true /* need to wait */ , cb will be triggered after all local blkids completed writting;
//
bool ReplicaStateMachine::async_fetch_write_blkids(std::vector< RemoteBlkId > const& remote_blkids,
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
                                               RS_DBG_ASSERT(!it->second->m_waiter,
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
            RS_DBG_ASSERT(!it->second->m_waiter, "not expecting to apply waiter on already waited entry.");
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

void ReplicaStateMachine::check_and_fetch_remote_blkids(std::vector< RemoteBlkId > const& fq_blkid_list) {
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
blkid_state_t ReplicaStateMachine::update_map_blkid(RemoteBlkId const& remote_blkid, blkid_state_t const& state) {
    RS_DBG_ASSERT(state != blkid_state_t::unknown && state != blkid_state_t::allocated,
                  "invalid state, not expecting update to state: {}", state);
    auto it = m_blkid_map.find(remote_blkid);
    const auto old_state = it->second->m_state;
    it->second->m_state = state;

    if ((state == blkid_state_t::completed) && (it->second->m_waiter != nullptr)) {
        // waiter on this fq_blkid can be released.
        // if this is the last fq_blkid that this waiter is waiting on, cb will be triggered automatically;
        RS_DBG_ASSERT_EQ(old_state, blkid_state_t::written, "invalid state, not expecting state to be: {}", state);
        it->second->m_waiter.reset();
    }

    return old_state;
}

std::size_t ReplicaStateMachine::remove_map_blkid(RemoteBlkId const& fq_blkid) { return m_blkid_map.erase(fq_blkid); }

void ReplicaStateMachine::fetch_blkid_data_from_leader(std::unique_ptr< std::vector< RemoteBlkId > > fq_blkid_list) {
    blkid_list_t remote_blkids;
    for (auto const& fq_blkid : *fq_blkid_list) {
        remote_blkids.push_back(fq_blkid.blkid);
    }
    m_rd->fetch_blkid_data_from_leader(remote_blkids);
}

void ReplicaStateMachine::create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    RS_LOG(DEBUG, "create_snapshot {}/{}", s.get_last_log_idx(), s.get_last_log_term());
    auto null_except = std::shared_ptr< std::exception >();
    auto ret_val{false};
    if (when_done) when_done(ret_val, null_except);
}

blkid_state_t ReplicaStateMachine::get_blkid_state(RemoteBlkId const& fq_blkid) const {
    const auto key_string = fq_blkid.to_key_string();
    const auto it = m_blkid_map.find(key_string);
    return (it != m_blkid_map.end()) ? it->second->m_state : blkid_state_t::unknown;
}

void ReplicaStateMachine::on_data_received(sisl::io_blob const& incoming_buf,
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
    ReplicaStateMachine* sm_ptr;
    std::map< RemoteBlkId, sisl::blob > m_req_blkid_hdrs;

    ReplDevImpl* repl_dev() { return sm_ptr->m_rd; }

    FetchDataClientContext(ReplicaStateMachine* sm) : sm_ptr(sm) {}
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

void ReplicaStateMachine::on_fetch_data_received(sisl::io_blob const& incoming_buf,
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
    ReplicaStateMachine* sm_ptr;
    blkid_list_t const blkids;
    sisl::sg_list sgs;
    sisl::io_blob hdr_blob;

    ReplDevImpl* repl_dev() { return sm_ptr->m_rd; }

    FetchDataServerContext(ReplicaStateMachine* sm, blkid_list_t&& b, sisl::sg_list&& sl) :
            sm_ptr(sm), blkids(std::move(b)), sgs{std::move(sl)} {}
};

void ReplicaStateMachine::on_fetch_data_request(sisl::io_blob const& incoming_buf,
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

void ReplicaStateMachine::on_fetch_data_send_completed(intrusive< sisl::GenericRpcData >& rpc_data) {
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

} // namespace homestore
