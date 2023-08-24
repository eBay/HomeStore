#include <sisl/logging/logging.h>
#include <sisl/fds/utils.hpp>
#include <sisl/fds/obj_allocator.hpp>
#include <sisl/fds/vector_pool.hpp>
#include <home_replication/repl_service.h>
#include <home_replication/repl_set.h>
#include <iomgr/iomgr_timer.hpp>
#include "state_machine.h"
#include "storage/storage_engine.h"
#include "log_store/journal_entry.h"
#include "service/repl_config.h"

SISL_LOGGING_DECL(home_replication)

namespace home_replication {

ReplicaStateMachine::ReplicaStateMachine(const std::shared_ptr< StateMachineStore >& state_store, ReplicaSet* rs) :
        m_state_store{state_store}, m_rs{rs}, m_group_id{rs->m_group_id} {
    m_success_ptr = nuraft::buffer::alloc(sizeof(int));
    m_success_ptr->put(0);
}

void ReplicaStateMachine::stop_write_wait_timer() {
    if (m_wait_pba_write_timer_hdl != iomgr::null_timer_handle) {
        iomanager.cancel_timer(m_wait_pba_write_timer_hdl);
        m_wait_pba_write_timer_hdl = iomgr::null_timer_handle;
    }
}

void ReplicaStateMachine::propose(const sisl::blob& header, const sisl::blob& key, const sisl::sg_list& value,
                                  void* user_ctx) {
    // Step 1: Alloc PBAs
    auto pbas = m_state_store->alloc_pbas(uint32_cast(value.size));

    // Step 2: Send the data to all replicas
    // m_rs->send_in_data_channel(pbas, value);

    // Step 3: Create the request structure containing all details essential for callback
    repl_req* req = sisl::ObjectAllocator< repl_req >::make_object();
    req->header = header;
    req->key = key;
    req->value = value;
    req->local_pbas = pbas;
    req->user_ctx = user_ctx;

    // Step 4: Write the data to underlying store
    m_state_store->async_write(value, pbas, [this, req]([[maybe_unused]] std::error_condition err) {
        assert(!err);
        ++req->num_pbas_written;
        check_and_commit(req);
    });

    // Step 5: Allocate and populate the journal entry
    auto const entry_size = sizeof(repl_journal_entry) +
        (pbas.size() * (sizeof(pba_t) + sizeof(uint32_t) /* pba size*/)) + header.size + key.size;
    raft_buf_ptr_t buf = nuraft::buffer::alloc(entry_size);

    auto* entry = r_cast< repl_journal_entry* >(buf->data_begin());
    entry->code = journal_type_t::DATA;
    entry->n_pbas = s_cast< uint16_t >(pbas.size());
    entry->user_header_size = header.size;
    entry->key_size = key.size;

    // Step 6: Copy the header and key into the journal entry
    uint8_t* raw_ptr = uintptr_cast(entry) + sizeof(repl_journal_entry);
    std::memcpy(raw_ptr, header.bytes, header.size);
    raw_ptr += header.size;
    std::memcpy(raw_ptr, key.bytes, key.size);

    raw_ptr += key.size;
    // now raw_ptr is pointing to pba list portion, layout: {pba-1, size-1}, {pba-2, size-2}, ..., {pba-n, size-n}
    // Step 7: Copy pba and its size into the buffer;
    for (const auto& p : pbas) {
        // fill in the pba and its size;
        *(r_cast< pba_t* >(raw_ptr)) = p;
        raw_ptr += sizeof(pba_t);
        *(r_cast< uint32_t* >(raw_ptr)) = m_state_store->pba_to_size(p);
        raw_ptr += sizeof(uint32_t);
    }

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

raft_buf_ptr_t ReplicaStateMachine::pre_commit_ext(const nuraft::state_machine::ext_op_params& params) {
    // Leader precommit is processed in next callback, since lsn would not have been known to repl layer till we get
    // the next callback.
    if (!m_rs->is_leader()) {
        int64_t lsn = s_cast< int64_t >(params.log_idx);
        raft_buf_ptr_t data = params.data;

        RS_LOG(DEBUG, "pre_commit: {}, size: {}", lsn, data->size());
        repl_req* req = lsn_to_req(lsn);

        m_rs->m_listener->on_pre_commit(req->lsn, req->header, req->key, req->user_ctx);
    }
    return m_success_ptr;
}

void ReplicaStateMachine::after_precommit_in_leader(const nuraft::raft_server::req_ext_cb_params& params) {
    repl_req* req = r_cast< repl_req* >(params.context);
    link_lsn_to_req(req, int64_cast(params.log_idx));

    m_rs->m_listener->on_pre_commit(req->lsn, req->header, req->key, req->user_ctx);
}

raft_buf_ptr_t ReplicaStateMachine::commit_ext(const nuraft::state_machine::ext_op_params& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);
    raft_buf_ptr_t data = params.data;

    RS_LOG(DEBUG, "apply_commit: {}, size: {}", lsn, data->size());

    repl_req* req = lsn_to_req(lsn);
    if (m_rs->is_leader()) {
        // This is the time to ensure flushing of journal happens in leader
        if (m_rs->m_data_journal->last_durable_index() < uint64_cast(lsn)) { m_rs->m_data_journal->flush(); }
        req->is_raft_written.store(true);
    }
    check_and_commit(req);
    return m_success_ptr;
}

void ReplicaStateMachine::check_and_commit(repl_req* req) {
    if ((req->num_pbas_written.load() == req->local_pbas.size()) && req->is_raft_written.load()) {
        m_rs->m_listener->on_commit(req->lsn, req->header, req->key, req->local_pbas, req->user_ctx);
        m_state_store->commit_lsn(req->lsn);
        m_lsn_req_map.erase(req->lsn);
        sisl::ObjectAllocator< repl_req >::deallocate(req);
    }
}

uint64_t ReplicaStateMachine::last_commit_index() { return uint64_cast(m_state_store->get_last_commit_lsn()); }

repl_req* ReplicaStateMachine::transform_journal_entry(const raft_buf_ptr_t& raft_buf) {
    // Leader has nothing to transform or process
    if (m_rs->is_leader()) { return nullptr; }

    fq_pba_list_t remote_pbas;
    pba_list_t local_pbas;

    repl_journal_entry* entry = r_cast< repl_journal_entry* >(raft_buf->data_begin());
    repl_req* req = sisl::ObjectAllocator< repl_req >::make_object();
    req->header =
        sisl::blob{uintptr_cast(raft_buf->data_begin()) + sizeof(repl_journal_entry), entry->user_header_size};
    req->key = sisl::blob{req->header.bytes + req->header.size, req->key.size};
    uint8_t* raw_pba_list = r_cast< uint8_t* >(req->key.bytes + req->key.size);

    // Transform log_entry and also populate the pbas in a list
    for (uint16_t i{0}; i < entry->n_pbas; ++i) {
        raw_pba_list += (i * (sizeof(pba_t) + sizeof(uint32_t) /* pba size*/));
        auto const remote_pba = fully_qualified_pba{entry->replica_id, *r_cast< pba_t* >(raw_pba_list),
                                                    *r_cast< uint32_t* >(raw_pba_list + sizeof(pba_t)) /* pba size */};
        remote_pbas.push_back(remote_pba);

        auto const [local_pba_list, state] = try_map_pba(remote_pba);
        // TODO: remove this assert after buf re-alloc is resolved;
        assert(local_pba_list.size() == 1);
        *r_cast< pba_t* >(raw_pba_list) = local_pba_list[0];
        *r_cast< uint32_t* >(raw_pba_list + sizeof(pba_t)) = m_state_store->pba_to_size(local_pba_list[0]);
        local_pbas.push_back(local_pba_list[0]);
    }
    // TODO: Should we leave this on senders id in journal or better to write local id?
    entry->replica_id = m_server_id;

    req->remote_fq_pbas = remote_pbas;
    req->local_pbas = local_pbas;
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

std::pair< pba_list_t, pba_state_t > ReplicaStateMachine::try_map_pba(const fully_qualified_pba& fq_pba) {
    const auto key_string = fq_pba.to_key_string();
    const auto it = m_pba_map.find(key_string);
    local_pba_info_ptr local_pbas_ptr{nullptr};
    if (it != m_pba_map.end()) {
        local_pbas_ptr = it->second;
    } else {
        const auto local_pbas = m_state_store->alloc_pbas(fq_pba.size);
        RS_DBG_ASSERT(local_pbas.size() > 0, "alloca_pbas returned null, no space left!");

        local_pbas_ptr = std::make_shared< local_pba_info >(local_pbas, pba_state_t::allocated, nullptr /*waiter*/);

        // insert to concurrent hash map
        m_pba_map.insert(key_string, local_pbas_ptr);
    }

    return std::make_pair(local_pbas_ptr->m_pbas, local_pbas_ptr->m_state);
}

//
// if return false /* no need to wait */, no cb will be triggered;
// if return true /* need to wait */ , cb will be triggered after all local pbas completed writting;
//
bool ReplicaStateMachine::async_fetch_write_pbas(const std::vector< fully_qualified_pba >& fq_pba_list,
                                                 batch_completion_cb_t cb) {
    std::vector< fully_qualified_pba > wait_to_fill_fq_pbas;
    std::shared_ptr< pba_waiter > waiter = nullptr;

    for (const auto& fq_pba : fq_pba_list) {
        const auto key_string = fq_pba.to_key_string();
        auto it = m_pba_map.find(key_string);

        if (it == m_pba_map.end()) {
            auto const [local_pba_list, state] = try_map_pba(fq_pba);
            it = m_pba_map.find(key_string);

            // add this fq_pba to wait list;
            wait_to_fill_fq_pbas.emplace_back(fq_pba);

            // fall through;
        }

        // now "it" points to either newly created map entry or already existed entry;
        if (it->second->m_state != pba_state_t::completed) {
            // only create waiter when there is at least one fq_pba that needs to be waited on;
            if (waiter == nullptr) { waiter = std::make_shared< pba_waiter >(std::move(cb)); }

            // same waiter can wait on multiple fq_pbas;
            RS_DBG_ASSERT_EQ(it->second->m_waiter, nullptr, "not expecting to apply waiter on already waited entry.");
            it->second->m_waiter = waiter;
        }
    }

    const auto wait_size = wait_to_fill_fq_pbas.size();
#if __cplusplus > 201703L
    [[unlikely]] if (resync_mode) {
#else
    if (sisl_unlikely(resync_mode)) {
#endif
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_pbas(std::move(wait_to_fill_fq_pbas));
    }
    else if (wait_size) {
        // some pbas are not in completed state, let's schedule a timer to check it again;
        // either we wait for data channel to fill in the data or we wait for certain time and trigger a fetch from
        // remote;
        m_wait_pba_write_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HR_DYNAMIC_CONFIG(wait_pba_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, &wait_to_fill_fq_pbas]([[maybe_unused]] void* cookie) {
                // check input fq_pbas to see if they completed write, if there is
                // still any fq_pba not completed yet, trigger a remote fetch
                check_and_fetch_remote_pbas(std::move(wait_to_fill_fq_pbas));
            });
    }

    // if size is not zero, it means caller needs to wait;
    return wait_size != 0;
}

void ReplicaStateMachine::check_and_fetch_remote_pbas(std::vector< fully_qualified_pba > fq_pba_list) {
    auto remote_fetch_pbas = std::make_unique< std::vector< fully_qualified_pba > >();
    for (auto fq_it = fq_pba_list.begin(); fq_it != fq_pba_list.end(); ++fq_it) {
        auto it = m_pba_map.find(fq_it->to_key_string());
        if (it->second->m_state != pba_state_t::completed) {
            // found some pba not completed yet, save to the remote list;
            remote_fetch_pbas->emplace_back(*fq_it);
        }
    }

    if (remote_fetch_pbas->size()) {
        // we've got some pbas not completed yet, let's fetch from remote;
        fetch_pba_data_from_leader(std::move(remote_fetch_pbas));
    }
}

//
// for the same fq_pba, if caller calls it concurrently with different state, result is undetermined;
//
pba_state_t ReplicaStateMachine::update_map_pba(const fully_qualified_pba& fq_pba, const pba_state_t& state) {
    RS_DBG_ASSERT(state != pba_state_t::unknown && state != pba_state_t::allocated,
                  "invalid state, not expecting update to state: {}", state);
    auto it = m_pba_map.find(fq_pba.to_key_string());
    const auto old_state = it->second->m_state;
    it->second->m_state = state;

    if ((state == pba_state_t::completed) && (it->second->m_waiter != nullptr)) {
        // waiter on this fq_pba can be released.
        // if this is the last fq_pba that this waiter is waiting on, cb will be triggered automatically;
        RS_DBG_ASSERT_EQ(old_state, pba_state_t::written, "invalid state, not expecting state to be: {}", state);
        it->second->m_waiter.reset();
    }

    return old_state;
}

std::size_t ReplicaStateMachine::remove_map_pba(const fully_qualified_pba& fq_pba) {
    return m_pba_map.erase(fq_pba.to_key_string());
}

void ReplicaStateMachine::fetch_pba_data_from_leader(std::unique_ptr< std::vector< fully_qualified_pba > >) {
    // TODO: to be implemented;
}

void ReplicaStateMachine::create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    RS_LOG(DEBUG, "create_snapshot {}/{}", s.get_last_log_idx(), s.get_last_log_term());
    auto null_except = std::shared_ptr< std::exception >();
    auto ret_val{false};
    if (when_done) when_done(ret_val, null_except);
}

} // namespace home_replication
