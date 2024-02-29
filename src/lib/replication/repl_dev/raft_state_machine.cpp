#include <iomgr/iomgr_timer.hpp>
#include <sisl/logging/logging.h>
#include <sisl/fds/utils.hpp>
#include <sisl/fds/vector_pool.hpp>

#include "service/raft_repl_service.h"
#include "repl_dev/raft_state_machine.h"
#include "repl_dev/raft_repl_dev.h"

SISL_LOGGING_DECL(replication)

namespace homestore {

RaftStateMachine::RaftStateMachine(RaftReplDev& rd) : m_rd{rd} {
    m_success_ptr = nuraft::buffer::alloc(sizeof(int));
    m_success_ptr->put(0);
}

static std::pair< sisl::blob, sisl::blob > header_only_extract(nuraft::buffer& buf) {
    repl_journal_entry* jentry = r_cast< repl_journal_entry* >(buf.data_begin());
    RELEASE_ASSERT_EQ(jentry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                      "Mismatched version of journal entry received from RAFT peer");
    RELEASE_ASSERT_EQ(jentry->code, journal_type_t::HS_HEADER_ONLY,
                      "Trying to extract header on non-header only entry");
    sisl::blob const header = sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry), jentry->user_header_size};
    sisl::blob const key = sisl::blob{header.cbytes() + header.size(), jentry->key_size};
    return {header, key};
}

ReplServiceError RaftStateMachine::propose_to_raft(repl_req_ptr_t rreq) {
    uint32_t val_size = rreq->value_inlined ? 0 : rreq->local_blkid.serialized_size();
    uint32_t entry_size = sizeof(repl_journal_entry) + rreq->header.size() + rreq->key.size() + val_size;
    rreq->alloc_journal_entry(entry_size, true /* raft_buf */);
    rreq->journal_entry->code = (rreq->value_inlined) ? journal_type_t::HS_HEADER_ONLY : journal_type_t::HS_LARGE_DATA;
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

    RD_LOG(TRACE, "Raft Channel: journal_entry=[{}] ", rreq->journal_entry->to_string());

    auto append_status = m_rd.raft_server()->append_entries(*vec);
    sisl::VectorPool< raft_buf_ptr_t >::free(vec);

    if (append_status && !append_status->get_accepted()) {
        RD_LOG(ERROR, "Raft Channel: Failed to propose rreq=[{}] result_code={}", rreq->to_compact_string(),
               append_status->get_result_code());
        return RaftReplService::to_repl_error(append_status->get_result_code());
    }
    return ReplServiceError::OK;
}

repl_req_ptr_t RaftStateMachine::transform_journal_entry(nuraft::ptr< nuraft::log_entry >& lentry) {
    // Validate the journal entry and see if it needs to be transformed

    repl_journal_entry* tmp_jentry = r_cast< repl_journal_entry* >(lentry->get_buf().data_begin());
    RELEASE_ASSERT_EQ(tmp_jentry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                      "Mismatched version of journal entry received from RAFT peer");

    RD_LOG(TRACE, "Received Raft log_entry=[term={}], journal_entry=[{}] ", lentry->get_term(),
           tmp_jentry->to_string());

    if (tmp_jentry->server_id == m_rd.server_id()) {
        // We are the proposer for this entry, lets pull the request from the map. We don't need any actual
        // transformation here, because the entry is already is local
        repl_key rkey{.server_id = tmp_jentry->server_id, .term = lentry->get_term(), .dsn = tmp_jentry->dsn};
        auto rreq = m_rd.repl_key_to_req(rkey);
        RELEASE_ASSERT(rreq != nullptr,
                       "Log entry write with local server_id rkey={} but its corresponding req is missting in map",
                       rkey.to_string());
        DEBUG_ASSERT(rreq->is_proposer, "Log entry has same server_id={}, but rreq says its not a proposer",
                     m_rd.server_id())
        return rreq;
    }

    auto log_to_journal_entry = [](raft_buf_ptr_t const& log_buf, auto log_buf_data_offset) {
        repl_journal_entry* jentry = r_cast< repl_journal_entry* >(log_buf->data_begin() + log_buf_data_offset);
        sisl::blob const header =
            sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry), jentry->user_header_size};
        sisl::blob const key = sisl::blob{header.cbytes() + header.size(), jentry->key_size};
        return std::make_tuple(jentry, header, key);
    };

    // Serialize the log_entry buffer which returns the actual raft log_entry buffer.
    raft_buf_ptr_t log_buf;
    size_t log_buf_data_offset;
    if (tmp_jentry->code == journal_type_t::HS_LARGE_DATA) {
        DEBUG_ASSERT_GT(tmp_jentry->value_size, 0, "Entry marked as large data, but value size is notified as 0");
        log_buf = lentry->serialize();
        log_buf_data_offset = log_buf->size() - lentry->get_buf().size();
    } else {
        DEBUG_ASSERT_EQ(tmp_jentry->value_size, 0, "Entry marked as inline data, but value size is not 0");
        log_buf = lentry->get_buf_ptr();
        log_buf_data_offset = 0;
    }

    auto const [jentry, header, key] = log_to_journal_entry(log_buf, log_buf_data_offset);
    RD_LOG(DEBUG, "Received Raft server_id={}, term={}, dsn={}, journal_entry=[{}] ", jentry->server_id,
           lentry->get_term(), jentry->dsn, jentry->to_string());

    // From the repl_key, get the repl_req. In cases where log stream got here first, this method will create a new
    // repl_req and return that back. Fill up all of the required journal entry inside the repl_req
    auto rreq = m_rd.applier_create_req(
        repl_key{.server_id = jentry->server_id, .term = lentry->get_term(), .dsn = jentry->dsn}, header, key,
        jentry->value_size);
    rreq->journal_buf = std::move(log_buf);
    rreq->journal_entry = jentry;

    if (jentry->value_size > 0) {
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
            blkid_location =
                uintptr_cast(new_buf->data_begin()) + rreq->raft_journal_buf()->size() - jentry->value_size;
            std::tie(rreq->journal_entry, rreq->header, rreq->key) = log_to_journal_entry(new_buf, log_buf_data_offset);
            rreq->journal_buf = std::move(new_buf);
        } else {
            // Can do in-place replace of remote blkid with local blkid.
            blkid_location = uintptr_cast(rreq->raft_journal_buf()->data_begin()) + rreq->raft_journal_buf()->size() -
                jentry->value_size;
        }
        std::memcpy(blkid_location, rreq->local_blkid.serialize().cbytes(), local_size);
    }
    return rreq;
}

raft_buf_ptr_t RaftStateMachine::pre_commit_ext(nuraft::state_machine::ext_op_params const& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);

    repl_req_ptr_t rreq = lsn_to_req(lsn);
    RD_LOG(DEBUG, "Raft channel: Precommit rreq=[{}]", rreq->to_compact_string());
    m_rd.m_listener->on_pre_commit(rreq->lsn, rreq->header, rreq->key, rreq);

    return m_success_ptr;
}

raft_buf_ptr_t RaftStateMachine::commit_ext(nuraft::state_machine::ext_op_params const& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);

    repl_req_ptr_t rreq = lsn_to_req(lsn);
    RD_LOG(DEBUG, "Raft channel: Received Commit message rreq=[{}]", rreq->to_compact_string());
    if (rreq->is_proposer) {
        // This is the time to ensure flushing of journal happens in the proposer
        if (m_rd.m_data_journal->last_durable_index() < uint64_cast(lsn)) { m_rd.m_data_journal->flush(); }
        rreq->state.fetch_or(uint32_cast(repl_req_state_t::LOG_FLUSHED));
    }

    m_lsn_req_map.erase(rreq->lsn);
    m_rd.report_committed(rreq);

    return m_success_ptr;
}

uint64_t RaftStateMachine::last_commit_index() { return uint64_cast(m_rd.get_last_commit_lsn()); }

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
} // namespace homestore
