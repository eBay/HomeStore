#include <iomgr/iomgr_timer.hpp>
#include <sisl/logging/logging.h>
#include <sisl/fds/utils.hpp>
#include <sisl/fds/vector_pool.hpp>
#include <libnuraft/nuraft.hxx>

#include "service/raft_repl_service.h"
#include "repl_dev/raft_state_machine.h"
#include "repl_dev/raft_repl_dev.h"
#include <homestore/homestore.hpp>
#include "common/homestore_config.hpp"

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
    RELEASE_ASSERT_EQ(jentry->code, journal_type_t::HS_DATA_INLINED,
                      "Trying to extract header on non-header only entry");
    sisl::blob const header = sisl::blob{uintptr_cast(jentry) + sizeof(repl_journal_entry), jentry->user_header_size};
    sisl::blob const key = sisl::blob{header.cbytes() + header.size(), jentry->key_size};
    return {header, key};
}

ReplServiceError RaftStateMachine::propose_to_raft(repl_req_ptr_t rreq) {
    rreq->create_journal_entry(true /* raft_buf */, m_rd.server_id());
    RD_LOGT("Raft Channel: propose journal_entry=[{}] ", rreq->journal_entry()->to_string());

    auto* vec = sisl::VectorPool< raft_buf_ptr_t >::alloc();
    vec->push_back(rreq->raft_journal_buf());

    auto append_status = m_rd.raft_server()->append_entries(*vec);
    sisl::VectorPool< raft_buf_ptr_t >::free(vec);

    if (append_status && !append_status->get_accepted()) {
        RD_LOGE("Raft Channel: Failed to propose rreq=[{}] result_code={}", rreq->to_compact_string(),
                append_status->get_result_code());
        return RaftReplService::to_repl_error(append_status->get_result_code());
    }
    return ReplServiceError::OK;
}

repl_req_ptr_t RaftStateMachine::localize_journal_entry_prepare(nuraft::log_entry& lentry) {
    // Validate the journal entry and see if it needs to be transformed
    repl_journal_entry* jentry = r_cast< repl_journal_entry* >(lentry.get_buf().data_begin());
    RELEASE_ASSERT_EQ(jentry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                      "Mismatched version of journal entry received from RAFT peer");

    RD_LOGT("Raft Channel: Localizing Raft log_entry: server_id={}, term={}, journal_entry=[{}] ", jentry->server_id,
            lentry.get_term(), jentry->to_string());

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

    repl_key const rkey{.server_id = jentry->server_id, .term = lentry.get_term(), .dsn = jentry->dsn};

    // Create a new rreq (or) Pull rreq from the map given the repl_key, header and key. Any new rreq will
    // allocate the blks (in case of large data). We will use the new blkid and transform the current journal entry's
    // blkid with this new one
    repl_req_ptr_t rreq;
    if ((jentry->code == journal_type_t::HS_DATA_LINKED) && (jentry->value_size > 0)) {
        MultiBlkId entry_blkid;
        entry_blkid.deserialize(entry_to_val(jentry), true /* copy */);

        rreq = m_rd.applier_create_req(rkey, jentry->code, entry_to_hdr(jentry), entry_to_key(jentry),
                                       (entry_blkid.blk_count() * m_rd.get_blk_size()), false /* is_data_channel */);
        if (rreq == nullptr) { goto out; }

        rreq->set_remote_blkid(RemoteBlkId{jentry->server_id, entry_blkid});

        auto const local_size = rreq->local_blkid().serialized_size();
        auto const remote_size = entry_blkid.serialized_size();
        auto const size_before_value = lentry.get_buf().size() - jentry->value_size;

        // It is possible that serialized size of the blkid allocated could be different (even though it
        // allocates the same size as remote), because we support scatterred writes on different physical blocks. In
        // that case, we need to completely prepare a new journal_entry buffer and assign that buffer to log_entry
        if (local_size > remote_size) {
            DEBUG_ASSERT(false, "We don't support different count of local blkid and remote blkid yet");
            raft_buf_ptr_t new_buf = nuraft::buffer::alloc(lentry.get_buf().size() + local_size - remote_size);

            std::memcpy(new_buf->data_begin(), lentry.get_buf().data_begin(), size_before_value);
            jentry = r_cast< repl_journal_entry* >(new_buf->data_begin());
            // lentry.change_buf(std::move(new_buf));
        }

        uint8_t* blkid_location = uintptr_cast(lentry.get_buf().data_begin()) + size_before_value;
        std::memcpy(blkid_location, rreq->local_blkid().serialize().cbytes(), local_size);
    } else {
        rreq = m_rd.applier_create_req(rkey, jentry->code, entry_to_hdr(jentry), entry_to_key(jentry),
                                       jentry->value_size, false /* is_data_channel */);
    }

    // We might have localized the journal entry with new blkid. We need to also update the header/key pointers pointing
    // to the data in the raft journal entry. It is possible that header/key pointers are pointing to the data ptrs that
    // was created during push/fetch data. The following step ensures that all information are localized
    rreq->change_raft_journal_buf(lentry.get_buf_ptr(), true /* adjust_hdr_key */);

out:
    if (rreq == nullptr) {
        RD_LOG(ERROR,
               "Failed to localize journal entry rkey={} jentry=[{}], we return error and let Raft resend this req",
               rkey.to_string(), jentry->to_string());
    }
    return rreq;
}

repl_req_ptr_t RaftStateMachine::localize_journal_entry_finish(nuraft::log_entry& lentry) {
    // Try to locate the rreq based on the log_entry.
    // If we are able to locate that req in the map for this entry, it could be one of
    //  a) This is an inline data and don't need any localization
    //  b) This is a proposer and thus don't need any localization
    //  c) This is an indirect data and we received raft entry append from leader and localized the journal entry.
    //  d) This is an indirect data and we received only on data channel, but no raft entry append from leader. This
    //     would mean _prepare is never called but directly finish is called. This can happen if that the leader is not
    //     the original proposer (perhaps unsupported scenario at this time)
    //
    // On case a), b), we return the rreq as is. For case c), we just need to localize the actual server_id as well (as
    // finishing step). For case d), we prepare the localization of journal entry and then finish them
    //
    //
    // If we are not able to locate that req in the map for this entry, it means that no entry from raft leader is
    // appended and data channel has not received a data. This is typical scenario if we do unpack().
    //
    // In this case, we call prepare the localization of journal entry ourselves and then finish them
    //
    repl_journal_entry* jentry = r_cast< repl_journal_entry const* >(lentry.get_buf().data_begin());
    RELEASE_ASSERT_EQ(jentry->major_version, repl_journal_entry::JOURNAL_ENTRY_MAJOR,
                      "Mismatched version of journal entry received from RAFT peer");

    repl_key rkey{.server_id = jentry->server_id, .term = lentry.get_term(), .dsn = jentry->dsn};

    auto rreq = m_rd.repl_key_to_req(rkey);
    if ((rreq == nullptr) || (rreq->is_localize_pending())) {
        rreq = localize_journal_entry_prepare(lentry);
        if (rreq == nullptr) {
            RELEASE_ASSERT(rreq != nullptr,
                           "We get an linked data for rkey=[{}], jentry=[{}] not as part of Raft Append but "
                           "indirectly through possibly unpack() and in those cases, if we are not able to alloc "
                           "location to write the data, there is no recourse. So we must crash this system ",
                           rkey.to_string(), jentry->to_string());
            return nullptr;
        }
    }

    if (rreq->is_proposer()) {
        DEBUG_ASSERT_EQ(jentry->server_id, m_rd.server_id(),
                        "Expected rkey={}, jentry={} proposer request to have local server_id in journal entry",
                        rkey.to_string(), jentry->to_string());
        return rreq;
    }
    jentry->server_id = m_rd.server_id();

    return rreq;
}

raft_buf_ptr_t RaftStateMachine::pre_commit_ext(nuraft::state_machine::ext_op_params const& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);

    repl_req_ptr_t rreq = lsn_to_req(lsn);
    RD_LOGD("Raft channel: Precommit rreq=[{}]", rreq->to_compact_string());
    m_rd.m_listener->on_pre_commit(rreq->lsn(), rreq->header(), rreq->key(), rreq);

    return m_success_ptr;
}

raft_buf_ptr_t RaftStateMachine::commit_ext(nuraft::state_machine::ext_op_params const& params) {
    int64_t lsn = s_cast< int64_t >(params.log_idx);
    RD_LOGD("Raft channel: Received Commit message lsn {} store {} logdev {} size {}", lsn,
            m_rd.m_data_journal->logstore_id(), m_rd.m_data_journal->logdev_id(), params.data->size());
    repl_req_ptr_t rreq = lsn_to_req(lsn);
    RD_DBG_ASSERT(rreq != nullptr, "Raft channel got null rreq for lsn={}", lsn);
    RD_LOGD("Raft channel: Received Commit message rreq=[{}]", rreq->to_string());
    if (rreq->is_proposer()) {
        // This is the time to ensure flushing of journal happens in the proposer
        rreq->add_state(repl_req_state_t::LOG_FLUSHED);
    }

    m_rd.handle_commit(rreq);

    return m_success_ptr;
}

void RaftStateMachine::commit_config(const ulong log_idx, raft_cluster_config_ptr_t& new_conf) {
    RD_LOGD("Raft channel: Commit new cluster conf , log_idx = {}", log_idx);
    // TODO:add more logic here if necessary
}

void RaftStateMachine::iterate_repl_reqs(std::function< void(int64_t, repl_req_ptr_t rreq) > const& cb) {
    for (auto [key, rreq] : m_lsn_req_map) {
        cb(key, rreq);
    }
}

uint64_t RaftStateMachine::last_commit_index() {
    RD_LOG(DEBUG, "Raft channel: last_commit_index {}", uint64_cast(m_rd.get_last_commit_lsn()));
    return uint64_cast(m_rd.get_last_commit_lsn());
}

void RaftStateMachine::become_ready() { m_rd.become_ready(); }

void RaftStateMachine::unlink_lsn_to_req(int64_t lsn) {
    auto const it = m_lsn_req_map.find(lsn);
    if (it != m_lsn_req_map.cend()) {
        RD_LOG(DEBUG, "Raft channel: erase lsn {},  rreq {}", lsn, it->second->to_string());
        m_lsn_req_map.erase(lsn);
    }
}

void RaftStateMachine::link_lsn_to_req(repl_req_ptr_t rreq, int64_t lsn) {
    rreq->set_lsn(lsn);
    rreq->add_state(repl_req_state_t::LOG_RECEIVED);
    // reset the rreq created_at time to now https://github.com/eBay/HomeStore/issues/506
    rreq->set_created_time();
    [[maybe_unused]] auto r = m_lsn_req_map.insert(lsn, std::move(rreq));
    RD_DBG_ASSERT_EQ(r.second, true, "lsn={} already in precommit list", lsn);
}

repl_req_ptr_t RaftStateMachine::lsn_to_req(int64_t lsn) {
    // Pull the req from the lsn
    auto const it = m_lsn_req_map.find(lsn);
    // RD_DBG_ASSERT(it != m_lsn_req_map.cend(), "lsn req map missing lsn={}", lsn);
    if (it == m_lsn_req_map.cend()) { return nullptr; }

    repl_req_ptr_t rreq = it->second;
    RD_DBG_ASSERT_EQ(lsn, rreq->lsn(), "lsn req map mismatch");
    return rreq;
}

nuraft_mesg::repl_service_ctx* RaftStateMachine::group_msg_service() { return m_rd.group_msg_service(); }

void RaftStateMachine::create_snapshot(nuraft::snapshot& s, nuraft::async_result< bool >::handler_type& when_done) {
    m_rd.on_create_snapshot(s, when_done);
}

int RaftStateMachine::read_logical_snp_obj(nuraft::snapshot& s, void*& user_ctx, ulong obj_id, raft_buf_ptr_t& data_out,
                                           bool& is_last_obj) {
    auto snp_ctx = std::make_shared< nuraft_snapshot_context >(s);
    auto snp_data = std::make_shared< snapshot_data >();
    snp_data->user_ctx = user_ctx;
    snp_data->offset = obj_id;
    snp_data->is_last_obj = is_last_obj;

    // Listener will read the snapshot data and we pass through the same.
    int ret = m_rd.m_listener->read_snapshot_data(snp_ctx, snp_data);
    if (ret < 0) return ret;

    // Update user_ctx and whether is_last_obj
    user_ctx = snp_data->user_ctx;
    is_last_obj = snp_data->is_last_obj;

    // We are doing a copy here.
    data_out = nuraft::buffer::alloc(snp_data->blob.size());
    nuraft::buffer_serializer bs(data_out);
    bs.put_raw(snp_data->blob.cbytes(), snp_data->blob.size());
    return ret;
}

void RaftStateMachine::save_logical_snp_obj(nuraft::snapshot& s, ulong& obj_id, nuraft::buffer& data, bool is_first_obj,
                                            bool is_last_obj) {
    auto snp_ctx = std::make_shared< nuraft_snapshot_context >(s);
    auto snp_data = std::make_shared< snapshot_data >();
    snp_data->offset = obj_id;
    snp_data->is_first_obj = is_first_obj;
    snp_data->is_last_obj = is_last_obj;

    // We are doing a copy here.
    sisl::io_blob_safe blob{s_cast< size_t >(data.size())};
    std::memcpy(blob.bytes(), data.data_begin(), data.size());
    snp_data->blob = std::move(blob);

    m_rd.m_listener->write_snapshot_data(snp_ctx, snp_data);

    // Update the object offset.
    obj_id = snp_data->offset;
}

bool RaftStateMachine::apply_snapshot(nuraft::snapshot& s) {
    m_rd.set_last_commit_lsn(s.get_last_log_idx());
    m_rd.m_data_journal->set_last_durable_lsn(s.get_last_log_idx());
    auto snp_ctx = std::make_shared< nuraft_snapshot_context >(s);
    return m_rd.m_listener->apply_snapshot(snp_ctx);
}

nuraft::ptr< nuraft::snapshot > RaftStateMachine::last_snapshot() {
    auto s = std::dynamic_pointer_cast< nuraft_snapshot_context >(m_rd.m_listener->last_snapshot());
    if (s == nullptr) return nullptr;
    return s->nuraft_snapshot();
}

void RaftStateMachine::free_user_snp_ctx(void*& user_snp_ctx) { m_rd.m_listener->free_user_snp_ctx(user_snp_ctx); }

std::string RaftStateMachine::rdev_name() const { return m_rd.rdev_name(); }

} // namespace homestore
