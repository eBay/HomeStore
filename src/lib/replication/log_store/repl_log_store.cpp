#include <sisl/fds/vector_pool.hpp>
#include "replication/log_store/repl_log_store.h"
#include "replication/repl_dev/raft_state_machine.h"
#include "replication/repl_dev/raft_repl_dev.h"
#include "replication/repl_dev/common.h"

namespace homestore {

uint64_t ReplLogStore::append(nuraft::ptr< nuraft::log_entry >& entry) {
    // We don't want to transform anything that is not an app log
    if (entry->get_val_type() != nuraft::log_val_type::app_log || entry->get_buf_ptr()->size() == 0) {
        ulong lsn = HomeRaftLogStore::append(entry);
        RD_LOGD(NO_TRACE_ID, "None-APP log: append entry term={}, log_val_type={} lsn={} size={}", entry->get_term(),
                static_cast< uint32_t >(entry->get_val_type()), lsn, entry->get_buf().size());
        return lsn;
    }

    repl_req_ptr_t rreq = m_sm.localize_journal_entry_finish(*entry, true /* is_append_log */);
    RELEASE_ASSERT_NE(nullptr != rreq, "Failed to localize journal entry before appending log");

    ulong lsn = HomeRaftLogStore::append(entry);
    m_sm.link_lsn_to_req(rreq, int64_cast(lsn));
    RD_LOGT(rreq->traceID(), "Raft Channel: Received append log entry rreq=[{}]", rreq->to_compact_string());
    return lsn;
}

void ReplLogStore::write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) {
    // We don't want to transform anything that is not an app log
    if (entry->get_val_type() != nuraft::log_val_type::app_log) {
        HomeRaftLogStore::write_at(index, entry);
        return;
    }

    repl_req_ptr_t rreq = m_sm.localize_journal_entry_finish(*entry);
    RELEASE_ASSERT(nullptr != rreq, "Failed to localize journal entry before overwriting log at index {}", index);
    HomeRaftLogStore::write_at(index, entry);
    m_sm.link_lsn_to_req(rreq, int64_cast(index));
    RD_LOGT(rreq->traceID(), "Raft Channel: Received write_at log entry rreq=[{}]", rreq->to_compact_string());
}

void ReplLogStore::end_of_append_batch(ulong start_lsn, ulong count) {
    int64_t end_lsn = int64_cast(start_lsn + count - 1);

    // Start fetch the batch of data for this lsn range from remote if its not available yet.
    auto reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
    auto proposer_reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
    for (int64_t lsn = int64_cast(start_lsn); lsn <= end_lsn; ++lsn) {
        auto rreq = m_sm.lsn_to_req(lsn);
        // Skip it for rreq == nullptr which is the case for raft config entries.
        if ((rreq == nullptr)) {
            continue;
        } else if (rreq->is_proposer()) {
            proposer_reqs->emplace_back(std::move(rreq));
        } else {
            reqs->emplace_back(std::move(rreq));
        }
    }

    RD_LOGT(NO_TRACE_ID, "Raft Channel: end_of_append_batch start_lsn={} count={} num_data_to_be_written={} {}",
            start_lsn, count, reqs->size(), proposer_reqs->size());

    if (!reqs->empty()) {
        // Check the map if data corresponding to all of these requsts have been received and written. If not,
        // schedule a fetch and write. Once all requests are completed and written, these requests are poped out of
        // the map and the future will be ready.
        auto cur_time = std::chrono::steady_clock::now();
        auto fut = m_rd.notify_after_data_written(reqs);
        // Wait for the fetch and write to be completed successfully.
        // It is essential to complete the data write before appending to the log. If the logs are flushed
        // before the data is written, a restart and subsequent log replay occurs, as the in-memory state is lost,
        // it leaves us uncertain about whether the data was actually written, potentially leading to data
        // inconsistency.
        std::move(fut).wait();
        HISTOGRAM_OBSERVE(m_rd.metrics(), data_channel_wait_latency_us, get_elapsed_time_us(cur_time));
    }

    // Flushing logs now.
    auto cur_time = std::chrono::steady_clock::now();
    HomeRaftLogStore::end_of_append_batch(start_lsn, count);
    HISTOGRAM_OBSERVE(m_rd.metrics(), raft_end_of_append_batch_latency_us, get_elapsed_time_us(cur_time));

    // Mark all the reqs completely written
    for (auto const& rreq : *reqs) {
        if (rreq) { rreq->add_state(repl_req_state_t::LOG_FLUSHED); }
    }

    // Data corresponding to proposer reqs have already been written before propose reqs to raft,
    // so skip waiting data written and mark reqs as flushed here.
    for (auto const& rreq : *proposer_reqs) {
        if (rreq) {
            RD_LOGT(rreq->traceID(),
                    "Raft Channel: end_of_append_batch, I am proposer for lsn {}, only flushed log for it",
                    rreq->lsn());
            rreq->add_state(repl_req_state_t::LOG_FLUSHED);
        }
    }

    // Convert volatile logs to non-volatile logs in state machine.
    for (int64_t lsn = int64_cast(start_lsn); lsn <= end_lsn; ++lsn) {
        auto rreq = m_sm.lsn_to_req(lsn);
        if (rreq != nullptr) {
            if (rreq->has_state(repl_req_state_t::ERRORED)) {
                RD_LOGE(rreq->traceID(), "Raft Channel: rreq=[{}] met some errors before", rreq->to_compact_string());
                continue;
            }
            rreq->set_is_volatile(false);
        }
    }

    sisl::VectorPool< repl_req_ptr_t >::free(reqs);
    sisl::VectorPool< repl_req_ptr_t >::free(proposer_reqs);
}

std::string ReplLogStore::rdev_name() const { return m_rd.rdev_name(); }
std::string ReplLogStore::identify_str() const { return m_rd.identify_str(); }

bool ReplLogStore::compact(ulong compact_upto_lsn) {
    auto truncation_upper_limit = m_rd.get_truncation_upper_limit();
    auto effective_compact_lsn = std::min(static_cast< repl_lsn_t >(compact_upto_lsn), truncation_upper_limit);
    RD_LOGD(NO_TRACE_ID,
            "Raft Channel: effective_compact_lsn={}, raft compact_to_lsn={}, local truncation_upper_limit={}",
            effective_compact_lsn, compact_upto_lsn, truncation_upper_limit);
    m_rd.on_compact(effective_compact_lsn);
    return HomeRaftLogStore::compact(effective_compact_lsn);
}
} // namespace homestore
