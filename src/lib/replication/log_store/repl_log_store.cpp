#include <sisl/fds/vector_pool.hpp>
#include "replication/log_store/repl_log_store.h"
#include "replication/repl_dev/raft_state_machine.h"
#include "replication/repl_dev/raft_repl_dev.h"
#include "replication/repl_dev/common.h"

namespace homestore {

uint64_t ReplLogStore::append(nuraft::ptr< nuraft::log_entry >& entry) {
    // We don't want to transform anything that is not an app log
    if (entry->get_val_type() != nuraft::log_val_type::app_log) {
        ulong lsn = HomeRaftLogStore::append(entry);
        RD_LOGD("append entry term={}, log_val_type={} lsn={} size={}", entry->get_term(),
                static_cast< uint32_t >(entry->get_val_type()), lsn, entry->get_buf().size());
        return lsn;
    }

    repl_req_ptr_t rreq = m_sm.localize_journal_entry_finish(*entry);
    ulong lsn = HomeRaftLogStore::append(entry);
    m_sm.link_lsn_to_req(rreq, int64_cast(lsn));

    RD_LOGD("Raft Channel: Received append log entry rreq=[{}]", rreq->to_compact_string());
    return lsn;
}

void ReplLogStore::write_at(ulong index, nuraft::ptr< nuraft::log_entry >& entry) {
    // We don't want to transform anything that is not an app log
    if (entry->get_val_type() != nuraft::log_val_type::app_log) {
        HomeRaftLogStore::write_at(index, entry);
        return;
    }

    repl_req_ptr_t rreq = m_sm.localize_journal_entry_finish(*entry);
    HomeRaftLogStore::write_at(index, entry);
    m_sm.link_lsn_to_req(rreq, int64_cast(index));
    RD_LOGD("Raft Channel: Received write_at log entry rreq=[{}]", rreq->to_compact_string());
}

void ReplLogStore::end_of_append_batch(ulong start_lsn, ulong count) {
    int64_t end_lsn = int64_cast(start_lsn + count - 1);

    // Start fetch the batch of data for this lsn range from remote if its not available yet.
    auto reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
    auto proposer_reqs = sisl::VectorPool< repl_req_ptr_t >::alloc();
    bool flush_log = false;
    for (int64_t lsn = int64_cast(start_lsn); lsn <= end_lsn; ++lsn) {
        auto rreq = m_sm.lsn_to_req(lsn);
        // Skip this call in proposer, since this method will synchronously flush the data, which is not required for
        // leader. Proposer will call the flush as part of commit after receiving quorum, upon which time, there is a
        // high possibility the log entry is already flushed. Skip it for rreq == nullptr which is the case for raft
        // config entries.
        if ((rreq == nullptr) /*|| rreq->is_proposer()*/)  { continue; }
	else if (rreq->is_proposer()) { proposer_reqs->emplace_back(std::move(rreq)); }
	else {reqs->emplace_back(std::move(rreq));}
    }

    RD_LOGT("Raft Channel: end_of_append_batch start_lsn={} count={} num_data_to_be_written={}", start_lsn, count,
            reqs->size());

    for (auto const& rreq : *reqs) {
        if ((rreq == nullptr) || (!rreq->has_linked_data())) { continue; }
        LOGINFO("Raft Channel: Data before future wait: rreq=[{}]", rreq->to_compact_string());
    }

    // All requests are from proposer for data write, so as mentioned above we can skip the flush for now
    if (!reqs->empty()) {
        // Check the map if data corresponding to all of these requsts have been received and written. If not, schedule
        // a fetch and write. Once all requests are completed and written, these requests are poped out of the map and
        // the future will be ready.
        auto fut = m_rd.notify_after_data_written(reqs);

        // In the meanwhile, we can flush the journal for this lsn batch. It is ok to flush the entries in log before
        // actual data is written, because, even if we have the log, it doesn't mean data is committed, until state
        // machine reports that. This way the flush and fetch both can run in parallel.
        HomeRaftLogStore::end_of_append_batch(start_lsn, count);

        // Wait for the fetch and write to be completed successfully.
        std::move(fut).wait();

        // Mark all the reqs also completely written
        for (auto const& rreq : *reqs) {
            if (rreq) { rreq->add_state(repl_req_state_t::LOG_FLUSHED); }
        }

        for (auto const& rreq : *reqs) {
            if ((rreq == nullptr) || (!rreq->has_linked_data())) { continue; }
            LOGINFO("Raft Channel: Data after future wait: rreq=[{}]", rreq->to_compact_string());
        }
    } else if (!proposer_reqs->empty()) {
        LOGINFO("Raft Channel: end_of_append_batch, I am proposer, only flush log s from {} , count {}", start_lsn, count);
        // Mark all the reqs also completely written
        HomeRaftLogStore::end_of_append_batch(start_lsn, count);
        for (auto const& rreq : *proposer_reqs) {
            if (rreq) { rreq->add_state(repl_req_state_t::LOG_FLUSHED); }
        }
    }
    sisl::VectorPool< repl_req_ptr_t >::free(reqs);
    sisl::VectorPool< repl_req_ptr_t >::free(proposer_reqs);
}

std::string ReplLogStore::rdev_name() const { return m_rd.rdev_name(); }

bool ReplLogStore::compact(ulong compact_upto_lsn) {
    RD_LOG(DEBUG, "Raft Channel: compact_to_lsn={}", compact_upto_lsn);
    m_rd.on_compact(compact_upto_lsn);
    return HomeRaftLogStore::compact(compact_upto_lsn);
}
} // namespace homestore
